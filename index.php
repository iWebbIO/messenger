<?php
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob:; media-src 'self' data: blob:; connect-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; frame-ancestors 'none';");
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', 1);
session_start();
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
ini_set('upload_max_filesize', '20M');
ini_set('post_max_size', '20M');

// ADMIN CREDENTIALS
$adminUser = '';
$adminPass = ''; // Set these to enable Admin Panel

// -------------------------------------------------------------------------
// 1. CONFIGURATION & DATABASE
// -------------------------------------------------------------------------
$dbFile = __DIR__ . '/chat_mw.db';

try {
    $db = new PDO("sqlite:$dbFile");
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $db->exec("PRAGMA journal_mode=WAL;");

    // Schema Migration System
    $ver = (int)$db->query("PRAGMA user_version")->fetchColumn();
    
    if ($ver < 1) {
        // Base Schema
        $db->exec("CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            avatar TEXT, 
            joined_at INTEGER,
            last_seen INTEGER
            , public_key TEXT
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            type TEXT,
            owner_id INTEGER,
            join_code TEXT,
            created_at INTEGER
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS group_members (
            group_id INTEGER,
            user_id INTEGER,
            last_received_id INTEGER DEFAULT 0,
            PRIMARY KEY (group_id, user_id)
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER DEFAULT NULL, 
            from_user TEXT,
            to_user TEXT,
            message TEXT,
            type TEXT DEFAULT 'text',
            reply_to_id INTEGER,
            extra_data TEXT,
            timestamp INTEGER
        )");

        $db->exec("CREATE INDEX IF NOT EXISTS idx_msg_to ON messages(to_user)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_msg_group ON messages(group_id)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_msg_ts ON messages(timestamp)");

        // Patch existing columns safely
        $cols = $db->query("PRAGMA table_info(users)")->fetchAll(PDO::FETCH_COLUMN, 1);
        if (!in_array('typing_to', $cols)) $db->exec("ALTER TABLE users ADD COLUMN typing_to TEXT");
        if (!in_array('typing_at', $cols)) $db->exec("ALTER TABLE users ADD COLUMN typing_at INTEGER");
        if (!in_array('bio', $cols)) $db->exec("ALTER TABLE users ADD COLUMN bio TEXT");

        $db->exec("PRAGMA user_version = 1");
        $ver = 1;
    }

    if ($ver < 2) {
        $cols = $db->query("PRAGMA table_info(users)")->fetchAll(PDO::FETCH_COLUMN, 1);
        if (!in_array('public_key', $cols)) $db->exec("ALTER TABLE users ADD COLUMN public_key TEXT");

        $gcols = $db->query("PRAGMA table_info(groups)")->fetchAll(PDO::FETCH_COLUMN, 1);
        if (!in_array('password', $gcols)) $db->exec("ALTER TABLE groups ADD COLUMN password TEXT");
        if (!in_array('invite_expiry', $gcols)) $db->exec("ALTER TABLE groups ADD COLUMN invite_expiry INTEGER");
        if (!in_array('join_enabled', $gcols)) $db->exec("ALTER TABLE groups ADD COLUMN join_enabled INTEGER DEFAULT 1");

        $db->exec("PRAGMA user_version = 2");
    }

    if ($ver < 3) {
        $gcols = $db->query("PRAGMA table_info(groups)")->fetchAll(PDO::FETCH_COLUMN, 1);
        if (!in_array('category', $gcols)) $db->exec("ALTER TABLE groups ADD COLUMN category TEXT DEFAULT 'group'");
        $db->exec("PRAGMA user_version = 3");
    }

    if ($ver < 4) {
        $db->exec("CREATE INDEX IF NOT EXISTS idx_users_last_seen ON users(last_seen)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_users_typing ON users(typing_to)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_groups_discovery ON groups(type, category)");
        $db->exec("PRAGMA user_version = 4");
    }

    if ($ver < 5) {
        $cols = $db->query("PRAGMA table_info(users)")->fetchAll(PDO::FETCH_COLUMN, 1);
        if (!in_array('observatory_access', $cols)) $db->exec("ALTER TABLE users ADD COLUMN observatory_access INTEGER DEFAULT 0");
        $db->exec("PRAGMA user_version = 5");
    }

    if ($ver < 6) {
        $db->exec("CREATE TABLE IF NOT EXISTS auth_tokens (token TEXT PRIMARY KEY, user_id INTEGER, expires_at INTEGER)");
        $db->exec("PRAGMA user_version = 6");
    }

} catch (PDOException $e) { die("DB Error: " . $e->getMessage()); }

// -------------------------------------------------------------------------
// 2. BACKEND API
// -------------------------------------------------------------------------
$action = $_GET['action'] ?? '';

if ($action === 'manifest') {
    header('Content-Type: application/manifest+json');
    header('Cache-Control: public, max-age=86400');
    echo json_encode([
        "name" => "moreweb Messenger",
        "short_name" => "Messenger",
        "start_url" => "index.php",
        "display" => "standalone",
        "background_color" => "#0f0518",
        "theme_color" => "#0f0518",
        "icons" => [
            ["src" => "?action=icon", "sizes" => "192x192", "type" => "image/svg+xml"],
            ["src" => "?action=icon", "sizes" => "512x512", "type" => "image/svg+xml"]
        ]
    ]);
    exit;
}
if ($action === 'icon') {
    header('Content-Type: image/svg+xml');
    header('Cache-Control: public, max-age=86400');
    echo '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><rect width="512" height="512" rx="100" fill="#1a0b2e"/><path d="M256 85c-93 0-168 69-168 154 0 49 25 92 64 121v62l60-33c14 4 29 6 44 6 93 0 168-69 168-154S349 85 256 85z" fill="#a855f7"/></svg>';
    exit;
}
if ($action === 'sw') {
    header('Content-Type: application/javascript');
    header('Cache-Control: public, max-age=3600');
    echo "const CACHE='mw-v1';self.addEventListener('install',e=>{e.waitUntil(caches.open(CACHE).then(c=>c.addAll(['index.php','?action=icon'])));self.skipWaiting()});self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));self.addEventListener('fetch',e=>{if(e.request.method!='GET')return;e.respondWith(fetch(e.request).catch(()=>caches.match(e.request).then(r=>r||new Response('',{status:404}))))});self.addEventListener('notificationclick',e=>{e.notification.close();e.waitUntil(clients.matchAll({type:'window',includeUncontrolled:true}).then(cl=>{for(let c of cl){if(c.url&&'focus'in c)return c.focus();}if(clients.openWindow)return clients.openWindow('index.php');}));});";
    exit;
}

if ($action === 'get_profile') {
    header('Content-Type: application/json');
    $u = $_GET['u'] ?? '';
    $stmt = $db->prepare("SELECT username, avatar, bio, joined_at, last_seen, public_key FROM users WHERE username = ?");
    $stmt->execute([$u]);
    echo json_encode($stmt->fetch() ?: ['status'=>'error']);
    exit;
}
if ($action === 'get_discoverable_groups') {
    header('Content-Type: application/json');
    $cat = $_GET['cat'] ?? 'group';
    $stmt = $db->prepare("SELECT id, name, type, join_code FROM groups WHERE type = 'discoverable' AND category = ? ORDER BY created_at DESC LIMIT 50");
    $stmt->execute([$cat]);
    echo json_encode(['status'=>'success', 'items'=>$stmt->fetchAll()]);
    exit;
}
if ($action === 'get_group_details') {
    header('Content-Type: application/json');
    if (!isset($_SESSION['user'])) { echo json_encode(['status'=>'error']); exit; }
    $gid = $_GET['id'] ?? 0;
    
    // Check membership
    $stmt = $db->prepare("SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?");
    $stmt->execute([$gid, $_SESSION['uid']]);
    if (!$stmt->fetch()) { echo json_encode(['status'=>'error', 'message'=>'Not a member']); exit; }

    // Get Group Info
    $stmt = $db->prepare("SELECT * FROM groups WHERE id = ?");
    $stmt->execute([$gid]);
    $group = $stmt->fetch();

    $stmt = $db->prepare("SELECT u.id, u.username, u.avatar, u.last_seen, u.public_key FROM group_members gm JOIN users u ON gm.user_id = u.id WHERE gm.group_id = ?");
    $stmt->execute([$gid]);
    echo json_encode(['status'=>'success', 'group'=>$group, 'members'=>$stmt->fetchAll(), 'is_owner'=>($group['owner_id'] == $_SESSION['uid'])]);
    exit;
}
if ($action === 'get_observatory') {
    header('Content-Type: application/json');
    if (!isset($_SESSION['uid'])) { echo json_encode(['status'=>'error']); exit; }
    
    $stmt = $db->prepare("SELECT observatory_access FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['uid']]);
    $acc = $stmt->fetchColumn();
    if ($acc != 2) {
        echo json_encode(['status' => 'access_denied', 'state' => (int)$acc]);
        exit;
    }

    $cacheFile = __DIR__ . '/mw_news_cache.enc';
    $key = 'mw_obs_key_static_99'; // Static key for cache encryption
    $iv = '1234567890123456'; // Fixed IV for cache consistency
    
    $data = null;
    // Check cache (10 minutes = 600 seconds)
    if (file_exists($cacheFile) && (time() - filemtime($cacheFile) < 600)) {
        $enc = file_get_contents($cacheFile);
        $dec = openssl_decrypt($enc, 'AES-128-CTR', $key, 0, $iv);
        $data = json_decode($dec, true);
    }
    
    if (!$data) {
        $ctx = stream_context_create(['http'=>['timeout'=>5]]);
        $market = @file_get_contents('https://raw.githubusercontent.com/itsyebekhe/rasadai/refs/heads/main/market.json', false, $ctx);
        $news = @file_get_contents('https://raw.githubusercontent.com/itsyebekhe/rasadai/refs/heads/main/news.json', false, $ctx);
        
        if ($market && $news) {
            $data = ['market' => json_decode($market, true), 'news' => json_decode($news, true)];
            $enc = openssl_encrypt(json_encode($data), 'AES-128-CTR', $key, 0, $iv);
            file_put_contents($cacheFile, $enc);
        }
    }
    echo json_encode(['status' => 'success', 'data' => $data]);
    exit;
}
if (isset($_SESSION['admin']) && !empty($adminUser)) {
    if ($action === 'admin_get_data') {
        header('Content-Type: application/json');
        $stats = [
            'users' => $db->query("SELECT COUNT(*) FROM users")->fetchColumn(),
            'groups' => $db->query("SELECT COUNT(*) FROM groups")->fetchColumn(),
            'messages' => $db->query("SELECT COUNT(*) FROM messages")->fetchColumn(),
            'db_size' => round(filesize($dbFile) / 1024 / 1024, 2) . ' MB'
        ];
        $users = $db->query("SELECT id, username, joined_at, last_seen, observatory_access FROM users ORDER BY id DESC")->fetchAll();
        $groups = $db->query("SELECT id, name, type, owner_id, created_at FROM groups ORDER BY id DESC")->fetchAll();
        echo json_encode(['status'=>'success', 'stats'=>$stats, 'users'=>$users, 'groups'=>$groups]);
        exit;
    }
    if ($action === 'admin_logout') {
        session_destroy();
        header("Location: index.php");
        exit;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');

    if (!isset($_SERVER['HTTP_X_CSRF_TOKEN']) || $_SERVER['HTTP_X_CSRF_TOKEN'] !== $_SESSION['csrf_token']) {
        http_response_code(403);
        echo json_encode(['status' => 'error', 'message' => 'CSRF validation failed']);
        exit;
    }

    $input = json_decode(file_get_contents('php://input'), true);
    if (!is_array($input)) $input = [];

    // AUTH
    if ($action === 'register') {
        $user = trim($input['username']);
        if (strlen($user) > 30) { echo json_encode(['status'=>'error','message'=>'Username too long']); exit; }
        if (!preg_match('/^[a-zA-Z0-9_]+$/', $user)) { echo json_encode(['status'=>'error','message'=>'Use letters, numbers, _ only']); exit; }

        $stmt = $db->prepare("SELECT 1 FROM users WHERE lower(username) = lower(?)");
        $stmt->execute([$user]);
        if ($stmt->fetch()) { echo json_encode(['status'=>'error','message'=>'Username taken']); exit; }

        $pass = password_hash($input['password'], PASSWORD_DEFAULT);
        try {
            $stmt = $db->prepare("INSERT INTO users (username, password, joined_at, last_seen) VALUES (?, ?, ?, ?)");
            $stmt->execute([$user, $pass, time(), time()]);
            session_regenerate_id(true);
            $_SESSION['user'] = $user;
            $_SESSION['uid'] = $db->lastInsertId();
            echo json_encode(['status' => 'success']);
        } catch (PDOException $e) { echo json_encode(['status' => 'error', 'message' => 'Registration failed']); }
        exit;
    }
    if ($action === 'login') {
        if (!empty($adminUser) && !empty($adminPass) && ($input['username'] ?? '') === $adminUser && ($input['password'] ?? '') === $adminPass) {
            session_regenerate_id(true);
            $_SESSION['admin'] = true;
            echo json_encode(['status' => 'success']);
            exit;
        }
        $stmt = $db->prepare("SELECT id, username, password FROM users WHERE lower(username) = lower(?)");
        $stmt->execute([$input['username']]);
        $row = $stmt->fetch();
        if ($row && password_verify($input['password'], $row['password'])) {
            session_regenerate_id(true);
            $_SESSION['user'] = $row['username'];
            $_SESSION['uid'] = $row['id'];
            $token = bin2hex(random_bytes(32));
            $db->prepare("INSERT INTO auth_tokens (token, user_id, expires_at) VALUES (?, ?, ?)")->execute([$token, $row['id'], time() + 2592000]);
            echo json_encode(['status' => 'success', 'token' => $token]);
        } else { echo json_encode(['status' => 'error', 'message' => 'Invalid credentials']); }
        exit;
    }
    
    if ($action === 'restore_session') {
        $token = $input['token'] ?? '';
        $stmt = $db->prepare("SELECT t.user_id, u.username FROM auth_tokens t JOIN users u ON t.user_id = u.id WHERE t.token = ? AND t.expires_at > ?");
        $stmt->execute([$token, time()]);
        $row = $stmt->fetch();
        if ($row) {
            session_regenerate_id(true);
            $_SESSION['user'] = $row['username'];
            $_SESSION['uid'] = $row['user_id'];
            $db->prepare("UPDATE auth_tokens SET expires_at = ? WHERE token = ?")->execute([time() + 2592000, $token]);
            echo json_encode(['status' => 'success']);
        } else { echo json_encode(['status' => 'error']); }
        exit;
    }

    if ($action === 'request_observatory') {
        if (!isset($_SESSION['uid'])) exit;
        $db->prepare("UPDATE users SET observatory_access = 1 WHERE id = ?")->execute([$_SESSION['uid']]);
        echo json_encode(['status'=>'success']);
        exit;
    }

    // ADMIN ACTIONS
    if (isset($_SESSION['admin']) && !empty($adminUser)) {
        if ($action === 'admin_delete_user') {
            $uid = $input['id'];
            $stmt = $db->prepare("SELECT username FROM users WHERE id = ?");
            $stmt->execute([$uid]);
            $u = $stmt->fetchColumn();
            if ($u) {
                $db->prepare("DELETE FROM users WHERE id = ?")->execute([$uid]);
                $db->prepare("DELETE FROM group_members WHERE user_id = ?")->execute([$uid]);
                $db->prepare("DELETE FROM messages WHERE from_user = ? OR to_user = ?")->execute([$u, $u]);
                // Cleanup orphaned messages from groups owned by this user before deleting groups
                $db->prepare("DELETE FROM messages WHERE group_id IN (SELECT id FROM groups WHERE owner_id = ?)")->execute([$uid]);
                // Delete groups owned by user
                $db->prepare("DELETE FROM groups WHERE owner_id = ?")->execute([$uid]);
            }
            echo json_encode(['status'=>'success']);
            exit;
        }
        if ($action === 'admin_delete_group') {
            $gid = $input['id'];
            $db->prepare("DELETE FROM groups WHERE id = ?")->execute([$gid]);
            $db->prepare("DELETE FROM group_members WHERE group_id = ?")->execute([$gid]);
            $db->prepare("DELETE FROM messages WHERE group_id = ?")->execute([$gid]);
            echo json_encode(['status'=>'success']);
            exit;
        }
        if ($action === 'admin_approve_observatory') {
            $uid = $input['id'];
            $val = $input['allow'] ? 2 : 0;
            $db->prepare("UPDATE users SET observatory_access = ? WHERE id = ?")->execute([$val, $uid]);
            echo json_encode(['status'=>'success']);
            exit;
        }
    }

    if (!isset($_SESSION['user'])) { http_response_code(403); exit; }
    $me = $_SESSION['user'];
    $myId = $_SESSION['uid'];

    // PROFILE
    if ($action === 'update_profile') {
        if (!empty($input['avatar'])) {
            $db->prepare("UPDATE users SET avatar = ? WHERE id = ?")->execute([$input['avatar'], $myId]);
        }
        if (!empty($input['new_password'])) {
            $db->prepare("UPDATE users SET password = ? WHERE id = ?")->execute([password_hash($input['new_password'], PASSWORD_DEFAULT), $myId]);
        }
        if (isset($input['bio'])) {
            $db->prepare("UPDATE users SET bio = ? WHERE id = ?")->execute([htmlspecialchars($input['bio']), $myId]);
        }
        echo json_encode(['status' => 'success']);
        exit;
    }
    if ($action === 'update_pubkey') {
        $db->prepare("UPDATE users SET public_key = ? WHERE id = ?")->execute([$input['key'], $myId]);
        echo json_encode(['status' => 'success']);
        exit;
    }

    // MESSAGING
    if ($action === 'send') {
        $ts = $input['timestamp'] ?? time();
        $reply = $input['reply_to'] ?? null;
        $extra = $input['extra'] ?? null;
        $type = $input['type'] ?? 'text';
        $msg = $input['message'];
        if (strlen($msg) > 15000000) { echo json_encode(['status'=>'error','message'=>'Message too long']); exit; }

        if (isset($input['to_user'])) {
            $stmt = $db->prepare("INSERT INTO messages (from_user, to_user, message, type, reply_to_id, extra_data, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([$me, $input['to_user'], $msg, $type, $reply, $extra, $ts]);
        } else if (isset($input['group_id'])) {
            if ($input['group_id'] != -1) {
                $chk = $db->prepare("SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?");
                $chk->execute([$input['group_id'], $myId]);
                if (!$chk->fetch()) { echo json_encode(['status'=>'error','message'=>'Not a member']); exit; }
            }

            // Channel Permission Check
            $gstmt = $db->prepare("SELECT owner_id, category FROM groups WHERE id = ?");
            $gstmt->execute([$input['group_id']]);
            $g = $gstmt->fetch();
            if ($g && $g['category'] === 'channel' && $g['owner_id'] != $myId) {
                echo json_encode(['status'=>'error','message'=>'Only the owner can post in this channel']); exit;
            }
            $stmt = $db->prepare("INSERT INTO messages (group_id, from_user, message, type, reply_to_id, extra_data, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([$input['group_id'], $me, $msg, $type, $reply, $extra, $ts]);
        }
        echo json_encode(['status' => 'success']);
        exit;
    }

    // AJAX UPLOAD
    if ($action === 'upload_msg') {
        if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
            echo json_encode(['status'=>'error', 'message'=>'Upload failed']); exit;
        }
        
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mime = $finfo->file($_FILES['file']['tmp_name']);
        $data = file_get_contents($_FILES['file']['tmp_name']);
        $b64 = 'data:' . $mime . ';base64,' . base64_encode($data);
        
        $msg = $b64;
        $type = strpos($mime, 'image') === 0 ? 'image' : 'file';
        $extra = $_FILES['file']['name'];
        $ts = $_POST['timestamp'] ?? time();
        $reply = $_POST['reply_to'] ?? null;
        
        if (!empty($_POST['to_user'])) {
            $stmt = $db->prepare("INSERT INTO messages (from_user, to_user, message, type, reply_to_id, extra_data, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([$me, $_POST['to_user'], $msg, $type, $reply, $extra, $ts]);
        } else if (!empty($_POST['group_id'])) {
            if ($_POST['group_id'] != -1) {
                $chk = $db->prepare("SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?");
                $chk->execute([$_POST['group_id'], $myId]);
                if (!$chk->fetch()) { echo json_encode(['status'=>'error','message'=>'Not a member']); exit; }
            }

            // Channel Permission Check
            $gstmt = $db->prepare("SELECT owner_id, category FROM groups WHERE id = ?");
            $gstmt->execute([$_POST['group_id']]);
            $g = $gstmt->fetch();
            if ($g && $g['category'] === 'channel' && $g['owner_id'] != $myId) {
                echo json_encode(['status'=>'error','message'=>'Only the owner can post in this channel']); exit;
            }
            $stmt = $db->prepare("INSERT INTO messages (group_id, from_user, message, type, reply_to_id, extra_data, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([$_POST['group_id'], $me, $msg, $type, $reply, $extra, $ts]);
        }
        echo json_encode(['status' => 'success']);
        exit;
    }

    // GROUPS
    if ($action === 'create_group') {
        $type = $input['type'];
        $cat = $input['category'] ?? 'group';
        $code = ($type === 'public' || $type === 'discoverable') ? rand(100000, 999999) : null;
        $joinEnabled = ($type === 'private') ? 0 : 1;
        
        try {
            $db->prepare("INSERT INTO groups (name, type, owner_id, join_code, created_at, join_enabled, category) VALUES (?, ?, ?, ?, ?, ?, ?)")
               ->execute([htmlspecialchars($input['name']), $type, $myId, $code, time(), $joinEnabled, $cat]);
            $gid = $db->lastInsertId();
            $db->prepare("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)")->execute([$gid, $myId]);
            echo json_encode(['status' => 'success']);
        } catch (Exception $e) { echo json_encode(['status'=>'error', 'message'=>$e->getMessage()]); }
        exit;
    }
    if ($action === 'update_group_settings') {
        $gid = $input['group_id'];
        // Verify owner
        $stmt = $db->prepare("SELECT owner_id FROM groups WHERE id = ?"); $stmt->execute([$gid]);
        if ($stmt->fetchColumn() != $myId) { echo json_encode(['status'=>'error','message'=>'Not owner']); exit; }

        if (isset($input['join_enabled'])) $db->prepare("UPDATE groups SET join_enabled = ? WHERE id = ?")->execute([$input['join_enabled'], $gid]);
        
        if (isset($input['generate_code'])) {
            $suffix = strtoupper(substr($input['suffix'] ?? 'X', 0, 1));
            if(!ctype_alpha($suffix)) $suffix = 'X';
            $code = rand(10000, 99999) . $suffix;
            $expiry = $input['expiry'] ? (time() + ($input['expiry'] * 60)) : null;
            $pwd = $input['password'] ? password_hash($input['password'], PASSWORD_DEFAULT) : null;
            
            $db->prepare("UPDATE groups SET join_code = ?, password = ?, invite_expiry = ? WHERE id = ?")
               ->execute([$code, $pwd, $expiry, $gid]);
        }
        echo json_encode(['status'=>'success']);
        exit;
    }
    if ($action === 'join_group') {
        $row = $db->prepare("SELECT * FROM groups WHERE join_code = ?");
        $row->execute([$input['code']]);
        $grp = $row->fetch();
        if ($grp) {
            if (!$grp['join_enabled']) { echo json_encode(['status'=>'error','message'=>'Joining disabled']); exit; }
            if ($grp['invite_expiry'] && time() > $grp['invite_expiry']) { echo json_encode(['status'=>'error','message'=>'Code expired']); exit; }
            if ($grp['password'] && !password_verify($input['password']??'', $grp['password'])) { echo json_encode(['status'=>'error','message'=>'Invalid password']); exit; }
            try { $db->prepare("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)")->execute([$grp['id'], $myId]); 
            echo json_encode(['status' => 'success']); } catch(Exception $e) { echo json_encode(['status' => 'error', 'message'=>'Joined already']); }
        } else echo json_encode(['status' => 'error', 'message' => 'Invalid code']);
        exit;
    }
    if ($action === 'leave_group') {
        $db->prepare("DELETE FROM group_members WHERE group_id = ? AND user_id = ?")->execute([$input['group_id'], $myId]);
        echo json_encode(['status' => 'success']);
        exit;
    }
    if ($action === 'delete_group') {
        $gid = $input['group_id'];
        $stmt = $db->prepare("SELECT owner_id FROM groups WHERE id = ?");
        $stmt->execute([$gid]);
        if ($stmt->fetchColumn() == $myId) {
            $db->prepare("DELETE FROM groups WHERE id = ?")->execute([$gid]);
            $db->prepare("DELETE FROM group_members WHERE group_id = ?")->execute([$gid]);
            $db->prepare("DELETE FROM messages WHERE group_id = ?")->execute([$gid]);
            echo json_encode(['status' => 'success']);
        } else echo json_encode(['status' => 'error', 'message' => 'Not owner']);
        exit;
    }

    // TYPING
    if ($action === 'typing') {
        $db->prepare("UPDATE users SET typing_to = ?, typing_at = ? WHERE id = ?")->execute([$input['to'], time(), $myId]);
        exit;
    }

    // POLLING
    if ($action === 'poll') {
        if (!isset($_SESSION['user'])) { http_response_code(403); exit; }
        $me = $_SESSION['user'];
        $myId = $_SESSION['uid'];

        if (!isset($_SESSION['last_seen_upd']) || time() - $_SESSION['last_seen_upd'] > 60) {
            $db->prepare("UPDATE users SET last_seen = ? WHERE id = ?")->execute([time(), $myId]);
            $_SESSION['last_seen_upd'] = time();
        }

        session_write_close();
        // Cleanup old messages (1% chance)
        if (rand(1, 100) === 1) {
            $t24h = time() - 86400;
            // 24 hours for everything - Exclude Discoverable Channels (Permanent)
            $db->exec("DELETE FROM messages WHERE timestamp < $t24h AND (group_id IS NULL OR group_id NOT IN (SELECT id FROM groups WHERE category = 'channel' AND type = 'discoverable'))");
        }

        // Self Profile
        $myProfile = $db->prepare("SELECT username, avatar, joined_at, bio FROM users WHERE id = ?");
        $myProfile->execute([$myId]);

        // DMs (Fetch & Delete)
        $db->beginTransaction();
        $stmt = $db->prepare("SELECT * FROM messages WHERE to_user = ? ORDER BY id ASC");
        $stmt->execute([$me]);
        $dms = $stmt->fetchAll();
        if (!empty($dms)) {
            $ids = implode(',', array_column($dms, 'id'));
            $db->exec("DELETE FROM messages WHERE id IN ($ids)");
        }
        $db->commit();

        // Groups
        $groups = $db->prepare("SELECT g.id, g.name, g.type, g.join_code, g.category, g.owner_id, gm.last_received_id FROM groups g JOIN group_members gm ON g.id=gm.group_id WHERE gm.user_id=?");
        $groups->execute([$myId]);
        $myGroups = $groups->fetchAll();
    
        $grpMsgs = [];
        foreach ($myGroups as $g) {
            $stmt = $db->prepare("SELECT * FROM messages WHERE group_id = ? AND id > ? ORDER BY id ASC");
            $stmt->execute([$g['id'], $g['last_received_id']]);
            $msgs = $stmt->fetchAll();
            if($msgs) {
                $grpMsgs = array_merge($grpMsgs, $msgs);
                $last = end($msgs)['id'];
                $db->prepare("UPDATE group_members SET last_received_id = ? WHERE group_id = ? AND user_id = ?")->execute([$last, $g['id'], $myId]);
            }
        }
    
        // Online Users
        $online = $db->prepare("SELECT username, avatar, last_seen, bio FROM users WHERE last_seen > ?");
        $online->execute([time()-300]);

        // Typing
        $typing = $db->prepare("SELECT username FROM users WHERE typing_to = ? AND typing_at > ?");
        $typing->execute([$me, time() - 5]);

        // Public Chat
        $lastPub = $input['last_pub'] ?? 0;
        $db->exec("DELETE FROM messages WHERE group_id = -1 AND timestamp < " . (time() - 300));
        $stmt = $db->prepare("SELECT * FROM messages WHERE group_id = -1 AND id > ? ORDER BY id ASC");
        $stmt->execute([$lastPub]);
        $pubMsgs = $stmt->fetchAll();

        echo json_encode(['profile' => $myProfile->fetch(), 'dms' => $dms, 'groups' => $myGroups, 'group_msgs' => $grpMsgs, 'public_msgs' => $pubMsgs, 'online' => $online->fetchAll(), 'typing' => $typing->fetchAll(PDO::FETCH_COLUMN)]);
        exit;
    }
}

if ($action === 'logout') { session_destroy(); header("Location: index.php"); exit; }

// -------------------------------------------------------------------------
// FRONTEND
// -------------------------------------------------------------------------
?><?php if (isset($_SESSION['admin']) && !empty($adminUser)) { ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Admin Panel - moreweb Messenger</title>
<link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap" rel="stylesheet">
<style>
    body { background: #0f0518; color: #eee; font-family: 'Roboto', sans-serif; margin: 0; padding: 20px; }
    .container { max-width: 1000px; margin: 0 auto; }
    .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 1px solid #2f1b42; }
    .header h1 { margin: 0; color: #a855f7; font-weight: 300; }
    .btn { padding: 8px 16px; background: #a855f7; color: #fff; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; font-size: 0.9rem; }
    .btn:hover { background: #9333ea; }
    .btn-danger { background: #ef4444; }
    .btn-danger:hover { background: #dc2626; }
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 40px; }
    .stat-card { background: #1a0b2e; padding: 20px; border-radius: 8px; border: 1px solid #2f1b42; text-align: center; }
    .stat-val { font-size: 2rem; font-weight: bold; color: #fff; margin: 10px 0; }
    .stat-label { color: #888; font-size: 0.9rem; text-transform: uppercase; letter-spacing: 1px; }
    .section { background: #1a0b2e; padding: 20px; border-radius: 8px; border: 1px solid #2f1b42; margin-bottom: 30px; }
    .section h2 { margin-top: 0; color: #ccc; font-size: 1.2rem; margin-bottom: 20px; }
    table { width: 100%; border-collapse: collapse; }
    th, td { text-align: left; padding: 12px; border-bottom: 1px solid #2f1b42; font-size: 0.9rem; }
    th { color: #888; font-weight: 500; }
    tr:last-child td { border-bottom: none; }
    .action-btn { padding: 4px 8px; font-size: 0.8rem; }
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>Admin Panel</h1>
        <a href="?action=admin_logout" class="btn">Logout</a>
    </div>
    <div class="stats-grid" id="stats"></div>
    
    <div class="section">
        <h2>Users</h2>
        <div style="overflow-x:auto">
            <table id="users-table">
                <thead><tr><th>ID</th><th>Username</th><th>Joined</th><th>Last Seen</th><th>Observatory</th><th>Action</th></tr></thead>
                <tbody></tbody>
            </table>
        </div>
    </div>

    <div class="section">
        <h2>Groups</h2>
        <div style="overflow-x:auto">
            <table id="groups-table">
                <thead><tr><th>ID</th><th>Name</th><th>Type</th><th>Owner ID</th><th>Created</th><th>Action</th></tr></thead>
                <tbody></tbody>
            </table>
        </div>
    </div>
</div>
<script>
const CSRF_TOKEN = "<?php echo $_SESSION['csrf_token']; ?>";
async function loadData() {
    let r = await fetch('?action=admin_get_data');
    let d = await r.json();
    if(d.status === 'success') {
        // Stats
        let sh = '';
        for(let [k,v] of Object.entries(d.stats)) {
            sh += `<div class="stat-card"><div class="stat-label">${k.replace('_',' ')}</div><div class="stat-val">${v}</div></div>`;
        }
        document.getElementById('stats').innerHTML = sh;

        // Users
        let uh = '';
        d.users.forEach(u => {
            let obsBtn = '';
            if(u.observatory_access == 1) obsBtn = `<button class="btn action-btn" style="background:#4caf50;margin-right:5px" onclick="apprObs(${u.id}, 1)">Approve</button><button class="btn btn-danger action-btn" onclick="apprObs(${u.id}, 0)">Deny</button>`;
            else if(u.observatory_access == 2) obsBtn = `<span style="color:#4caf50;margin-right:5px">Active</span><button class="btn btn-danger action-btn" style="padding:2px 6px;font-size:0.7rem" onclick="apprObs(${u.id}, 0)">Revoke</button>`;
            else obsBtn = `<span style="color:#666">None</span>`;
            
            uh += `<tr><td>${u.id}</td><td>${u.username}</td><td>${new Date(u.joined_at*1000).toLocaleDateString()}</td><td>${new Date(u.last_seen*1000).toLocaleString()}</td><td>${obsBtn}</td><td><button class="btn btn-danger action-btn" onclick="delUser(${u.id}, '${u.username}')">Delete</button></td></tr>`;
        });
        document.querySelector('#users-table tbody').innerHTML = uh || '<tr><td colspan="6">No users found</td></tr>';

        // Groups
        let gh = '';
        d.groups.forEach(g => {
            gh += `<tr><td>${g.id}</td><td>${g.name}</td><td>${g.type}</td><td>${g.owner_id}</td><td>${new Date(g.created_at*1000).toLocaleDateString()}</td><td><button class="btn btn-danger action-btn" onclick="delGroup(${g.id})">Delete</button></td></tr>`;
        });
        document.querySelector('#groups-table tbody').innerHTML = gh || '<tr><td colspan="6">No groups found</td></tr>';
    }
}
async function delUser(id, name) {
    if(confirm(`Delete user ${name}? This cannot be undone.`)) {
        await fetch('?action=admin_delete_user', {method:'POST', headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF_TOKEN}, body:JSON.stringify({id})});
        loadData();
    }
}
async function delGroup(id) {
    if(confirm(`Delete group ${id}?`)) {
        await fetch('?action=admin_delete_group', {method:'POST', headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF_TOKEN}, body:JSON.stringify({id})});
        loadData();
    }
}
async function apprObs(id, allow) {
    await fetch('?action=admin_approve_observatory', {method:'POST', headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF_TOKEN}, body:JSON.stringify({id, allow})});
    loadData();
}
loadData();
</script>
</body>
</html>
<?php exit; } ?>

<?php if (!isset($_SESSION['user'])) { ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>moreweb Messenger - Login</title>
<link rel="manifest" href="?action=manifest">
<meta name="theme-color" content="#0f0518">
<link rel="icon" href="?action=icon" type="image/svg+xml">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Roboto:wght@100;300;400;500&display=swap" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@100;300;400;700&family=Roboto:wght@100;300;400;500&display=swap" rel="stylesheet">
<style>
    body { background: #0f0518; color: #eee; font-family: 'Roboto', sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; overflow: hidden; }
    
    .box { background: #1a0b2e; padding: 48px 40px 36px; border-radius: 12px; width: 400px; max-width: 90%; text-align: center; box-shadow: 0 10px 30px rgba(0,0,0,0.5); border: 1px solid #2f1b42; position: relative; z-index: 10; display: flex; flex-direction: column; align-items: center; }
    
    .welcome-text { font-weight: 100; font-size: 3.5rem; margin-bottom: 10px; color: #fff; letter-spacing: -0.5px; text-shadow: 0 0 20px rgba(168, 85, 247, 0.5); }
    
    h2 { font-weight: 400; font-size: 1.1rem; margin: 0 0 40px 0; color: #aaa; }
    
    input { width: 100%; padding: 13px 15px; margin: 0 0 15px 0; background: #261038; border: 1px solid #2f1b42; color: #fff; border-radius: 6px; box-sizing: border-box; font-family: inherit; font-size: 1rem; transition: 0.2s; }
    input:focus { border-color: #a855f7; outline: none; box-shadow: 0 0 10px rgba(168, 85, 247, 0.3); }
    
    button { width: 100%; padding: 12px 0; background: #a855f7; color: #fff; border: none; border-radius: 6px; font-weight: bold; font-size: 0.9rem; cursor: pointer; font-family: inherit; margin-top: 20px; transition: background 0.2s; box-shadow: 0 4px 15px rgba(168, 85, 247, 0.4); }
    button:hover { background: #9333ea; }
    
    #toggle-text { color: #a855f7; cursor: pointer; font-size: 0.875rem; margin-top: 25px; font-weight: 500; }
    #admin-link { color: #666; cursor: pointer; font-size: 0.75rem; margin-top: 15px; display: block; }

    @keyframes gradientBG { 0% {background-position: 0% 50%;} 50% {background-position: 100% 50%;} 100% {background-position: 0% 50%;} }
    #login-bg {
        position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: 0;
        background: linear-gradient(-45deg, #0f0518, #3b0764, #6b21a8, #0f0518);
        background-size: 400% 400%;
        animation: gradientBG 3s ease infinite;
        opacity: 0; transition: opacity 1.5s ease-in-out;
    }
    body.login-process #login-bg { opacity: 1; }

    /* Splash Screen */
    .splash-screen {
        position: fixed; top: 0; left: 0; width: 100%; height: 100%;
        background-color: #202124; z-index: 9999;
        background-color: #000000; z-index: 9999;
        display: flex; justify-content: center; align-items: center;
        animation: screenFadeOut 0.5s ease-in-out 1.5s forwards;
        pointer-events: none;
    }
    .splash-screen .word {
        color: #FFFFFF; font-family: 'Roboto', sans-serif; font-weight: 100; font-size: clamp(4rem, 10vw, 6rem);
        color: #FFFFFF; font-family: 'Poppins', sans-serif; font-weight: 100; font-size: clamp(8rem, 15vw, 10rem);
        display: grid; grid-template-columns: auto auto; justify-items: center;
        line-height: 0.8; gap: 0.15em; direction: ltr;
        line-height: 0.8; gap: 0.15em; text-shadow: 0 0 30px #bf00ff; direction: ltr;
        animation: fadeWordOut 0.3s cubic-bezier(0.55, 0.085, 0.68, 0.53) 1.0s forwards;
    }
    .splash-screen .word span { opacity: 0; position: relative; }

    @keyframes letterAppear { from { opacity: 0; transform: scale(0.9); } to { opacity: 1; transform: scale(1); } }
    @keyframes fadeWordOut { from { opacity: 1; transform: scale(1); filter: blur(0); } to { opacity: 0; transform: scale(1.1); filter: blur(10px); } }
    @keyframes screenFadeOut { to { opacity: 0; visibility: hidden; } }

    .splash-screen .word span:nth-child(1) { animation: letterAppear 0.3s ease-out 0.05s forwards; }
    .splash-screen .word span:nth-child(2) { animation: letterAppear 0.3s ease-out 0.15s forwards; }
    .splash-screen .word span:nth-child(3) { animation: letterAppear 0.3s ease-out 0.25s forwards; }
    .splash-screen .word span:nth-child(4) { animation: letterAppear 0.3s ease-out 0.30s forwards; }

    .lang-toggle { position: absolute; top: 20px; right: 20px; display: flex; gap: 15px; z-index: 20; }
    .lang-opt { font-weight: 500; color: #9aa0a6; cursor: pointer; transition: 0.2s; font-size: 0.9rem; }
    .lang-opt.active { color: #e8eaed; font-weight: 700; }
    .rtl { direction: rtl; }
</style>
</head>
<body>

<div class="splash-screen">
    <div class="word"><span>m</span><span>o</span><span>r</span><span>e</span></div>
</div>

<div class="lang-toggle">
    <div class="lang-opt active" id="l-en" onclick="setLang('en')">EN</div>
    <div class="lang-opt" id="l-fa" onclick="setLang('fa')">فا</div>
</div>

<div id="login-bg"></div>
<div class="box">
    <div class="welcome-text">Welcome</div>
    <h2 id="ttl">moreweb Messenger</h2><div id="err" style="color:#f55;display:none;margin-bottom:10px"></div>
    <input id="u" placeholder="Username"><input type="password" id="p" placeholder="Password">
    <button onclick="sub()">Sign In</button>
    <div id="toggle-text" onclick="toggleMode()">Need an account? Create one</div>
</div>
<script>
const CSRF_TOKEN = "<?php echo $_SESSION['csrf_token']; ?>";
let reg=false;
const TR = {
    en: { ttl: "moreweb Messenger", signin: "Sign In", signup: "Sign Up", user: "Username", pass: "Password", no_acc: "Need an account? Create one", has_acc: "Already have an account? Sign In", create: "Create Account", err: "Please fill in all fields", proc: "Processing..." },
    fa: { ttl: "پیام‌رسان موروب", signin: "ورود", signup: "ثبت نام", user: "نام کاربری", pass: "رمز عبور", no_acc: "حساب ندارید؟ یکی بسازید", has_acc: "حساب دارید؟ وارد شوید", create: "ایجاد حساب", err: "لطفا تمام فیلدها را پر کنید", proc: "در حال پردازش..." }
};
let curLang = localStorage.getItem('mw_lang') || 'en';

function setLang(l) {
    curLang = l; localStorage.setItem('mw_lang', l);
    document.body.classList.toggle('rtl', l=='fa');
    document.getElementById('l-en').classList.toggle('active', l=='en');
    document.getElementById('l-fa').classList.toggle('active', l=='fa');
    applyLang();
}
function applyLang() {
    const t = TR[curLang];
    document.getElementById('ttl').innerText = reg ? t.create : t.ttl;
    document.getElementById('u').placeholder = t.user;
    document.getElementById('p').placeholder = t.pass;
    document.querySelector('button').innerText = reg ? t.signup : t.signin;
    document.getElementById('toggle-text').innerText = reg ? t.has_acc : t.no_acc;
}
function toggleMode() {
    reg = !reg;
    applyLang();
    document.getElementById('err').style.display = 'none';
}
async function sub(){
    let u=document.getElementById('u').value.trim(),p=document.getElementById('p').value;
    if(!u||!p){let e=document.getElementById('err');e.innerText="Please fill in all fields";e.style.display='block';return;}
    document.body.classList.add('login-process');
    let btn=document.querySelector('button');btn.disabled=true;btn.innerText=TR[curLang].proc;
    let r=await fetch('?action='+(reg?'register':'login'),{
        method:'POST',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': CSRF_TOKEN},
        body:JSON.stringify({username:u,password:p})
    });
    let d=await r.json();
    if(d.status=='success'){ if(d.token)localStorage.setItem('mw_auth_token',d.token); location.reload(); }
    else{document.body.classList.remove('login-process');let e=document.getElementById('err');e.innerText=d.message;e.style.display='block';btn.disabled=false;applyLang();}
}
if(localStorage.getItem('mw_auth_token')){
    document.body.classList.add('login-process');
    fetch('?action=restore_session',{
        method:'POST', headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF_TOKEN},
        body:JSON.stringify({token:localStorage.getItem('mw_auth_token')})
    }).then(r=>r.json()).then(d=>{
        if(d.status=='success')location.reload(); else {localStorage.removeItem('mw_auth_token');document.body.classList.remove('login-process');}
    }).catch(()=>{document.body.classList.remove('login-process');});
}
setLang(curLang);
if('serviceWorker' in navigator)navigator.serviceWorker.register('?action=sw');
</script></body></html>
<?php exit; } ?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, interactive-widget=resizes-content">
<link rel="manifest" href="?action=manifest">
<meta name="theme-color" content="#0f0518">
<link rel="icon" href="?action=icon" type="image/svg+xml">
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@100;300;400;700&display=swap" rel="stylesheet">
<title>moreweb Messenger</title>
<style>
    :root { --bg:#0f0518; --rail:#0b0b0b; --panel:#1a0b2e; --border:#2f1b42; --accent:#a855f7; --text:#e0e0e0; --msg-in:#261038; --msg-out:#581c87; --sb-thumb:rgba(255,255,255,0.5); --sb-hover:rgba(255,255,255,0.7); --input-bg:#333; --pattern:#222; --hover-overlay:rgba(255,255,255,0.05); }
    .light-mode { --bg:#ffffff; --rail:#f0f0f0; --panel:#f5f5f5; --border:#ddd; --text:#111; --msg-in:#fff; --msg-out:#f3e8ff; --sb-thumb:rgba(0,0,0,0.4); --sb-hover:rgba(0,0,0,0.6); --input-bg:#fff; --pattern:#e5e5e5; --hover-overlay:rgba(0,0,0,0.05); }
    .light-mode .rail-btn { color:#555; }
    @media (hover: hover) {
        .light-mode .rail-btn:hover { background:#e0e0e0; color:#000; }
        .light-mode .list-item:hover { background:#f0f0f0; }
    }
    .light-mode .list-item.active { background:#e6e6e6; }
    .light-mode input { background:#fff; border:1px solid #ccc; color:#000; }
    .light-mode .msg-meta { color:#777; }
    .light-mode .reply-ctx { background:#eee; color:#333; }
    .light-mode .ctx-menu { background:#fff; border-color:#ccc; }

    .e2ee-on { color: var(--accent); }
    * { -webkit-tap-highlight-color: transparent; }
    body { margin:0; font-family:'Calibri', 'Poppins', sans-serif; background:var(--bg); color:var(--text); height:100vh; height:calc(var(--vh, 1vh) * 100); display:flex; overflow:hidden; overscroll-behavior-y: none; }
    .rtl { font-family: 'Calibri', 'Tahoma', sans-serif; }
    .rtl .nav-panel, .rtl .main-view, .rtl .modal-box, .rtl .box { direction: rtl; text-align: right; }
    .rtl .list-item.active { border-left: none; border-right: 4px solid var(--accent); padding-left: 15px; padding-right: 11px; }
    .rtl .avatar { margin-right: 0; margin-left: 12px; }
    .rtl .msg-meta { text-align: left; }
    
    /* Custom Scrollbar */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background-color: transparent; border-radius: 3px; }
    
    /* Show scrollbar on hover for specific containers */
    .nav-rail:hover::-webkit-scrollbar-thumb,
    .list-area:hover::-webkit-scrollbar-thumb,
    .messages:hover::-webkit-scrollbar-thumb,
    #observatory-view:hover::-webkit-scrollbar-thumb { background-color: var(--sb-thumb); }
    
    ::-webkit-scrollbar-thumb:hover { background-color: var(--sb-hover); }

    /* Layout */
    .app-container { display:flex; width:100%; height:100%; }
    .nav-rail { width:60px; background:var(--rail); border-right:1px solid var(--border); display:flex; flex-direction:column; align-items:center; padding-top:20px; z-index:10; overflow-y:auto; min-height:0; }
    .rail-btn { width:40px; height:40px; border-radius:10px; display:flex; align-items:center; justify-content:center; margin-bottom:15px; cursor:pointer; color:#888; transition:0.2s; position:relative; user-select:none; flex-shrink:0; }
    @media (hover: hover) { .rail-btn:hover { background:rgba(255,255,255,0.1); color:#fff; } }
    .rail-btn:active { transform: scale(0.95); background:rgba(255,255,255,0.1); }
    .rail-btn.active { background:var(--accent); color:#fff; }
    .rail-btn svg { width:24px; height:24px; fill:currentColor; }
    .rail-badge { position:absolute; top:-2px; right:-2px; background:red; border-radius:50%; width:10px; height:10px; display:none; border:2px solid var(--rail); }

    .nav-panel { width:280px; background:var(--panel); border-right:1px solid var(--border); display:flex; flex-direction:column; min-height:0; }
    .panel-header { padding:20px; font-weight:bold; font-size:1.2rem; border-bottom:1px solid var(--border); display:flex; justify-content:space-between; align-items:center; }
    .list-area { flex:1; overflow-y:auto; overscroll-behavior-y: contain; }
    .list-item { padding:15px; border-bottom:1px solid var(--border); display:flex; align-items:center; cursor:pointer; transition:0.2s; position:relative; user-select:none; }
    @media (hover: hover) { .list-item:hover { background:rgba(255,255,255,0.1); } }
    .list-item:active { background:rgba(255,255,255,0.05); }
    .list-item.active { background:rgba(255,255,255,0.15); border-left:4px solid var(--accent); padding-left:11px; }
    .avatar { width:40px; height:40px; border-radius:50%; background:#444; margin-right:12px; display:flex; align-items:center; justify-content:center; font-weight:bold; background-size:cover; flex-shrink:0; }
    
    .main-view { flex:1; display:flex; flex-direction:column; background:var(--bg); background-image:radial-gradient(var(--pattern) 1px, transparent 1px); background-size:20px 20px; position:relative; min-height:0; }
    .chat-header { height:60px; background:var(--panel); border-bottom:1px solid var(--border); display:flex; align-items:center; justify-content:space-between; padding:0 20px; }
    .header-actions { display:flex; gap:15px; position:relative; }
    .chat-info-clickable { cursor: pointer; }
    
    .notif-btn { position:relative; cursor:pointer; color:var(--text); opacity:0.8; }
    .notif-badge { position:absolute; top:-5px; right:-5px; background:#f44; color:#fff; font-size:0.6rem; padding:1px 4px; border-radius:8px; display:none; }
    .notif-dropdown { position:absolute; top:40px; right:0; width:250px; background:var(--panel); border:1px solid var(--border); border-radius:8px; display:none; z-index:100; box-shadow:0 5px 15px rgba(0,0,0,0.5); overflow:hidden; }
    .notif-item { padding:12px; border-bottom:1px solid var(--border); font-size:0.85rem; cursor:pointer; color:var(--text); }
    .notif-item:hover { background:var(--hover-overlay); }

    .menu-btn { cursor:pointer; color:var(--text); opacity:0.8; position:relative; }
    .menu-dropdown { position:absolute; top:35px; right:0; background:var(--panel); border:1px solid var(--border); border-radius:8px; display:none; z-index:101; width:160px; box-shadow:0 5px 15px rgba(0,0,0,0.5); }
    .menu-item { padding:12px; border-bottom:1px solid var(--border); font-size:0.9rem; cursor:pointer; display:block; color:var(--text); }
    .menu-item:hover { background:rgba(255,255,255,0.1); }
    .red-text { color: #ff5555; }

    .messages { flex:1; overflow-y:auto; padding:20px; display:flex; flex-direction:column; gap:5px; overscroll-behavior-y: contain; }
    .msg { max-width:65%; padding:8px 12px; border-radius:8px; font-size:0.95rem; line-height:1.4; position:relative; word-wrap:break-word; }
    .msg.in { align-self:flex-start; background:var(--msg-in); border-top-left-radius:0; border:1px solid transparent; }
    .msg.out { align-self:flex-end; background:var(--msg-out); border-top-right-radius:0; }
    .msg img { max-width:100%; border-radius:4px; margin-top:5px; cursor:pointer; }
    .file-att { background:rgba(0,0,0,0.2); padding:10px; border-radius:5px; display:flex; align-items:center; gap:10px; cursor:pointer; border:1px solid rgba(255,255,255,0.1); margin-top:5px; }
    .file-att:hover { background:rgba(0,0,0,0.3); }
    .msg-sender { font-size:0.75rem; font-weight:bold; color:var(--accent); margin-bottom:4px; cursor:pointer; }
    .msg-meta { font-size:0.7rem; color:rgba(255,255,255,0.5); text-align:right; margin-top:2px; }
    .msg.pinned { border: 1px solid var(--accent); }
    .reaction-bar { position:absolute; bottom:-12px; right:0; background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:2px 6px; font-size:0.8rem; box-shadow:0 2px 5px rgba(0,0,0,0.5); cursor:pointer; }
    
    .scroll-btn { position:absolute; bottom:80px; right:20px; width:35px; height:35px; background:var(--panel); border:1px solid var(--border); border-radius:50%; display:none; align-items:center; justify-content:center; cursor:pointer; box-shadow:0 4px 10px rgba(0,0,0,0.5); z-index:90; color:var(--accent); }

    /* Audio Player */
    .audio-player { display:flex; align-items:center; gap:10px; background:rgba(0,0,0,0.2); padding:8px 12px; border-radius:20px; min-width:200px; border:1px solid rgba(255,255,255,0.1); margin-top:5px; }
    .play-btn { width:32px; height:32px; background:var(--accent); color:#fff; border-radius:50%; flex-shrink:0; display:flex; align-items:center; justify-content:center; cursor:pointer; border:none; transition:0.2s; }
    .play-btn:hover { filter:brightness(1.1); }
    .play-btn svg { width:14px; height:14px; fill:currentColor; margin-left:2px; }
    .play-btn.playing svg { margin-left:0; }
    .audio-progress { flex:1; height:4px; background:rgba(255,255,255,0.2); border-radius:2px; position:relative; cursor:pointer; }
    .audio-bar { height:100%; background:var(--accent); width:0%; border-radius:2px; transition:width 0.1s linear; }
    .audio-time { font-size:0.75rem; font-family:monospace; color:#ccc; min-width:35px; text-align:right; }

    .input-area { padding:15px; background:var(--panel); display:flex; gap:10px; align-items:center; border-top:1px solid var(--border); padding-bottom: calc(15px + env(safe-area-inset-bottom)); }
    .input-wrapper { flex:1; position:relative; }
    .reply-ctx { background:#2a2a2a; padding:6px 10px; border-radius:5px 5px 0 0; font-size:0.8rem; color:#aaa; display:none; justify-content:space-between; align-items:center; }
    input[type=text] { width:100%; padding:12px; border-radius:20px; border:none; background:var(--input-bg); color:var(--text); outline:none; box-sizing:border-box; }
    #txt { width:100%; padding:10px 12px; border-radius:20px; border:none; background:var(--input-bg); color:var(--text); outline:none; box-sizing:border-box; resize:none; height:40px; font-family:inherit; overflow-y:hidden; line-height:1.4; display:block; }
    
    #btn-e2ee svg { fill: var(--accent); }
    .btn-icon { background:none; border:none; color:#888; cursor:pointer; display:flex; align-items:center; justify-content:center; border-radius:50%; transition:0.2s; width:40px; height:40px; padding:0; position:relative; flex-shrink:0; user-select:none; }
    @media (hover: hover) { .btn-icon:hover { color:#fff; background:rgba(255,255,255,0.1); } }
    .btn-icon:active { transform: scale(0.9); background:rgba(255,255,255,0.15); }
    .btn-primary { background:var(--accent); color:#fff; border:none; padding:8px 16px; border-radius:20px; cursor:pointer; font-weight:bold; }
    
    .tab-content { display:flex; flex-direction:column; flex:1; min-height:0; }
    .settings-panel { padding:20px; text-align:center; overflow-y:auto; flex:1; }
    .form-group { margin-top:15px; text-align:left; }
    .form-input { width:100%; padding:10px; background:var(--input-bg); border:1px solid var(--border); color:var(--text); border-radius:4px; margin-top:5px; outline:none; box-sizing:border-box; }
    .form-select { width:100%; padding:10px; background:var(--input-bg); border:1px solid var(--border); color:var(--text); border-radius:4px; margin-top:5px; outline:none; }
    .about-link { color: var(--accent); text-decoration:none; }

    /* Modal */
    .modal-overlay { position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.7); z-index:1000; display:none; align-items:center; justify-content:center; }
    .modal-box { background:var(--panel); padding:20px; border-radius:12px; width:300px; border:1px solid var(--border); box-shadow:0 10px 30px #000; }
    .modal-title { margin:0 0 10px 0; font-size:1.1rem; font-weight:bold; }
    .modal-body { color:#ccc; font-size:0.9rem; margin-bottom:15px; }
    .modal-btns { display:flex; justify-content:flex-end; gap:10px; margin-top:20px; }
    .btn-modal { padding:8px 16px; border-radius:6px; cursor:pointer; border:none; font-weight:bold; }
    .btn-sec { background:transparent; color:#aaa; border:1px solid #444; }
    .btn-pri { background:var(--accent); color:#fff; }
    
    /* WEncrypt Overlay */
    .we-overlay { position:absolute; top:60px; left:0; width:100%; height:calc(100% - 60px); background:rgba(0,0,0,0.85); z-index:50; display:none; flex-direction:column; align-items:center; justify-content:center; text-align:center; }
    .we-status { margin-top:20px; color:var(--accent); font-size:1.2rem; }

    /* Context Menu */
    .ctx-menu { position:fixed; background:var(--panel); border:1px solid var(--border); border-radius:8px; box-shadow:0 5px 20px rgba(0,0,0,0.5); z-index:2000; min-width:180px; overflow:hidden; font-size:0.9rem; }
    .ctx-reactions { display:flex; padding:8px; gap:5px; background:rgba(0,0,0,0.2); justify-content:space-around; }
    .ctx-reaction { cursor:pointer; transition:0.2s; font-size:1.2rem; padding:2px; border-radius:4px; }
    .ctx-reaction:hover { background:rgba(255,255,255,0.2); transform:scale(1.2); }
    .ctx-item { padding:10px 15px; cursor:pointer; display:flex; align-items:center; gap:10px; }
    .ctx-item:hover { background:rgba(255,255,255,0.05); }
    .ctx-separator { height:1px; background:var(--border); margin:2px 0; }

    /* Loading Animation */
    #progress-bar-container { position: fixed; top: 0; left: 0; width: 100%; height: 4px; background-color: rgba(255, 255, 255, 0.1); z-index: 10000; transition: opacity 0.8s ease-out, visibility 0.8s ease-out; pointer-events: none; }
    #progress-bar { height: 100%; width: 0; background: linear-gradient(90deg, #4A00E0, #00BFFF, #E01E5A); border-radius: 0 2px 2px 0; transition: width 0.4s ease-out; }
    .loader-hidden { opacity: 0 !important; visibility: hidden !important; }
    
    .rail-letters { position: relative; width: 40px; height: 40px; font-size: 1.8rem; font-weight: 100; color: var(--accent); font-family: 'Poppins', sans-serif; }
    .rail-letters span { position: absolute; top: 0; left: 50%; transform: translateX(-50%); opacity: 0; animation: sequentialReplace 2s infinite; text-transform: lowercase; }
    .rail-letters span:nth-child(1) { animation-delay: 0s; }
    .rail-letters span:nth-child(2) { animation-delay: 0.5s; }
    .rail-letters span:nth-child(3) { animation-delay: 1.0s; }
    .rail-letters span:nth-child(4) { animation-delay: 1.5s; }
    .rail-dot { width: 5px; height: 5px; background-color: var(--text); border-radius: 50%; animation: pulse 1.5s infinite ease-in-out; }
    .tab-loader { display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; width: 100%; min-height: 200px; }
    
    /* Lightbox */
    .lightbox { position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.95); z-index:2000; display:none; align-items:center; justify-content:center; flex-direction:column; backdrop-filter:blur(5px); }
    .lightbox img { max-width:100%; max-height:85%; object-fit:contain; box-shadow:0 0 20px rgba(0,0,0,0.5); }
    .lightbox-controls { position:absolute; top:15px; right:15px; display:flex; gap:15px; z-index:2001; }
    .lb-btn { width:40px; height:40px; background:rgba(255,255,255,0.1); border-radius:50%; display:flex; align-items:center; justify-content:center; color:#fff; cursor:pointer; backdrop-filter:blur(10px); }
    
    /* Media Preview */
    .media-preview { position:fixed; top:0; left:0; width:100%; height:100%; background:#000; z-index:3000; display:none; flex-direction:column; }
    .preview-header { padding:15px; display:flex; justify-content:space-between; align-items:center; color:#fff; background:rgba(0,0,0,0.3); }
    .preview-content { flex:1; display:flex; align-items:center; justify-content:center; overflow:hidden; position:relative; }
    .preview-content img { max-width:100%; max-height:100%; object-fit:contain; }
    .preview-footer { padding:20px; display:flex; justify-content:space-between; align-items:center; background:rgba(0,0,0,0.5); }
    .toast { position:fixed; top:80px; left:50%; transform:translateX(-50%); background:rgba(30,30,30,0.9); color:#fff; padding:8px 16px; border-radius:20px; font-size:0.85rem; z-index:4000; opacity:0; transition:opacity 0.3s; pointer-events:none; box-shadow:0 4px 12px rgba(0,0,0,0.3); backdrop-filter:blur(5px); border:1px solid rgba(255,255,255,0.1); }
    .toast.show { opacity:1; }

    /* Attachment Menu */
    .att-menu { width:100%; background:var(--panel); border-top:1px solid var(--border); padding:20px; padding-bottom:calc(20px + env(safe-area-inset-bottom)); display:none; grid-template-columns: repeat(4, 1fr); gap:10px; z-index:100; animation: slideUp 0.2s ease-out; box-sizing:border-box; }
    .att-item { display:flex; flex-direction:column; align-items:center; cursor:pointer; gap:8px; }
    .att-icon { width:56px; height:56px; border-radius:50%; display:flex; align-items:center; justify-content:center; color:#fff; transition:transform 0.2s; box-shadow: 0 4px 10px rgba(0,0,0,0.2); }
    .att-icon svg { width: 28px; height: 28px; fill: currentColor; }
    .att-icon:active { transform:scale(0.95); }
    .att-label { font-size: 0.8rem; color: var(--text); opacity: 0.9; font-weight: 500; }
    .att-cam { background: linear-gradient(135deg, #FF512F, #DD2476); }
    .att-gal { background: linear-gradient(135deg, #8E2DE2, #4A00E0); }
    .att-file { background: linear-gradient(135deg, #11998e, #38ef7d); }
    .att-loc { background: linear-gradient(135deg, #ff9966, #ff5e62); }
    @keyframes slideUp { from { transform: translateY(100%); } to { transform: translateY(0); } }
    
    @keyframes sequentialReplace { 0%, 100% { opacity: 0; transform: translateX(-50%) scale(0.95); } 15% { opacity: 1; transform: translateX(-50%) scale(1); } 30% { opacity: 1; transform: translateX(-50%) scale(1); } 45% { opacity: 0; transform: translateX(-50%) scale(0.95); } }
    @keyframes pulse { 0%, 100% { transform: scale(1); opacity: 1; } 50% { transform: scale(1.3); opacity: 0.7; } }

    @media (max-width: 768px) {
        .app-container { flex-direction: column; }
        .nav-rail { 
            width: 100%; height: 60px;
            flex-direction: row; justify-content: space-evenly; align-items: center;
            padding-top: 0; border-right: none; border-top: 1px solid var(--border);
            position: fixed; bottom: 0; left: 0; background: var(--panel);
            z-index: 30;
            padding-bottom: env(safe-area-inset-bottom);
        }
        .rail-btn { margin-bottom: 0; width: auto; height: 100%; flex: 1; border-radius: 0; }
        .rail-btn.active { background: transparent; color: var(--accent); position: relative; }
        .rail-btn.active::after { content:''; position:absolute; top:0; left:0; width:100%; height:3px; background:var(--accent); }
        .rail-spacer { display: none; }
        
        .nav-panel { 
            width: 100%; left: 0; top: 0; 
            height: calc(100% - 60px - env(safe-area-inset-bottom)); 
            border-right: none; 
            z-index: 5;
            position: absolute;
        }
        .nav-panel.hidden { display: flex; }
        
        .main-view { 
            width: 100%; height: 100%; 
            position: fixed; top: 0; left: 0; 
            z-index: 40; 
            transform: translateX(100%); transition: transform 0.3s cubic-bezier(0.4, 0.0, 0.2, 1);
            background: var(--bg);
        }
        .main-view.active { transform: translateX(0); }
        
        .back-btn { display: flex; align-items: center; justify-content: center; margin-right: 10px; font-size: 1.5rem; padding: 5px; }
        .back-btn { display: flex; align-items: center; justify-content: center; margin-right: 5px; font-size: 1.5rem; padding: 10px; }
        .list-item { padding: 20px 15px; }
        .avatar { width: 45px; height: 45px; }
        .btn-icon svg { width: 28px; height: 28px; }
        input, textarea { font-size: 16px !important; }
        .msg { max-width: 85%; }
        .messages { padding: 10px; }
        .desktop-only { display: none !important; }
        .mobile-only { display: block !important; }
    }
    @media (min-width: 769px) { .back-btn { display:none; } .mobile-only { display: none !important; } }

    /* Splash Screen Main App */
    .splash-screen { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: #000000; z-index: 9999; display: flex; justify-content: center; align-items: center; pointer-events: none; }
    .splash-screen .word { color: #FFFFFF; font-family: 'Poppins', sans-serif; font-weight: 100; font-size: clamp(8rem, 15vw, 10rem); display: grid; grid-template-columns: auto auto; justify-items: center; line-height: 0.8; gap: 0.15em; text-shadow: 0 0 30px #bf00ff; direction: ltr; }
    .splash-screen .word span { opacity: 0; position: relative; }
    @keyframes letterAppear { from { opacity: 0; transform: scale(0.9); } to { opacity: 1; transform: scale(1); } }
    .splash-screen .word span:nth-child(1) { animation: letterAppear 0.3s ease-out 0.05s forwards; }
    .splash-screen .word span:nth-child(2) { animation: letterAppear 0.3s ease-out 0.15s forwards; }
    .splash-screen .word span:nth-child(3) { animation: letterAppear 0.3s ease-out 0.25s forwards; }
    .splash-screen .word span:nth-child(4) { animation: letterAppear 0.3s ease-out 0.30s forwards; }

    /* Connection Indicator */
    .conn-indicator { padding: 6px 0 0 0; height: 22px; display: flex; align-items: center; justify-content: center; transition: 0.3s; flex-shrink: 0; }
    .conn-more { font-family: 'Poppins', sans-serif; font-weight: 100; font-size: 1.4rem; letter-spacing: 0.1em; color: #fff; text-shadow: 0 0 15px #bf00ff; display: none; gap: 5px; line-height: 1; }
    .conn-more span { display: inline-block; animation: letterAppear 0.5s ease-out forwards; }
    .conn-text { font-size: 0.75rem; color: #888; font-style: italic; display: block; font-family: 'Roboto', sans-serif; font-weight: 300; letter-spacing: 0.05em; }
    .conn-dots::after { content: '.'; animation: dots 1.5s infinite; display: inline-block; width: 1.5em; text-align: left; }
    .status-connected .conn-more { display: flex; }
    .status-connected .conn-text { display: none; }
    .light-mode .conn-more { color: #333; text-shadow: 0 0 10px rgba(168, 85, 247, 0.5); }
    @keyframes dots { 0% { content: '.'; } 33% { content: '..'; } 66% { content: '...'; } }

    /* Observatory Styles */
    .market-list { padding:15px; }
    .market-row-item { display:flex; justify-content:space-between; padding:15px; border-bottom:1px solid var(--border); align-items:center; background:rgba(255,255,255,0.02); margin-bottom:10px; border-radius:8px; }
    .market-row-label { color:#888; font-size:0.9rem; }
    .market-row-val { font-weight:bold; color:var(--accent); font-family:monospace; font-size:1.2rem; }
    
    .obs-header { padding:20px; border-bottom:1px solid var(--border); background:var(--panel); display:flex; justify-content:space-between; align-items:center; position:sticky; top:0; z-index:10; height:60px; box-sizing:border-box; }
    .obs-title { font-size:1.3rem; font-weight:bold; color:var(--text); display:flex; align-items:center; gap:10px; }
    .obs-grid { display:grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap:20px; padding:20px; }
    .news-card-lg { background:var(--panel); border:1px solid var(--border); border-radius:12px; overflow:hidden; transition:transform 0.2s; cursor:pointer; display:flex; flex-direction:column; height:100%; }
    .news-card-lg:hover { transform:translateY(-3px); box-shadow:0 5px 15px rgba(0,0,0,0.3); border-color:var(--accent); }
    .news-card-body { padding:20px; flex:1; display:flex; flex-direction:column; }
    .news-card-title { font-size:1.1rem; font-weight:bold; margin-bottom:10px; line-height:1.4; color:var(--text); }
    .news-card-meta { font-size:0.8rem; color:#888; margin-bottom:12px; display:flex; justify-content:space-between; align-items:center; }
    .news-card-summary { font-size:0.9rem; color:#ccc; line-height:1.6; flex:1; margin-bottom:15px; }
    .news-card-footer { padding:12px 20px; background:rgba(0,0,0,0.2); border-top:1px solid var(--border); font-size:0.8rem; color:#aaa; display:flex; justify-content:space-between; align-items:center; }
    .news-tag { background:var(--accent); color:#fff; padding:2px 8px; border-radius:4px; font-size:0.7rem; font-weight:bold; }
    .sentiment-dot { width:8px; height:8px; border-radius:50%; display:inline-block; margin-right:5px; }
    .news-impact { padding:12px; background:rgba(168, 85, 247, 0.08); border-left:3px solid var(--accent); border-radius:4px; font-size:0.85rem; color:#ddd; margin-top:auto; }
    .news-impact strong { color:var(--accent); display:block; margin-bottom:5px; font-size:0.7rem; text-transform:uppercase; letter-spacing:1px; opacity:0.9; }
    .rtl .news-impact { border-left:none; border-right:3px solid var(--accent); }
    .rtl .sentiment-dot { margin-right:0; margin-left:5px; }
    .news-summary-list { margin:0; padding:0 0 0 20px; list-style-type:disc; }
    .rtl .news-summary-list { padding:0 20px 0 0; direction: rtl; }
</style>
</head>
<body>

<div id="app-splash" class="splash-screen">
    <div class="word"><span>m</span><span>o</span><span>r</span><span>e</span></div>
</div>

<!-- LOADING SYSTEM -->
<div id="progress-bar-container">
    <div id="progress-bar"></div>
</div>

<!-- TOAST -->
<div id="toast" class="toast"></div>

<!-- MEDIA PREVIEW -->
<div id="media-preview" class="media-preview">
    <div class="preview-header"><button class="btn-icon" onclick="closePreview()">&times;</button><span>Preview</span><div style="width:40px"></div></div>
    <div class="preview-content"><img id="preview-img" src=""></div>
    <div class="preview-footer">
        <div style="color:#aaa;font-size:0.8rem" id="preview-info"></div>
        <button class="btn-primary" onclick="sendPreview()">Send</button>
    </div>
</div>

<!-- MODAL SYSTEM -->
<div id="app-modal" class="modal-overlay">
    <div class="modal-box">
        <h3 id="modal-title" class="modal-title"></h3>
        <div id="modal-body" class="modal-body"></div>
        <input id="modal-input" type="text" class="form-input" style="display:none">
        <div class="modal-btns">
            <button id="modal-cancel" class="btn-modal btn-sec">Cancel</button>
            <button id="modal-ok" class="btn-modal btn-pri">OK</button>
        </div>
    </div>
</div>

<!-- CONTEXT MENU -->
<div id="ctx-menu" class="ctx-menu" style="display:none">
    <!-- Dynamic Content -->
</div>

<div class="app-container">
    <!-- NAVIGATION RAIL -->
    <div class="nav-rail">
        <div class="rail-btn active" id="nav-chats" onclick="switchTab('chats')">
            <svg viewBox="0 0 24 24"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2z"/></svg>
            <div class="rail-badge" id="badge-chats"></div>
        </div>
        <div class="rail-btn" id="nav-groups" onclick="switchTab('groups')">
            <svg viewBox="0 0 24 24"><path d="M16 11c1.66 0 2.99-1.34 2.99-3S17.66 5 16 5c-1.66 0-3 1.34-3 3s1.34 3 3 3zm-8 0c1.66 0 2.99-1.34 2.99-3S9.66 5 8 5C6.34 5 5 6.34 5 8s1.34 3 3 3zm0 2c-2.33 0-7 1.17-7 3.5V19h14v-2.5c0-2.33-4.67-3.5-7-3.5zm8 0c-.29 0-.62.02-.97.05 1.16.84 1.97 1.97 1.97 3.45V19h6v-2.5c0-2.33-4.67-3.5-7-3.5z"/></svg>
            <div class="rail-badge" id="badge-groups"></div>
        </div>
        <div class="rail-btn" id="nav-channels" onclick="switchTab('channels')">
            <svg viewBox="0 0 24 24"><path d="M21 3H3c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h18c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm0 16H3V5h18v14zM5 10h14v2H5zm0 4h14v2H5z"/></svg>
            <div class="rail-badge" id="badge-channels"></div>
        </div>
        <div class="rail-btn" id="nav-public" onclick="switchTab('public')">
            <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/></svg>
        </div>
        <div class="rail-btn" id="nav-observatory" onclick="switchTab('observatory')">
            <svg viewBox="0 0 24 24"><path d="M19.9,1.622a1,1,0,0,0-1.365-.52L1.562,9.388a1,1,0,0,0-.488,1.276L2.59,14.378A1,1,0,0,0,3.516,15a1.043,1.043,0,0,0,.24-.029L11,13.179v4.407L7.293,21.293a1,1,0,1,0,1.414,1.414L11,20.414V22a1,1,0,0,0,2,0V20.414l2.293,2.293a1,1,0,0,0,1.414-1.414L13,17.586v-4.9L22.24,10.4a1,1,0,0,0,.686-1.348ZM4.115,12.821l-.836-2.047L18.447,3.368l2.191,5.367Z"/></svg>
        </div>
        
        <div style="flex:1" class="rail-spacer"></div>
        <div class="rail-btn desktop-only" id="nav-about" onclick="switchTab('about')">
            <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>
        </div>
        <div class="rail-btn" id="nav-settings" onclick="switchTab('settings')">
            <svg viewBox="0 0 24 24"><path d="M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58a.49.49 0 0 0 .12-.61l-1.92-3.32a.488.488 0 0 0-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54a.484.484 0 0 0-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L3.16 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.09.63-.09.94s.02.64.07.94l-2.03 1.58a.49.49 0 0 0-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z"/></svg>
        </div>
        <div class="rail-btn desktop-only" onclick="if(confirm('Logout?')){localStorage.removeItem('mw_auth_token');location.href='?action=logout'}" title="Logout">
            <svg viewBox="0 0 24 24"><path d="M10.09 15.59L11.5 17l5-5-5-5-1.41 1.41L12.67 11H3v2h9.67l-2.58 2.59zM19 3H5c-1.11 0-2 .9-2 2v4h2V5h14v14H5v-4H3v4c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2z"/></svg>
        </div>
    </div>

    <!-- LIST PANEL -->
    <div class="nav-panel" id="nav-panel">
        <div id="conn-indicator" class="conn-indicator">
            <div class="conn-more"><span>m</span><span>o</span><span>r</span><span>e</span></div>
            <div class="conn-text">Connecting<span class="conn-dots"></span></div>
        </div>
        <div id="tab-chats" class="tab-content">
            <div style="padding:10px 15px 5px 15px"><input type="text" id="chat-search" class="form-input" placeholder="Search chats..." onkeyup="renderLists()" style="margin:0;padding:10px 15px;border-radius:20px"></div>
            <div class="panel-header" style="padding-top:5px;padding-bottom:5px;border-bottom:none"><span data-i18n="tab_chats">Chats</span> <div class="btn-icon" onclick="promptChat()">+</div></div>
            <div class="list-area" id="list-chats">
                <div class="tab-loader">
                    <div class="rail-letters"><span>m</span><span>o</span><span>R</span><span>e</span></div>
                    <div class="rail-dot"></div>
                </div>
            </div>
        </div>
        <div id="tab-groups" class="tab-content" style="display:none">
            <div style="padding:10px 15px 5px 15px"><input type="text" id="group-search" class="form-input" placeholder="Search groups..." onkeyup="renderLists()" style="margin:0;padding:10px 15px;border-radius:20px"></div>
            <div class="panel-header" style="padding-top:5px;padding-bottom:5px;border-bottom:none"><span data-i18n="tab_groups">Groups</span> 
                <div style="display:flex;gap:5px">
                <div class="btn-icon" onclick="discover('group')" title="Discover Groups">🌍</div>
                <div class="btn-icon" onclick="createGroup()" title="Create Group">+</div>
                </div></div>
            <div style="padding:0 15px 10px 15px"><button class="form-input" style="cursor:pointer;border-radius:20px;text-align:center;background:var(--bg);border:1px solid var(--border)" onclick="joinGroup()">Join via Code</button></div>
            <div class="list-area" id="list-groups">
                <div class="tab-loader">
                    <div class="rail-letters"><span>m</span><span>o</span><span>R</span><span>e</span></div>
                    <div class="rail-dot"></div>
                </div>
            </div>
        </div>
        <div id="tab-channels" class="tab-content" style="display:none">
            <div style="padding:10px 15px 5px 15px"><input type="text" id="channel-search" class="form-input" placeholder="Search channels..." onkeyup="renderLists()" style="margin:0;padding:10px 15px;border-radius:20px"></div>
            <div class="panel-header" style="padding-top:5px;padding-bottom:5px;border-bottom:none"><span data-i18n="tab_channels">Channels</span> <div style="display:flex;gap:5px"><div class="btn-icon" onclick="discover('channel')" title="Discover Channels">🌍</div><div class="btn-icon" onclick="createChannel()" title="Create Channel">+</div></div></div>
            <div style="padding:0 15px 10px 15px"><button class="form-input" style="cursor:pointer;border-radius:20px;text-align:center;background:var(--bg);border:1px solid var(--border)" onclick="joinGroup()">Join via Code</button></div>
            <div class="list-area" id="list-channels">
                <div class="tab-loader">
                    <div class="rail-letters"><span>m</span><span>o</span><span>R</span><span>e</span></div>
                    <div class="rail-dot"></div>
                </div>
            </div>
        </div>
        <div id="tab-public" class="tab-content" style="display:none">
            <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%">
                <div style="font-size:1.2rem;color:#888" data-i18n="online_users">Online Users</div>
                <div id="online-count" style="font-size:4rem;font-weight:bold;color:var(--accent)">0</div>
            </div>
        </div>
        <div id="tab-observatory" class="tab-content" style="display:none">
            <div class="panel-header" data-i18n="tab_observatory">Observatory</div>
            <div class="list-area">
                <div id="obs-clocks" style="padding:15px;border-bottom:1px solid var(--border);"></div>
                <div id="obs-market-list" class="market-list"></div>
                <div style="padding:20px;text-align:center;color:#666;font-size:0.9rem" class="mobile-only">Select an item or view the feed on the right.</div>
                <div style="padding:15px" class="mobile-only"><button class="btn-primary" style="width:100%" onclick="showObsFeed()">View News Feed</button></div>
            </div>
        </div>
        <div id="tab-settings" class="tab-content" style="display:none">
            <div class="panel-header" data-i18n="tab_settings">Settings</div>
            <div class="settings-panel">
                <div class="avatar" id="my-av" style="width:80px;height:80px;margin:0 auto;font-size:2rem"></div>
                <h3 id="my-name"></h3>
                <p id="my-date" style="color:#777;font-size:0.8rem"></p>
                <div class="form-group"><label data-i18n="bio">Bio / Status</label><input class="form-input" id="set-bio" maxlength="50"></div>
                <div class="form-group"><label data-i18n="avatar_url">Avatar URL</label><input class="form-input" id="set-av"></div>
                <div class="form-group"><label data-i18n="new_pass">New Password</label><input class="form-input" id="set-pw" type="password"></div>
                <div class="form-group"><label data-i18n="lang_select">Language</label><select id="set-lang" class="form-select" onchange="setLang(this.value)"><option value="en">English</option><option value="fa">فارسی</option></select></div>
                <div class="form-group"><button class="btn-sec" style="width:100%;padding:10px;border:1px solid var(--border);border-radius:4px;cursor:pointer;background:var(--panel);color:var(--text)" onclick="toggleTheme()" data-i18n="toggle_theme">Toggle Dark/Light Mode</button></div>
                <div class="form-group"><button class="btn-sec" style="width:100%;padding:10px;border:1px solid var(--border);border-radius:4px;cursor:pointer;background:var(--panel);color:var(--text)" onclick="enableNotifs()" data-i18n="enable_notif">Enable Notifications</button></div>
                <div class="form-group">
                    <label>Font Size (<span id="lbl-fs">16px</span>)</label>
                    <input type="range" id="set-fs" min="12" max="24" step="1" value="16" oninput="applyAppearance()" style="width:100%">
                </div>
                <div class="form-group">
                    <label>Interface Scale (<span id="lbl-scale">100%</span>)</label>
                    <input type="range" id="set-scale" min="70" max="130" step="5" value="100" oninput="applyAppearance()" style="width:100%">
                </div>
                <br><button class="btn-primary" onclick="saveSettings()" data-i18n="save">Save</button>
                
                <div class="mobile-only" style="margin-top:30px;border-top:1px solid var(--border);padding-top:20px">
                    <h3 data-i18n="tab_about">About</h3>
                    <p style="color:#888;">moreweb Messenger v0.0.1</p>
                    <button class="btn-sec" style="margin-bottom:20px;cursor:pointer;padding:8px 16px;border-radius:20px" onclick="checkUpdates()" data-i18n="check_updates">Check for Updates</button><br>
                    <a href="https://github.com/iWebbIO/php-messenger" target="_blank" class="about-link">GitHub Repository</a>
                    <br><br>
                    <button class="btn-sec" style="width:100%;padding:10px;border:1px solid #f55;color:#f55;border-radius:4px;cursor:pointer;background:transparent" onclick="if(confirm('Logout?')){localStorage.removeItem('mw_auth_token');location.href='?action=logout'}" data-i18n="logout">Logout</button>
                </div>
            </div>
        </div>
        <!-- ABOUT TAB -->
        <div id="tab-about" class="tab-content desktop-only" style="display:none">
            <div class="panel-header" data-i18n="tab_about">About</div>
            <div class="list-area" style="padding:20px; text-align:center; color:#ccc;">
                <h2>moreweb Messenger</h2>
                <p style="color:#888;">Version 0.0.1</p>
                <p data-i18n="about_desc">A secure, self-contained messenger with ephemeral server storage and local history persistence.</p>
                <br>
                <button class="btn-sec" style="margin-bottom:20px;cursor:pointer;padding:8px 16px;border-radius:20px" onclick="checkUpdates()" data-i18n="check_updates">Check for Updates</button><br>
                <a href="https://github.com/iWebbIO/php-messenger" target="_blank" class="about-link">
                    <svg viewBox="0 0 24 24" width="24" height="24" fill="currentColor" style="vertical-align:middle"><path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/></svg>
                    GitHub Repository
                </a>
            </div>
        </div>
    </div>

    <!-- MAIN CHAT -->
    <div class="main-view" id="main-view">
        <div id="chat-view" style="display:flex;flex-direction:column;height:100%;width:100%;position:relative">
        <div class="chat-header">
            <div style="display:flex;align-items:center">
                <div class="back-btn" onclick="closeChat()" style="cursor:pointer">&larr;</div>
                <div class="avatar chat-info-clickable" id="chat-av" onclick="showProfilePopup()"></div>
                <div class="chat-info-clickable" onclick="showProfilePopup()"><div id="chat-title" style="font-weight:bold"></div><div id="chat-sub" style="font-size:0.75rem;color:#999"></div><div id="typing-ind" style="font-size:0.7rem;color:var(--accent);display:none;font-style:italic">typing...</div></div>
            </div>
            
            <div class="header-actions">
                <div class="btn-icon notif-btn" onclick="toggleNotif()">
                    <svg viewBox="0 0 24 24" width="24" fill="currentColor"><path d="M12 22c1.1 0 2-.9 2-2h-4c0 1.1.9 2 2 2zm6-6v-5c0-3.07-1.63-5.64-4.5-6.32V4c0-.83-.67-1.5-1.5-1.5s-1.5.67-1.5 1.5v.68C7.64 5.36 6 7.92 6 11v5l-2 2v1h16v-1l-2-2zm-2 1H8v-6c0-2.48 1.51-4.5 4-4.5s4 2.02 4 4.5v6z"/></svg>
                    <div class="notif-badge" id="notif-count">0</div>
                    <div class="notif-dropdown" id="notif-list"></div>
                </div>
                <div class="btn-icon menu-btn" onclick="toggleMenu(event)">
                    <svg viewBox="0 0 24 24" width="24" fill="currentColor"><path d="M12 8c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm0 2c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zm0 6c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2z"/></svg>
                    <div class="menu-dropdown" id="chat-menu">
                        <div class="menu-item" onclick="clearChat()" data-i18n="clear_history">Clear History</div>
                        <div class="menu-item red-text" onclick="deleteChat()" data-i18n="delete_chat">Delete Chat</div>
                        <div class="menu-item" onclick="exportChat()" data-i18n="export_chat">Export Chat</div>
                    </div>
                </div>
            </div>
        </div>

        <div id="we-overlay" class="we-overlay">
            <svg viewBox="0 0 24 24" width="64" height="64" style="fill:var(--accent)"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-9-2c0-1.66 1.34-3 3-3s3 1.34 3 3v2H9V6zm9 14H6V10h12v10zm-6-3c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2z"/></svg>
            <div class="we-status" id="we-status">Waiting for members...</div>
            <div style="margin-top:10px;color:#888;font-size:0.9rem">Do not leave this screen.</div>
        </div>

        <div class="messages" id="msgs"></div>

        <div id="scroll-btn" class="scroll-btn" onclick="scrollToBottom(true)">
            <svg viewBox="0 0 24 24" width="24" height="24" fill="currentColor"><path d="M7.41 8.59L12 13.17l4.59-4.58L18 10l-6 6-6-6 1.41-1.41z"/></svg>
        </div>

        <div class="input-area" id="input-box" style="visibility:hidden">
            <input type="file" id="file" hidden onchange="uploadFile(this)">
            <div class="input-wrapper">
                <div class="reply-ctx" id="reply-ui">
                    <div id="reply-txt" style="flex:1;overflow:hidden;margin-right:10px"></div>
                <button id="del-btn" style="display:none;font-size:0.8rem;color:#f55;margin-right:10px;background:none;border:none;cursor:pointer" onclick="deleteMsg()">Delete</button>
                    <span onclick="cancelReply()" style="cursor:pointer">&times;</span>
                </div>
                <div id="rec-ui" style="display:none;align-items:center;height:40px;background:#333;border-radius:20px;padding:0 15px;color:#f55">
                    <span style="flex:1">Recording...</span>
                    <span onclick="stopRec(false)" style="cursor:pointer;margin-right:15px;color:#ccc;letter-spacing:0.2em;text-align:center">C A N C E L</span>
                    <button onclick="stopRec(true)" class="btn-icon" style="background:var(--accent);color:#fff;width:45px;height:45px;border-radius:50%"><svg viewBox="0 0 24 24"><path d="M21 7L9 19l-5.5-5.5L5 12.5 9 16.5 19 6l2 1z"/></svg></button>
                </div>
                <textarea id="txt" rows="1" placeholder="Type a message..." enterkeyhint="send"></textarea>
            </div>
            <button class="btn-icon" id="btn-att" onclick="handleAttClick(event)">
                <svg viewBox="0 0 24 24" width="24" fill="currentColor"><path d="M16.5 6v11.5c0 2.21-1.79 4-4 4s-4-1.79-4-4V5a2.5 2.5 0 0 1 5 0v10.5c0 .55-.45 1-1 1s-1-.45-1-1V6H10v9.5a2.5 2.5 0 0 0 5 0V5c0-2.21-1.79-4-4-4S7 2.79 7 5v12.5c0 3.04 2.46 5.5 5.5 5.5s5.5-2.46 5.5-5.5V6h-1.5z"/></svg>
            </button>
            <button class="btn-icon" id="btn-send" style="color:var(--accent)" onmousedown="event.preventDefault()" onclick="handleMainBtn()">
                <svg id="icon-mic" viewBox="0 0 24 24" width="24" fill="currentColor"><path d="M12 14c1.66 0 3-1.34 3-3V5c0-1.66-1.34-3-3-3S9 3.34 9 5v6c0 1.66 1.34 3 3 3z"/><path d="M17 11c0 2.76-2.24 5-5 5s-5-2.24-5-5H5c0 3.53 2.61 6.43 6 6.92V21h2v-3.08c3.39-.49 6-3.39 6-6.92h-2z"/></svg>
                <svg id="icon-send" viewBox="0 0 24 24" width="24" fill="currentColor" style="display:none"><path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"/></svg>
            </button>
        </div>
        <!-- Attachment Menu -->
        <div id="att-menu" class="att-menu">
            <div class="att-item" onclick="pickMedia('camera')">
                <div class="att-icon att-cam"><svg viewBox="0 0 24 24"><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z" style="display:none"/><path d="M9 2L7.17 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2h-3.17L15 2H9zm3 15c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5z"/></svg></div>
                <span class="att-label" data-i18n="camera">Camera</span>
            </div>
            <div class="att-item" onclick="pickMedia('gallery')">
                <div class="att-icon att-gal"><svg viewBox="0 0 24 24"><path d="M21 19V5c0-1.1-.9-2-2-2H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2zM8.5 13.5l2.5 3.01L14.5 12l4.5 6H5l3.5-4.5z"/></svg></div>
                <span class="att-label" data-i18n="gallery">Gallery</span>
            </div>
            <div class="att-item" onclick="pickMedia('file')">
                <div class="att-icon att-file"><svg viewBox="0 0 24 24"><path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg></div>
                <span class="att-label" data-i18n="file">Document</span>
            </div>
            <div class="att-item" onclick="sendLocation()">
                <div class="att-icon att-loc"><svg viewBox="0 0 24 24"><path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5c-1.38 0-2.5-1.12-2.5-2.5s1.12-2.5 2.5-2.5 2.5 1.12 2.5 2.5-1.12 2.5-2.5 2.5z"/></svg></div>
                <span class="att-label" data-i18n="location">Location</span>
            </div>
        </div>
        </div>
        
        <!-- OBSERVATORY VIEW -->
        <div id="observatory-view" style="display:none;flex-direction:column;height:100%;width:100%;overflow-y:auto;background:var(--bg)">
            <div class="obs-header">
                <div class="obs-title"><div class="back-btn mobile-only" onclick="closeObs()" style="cursor:pointer;margin-right:10px">&larr;</div> <span data-i18n="tab_observatory">Observatory</span></div>
                <div style="font-size:0.8rem;color:#888" id="obs-last-upd"></div>
            </div>
            <div id="obs-news-grid" class="obs-grid">
                <div class="tab-loader"><div class="rail-letters"><span>m</span><span>o</span><span>R</span><span>e</span></div><div class="rail-dot"></div></div>
            </div>
        </div>
    </div>
</div>

<script>
const ME = "<?php echo $_SESSION['user']; ?>";
const CSRF_TOKEN = "<?php echo $_SESSION['csrf_token']; ?>";
let lastTyping = 0;
let lastRead = 0;
let mediaRec=null, audChunks=[], recMime='';
let pendingFile = null;
let currentAudio=null, currentBtn=null, updateInterval=null;
let S = { tab:'chats', id:null, type:null, reply:null, ctx:null, dms:{}, groups:{}, online:[], notifs:[], keys:{pub:null,priv:null}, e2ee:{}, we:{active:false, ready:[]}, scroll:{} };

const TR = {
    en: {
        tab_chats: "Chats", tab_groups: "Groups", tab_channels: "Channels", tab_public: "Public", tab_observatory: "Observatory", tab_settings: "Settings", tab_about: "About",
        search_chats: "Search chats...", search_groups: "Search groups...", search_channels: "Search channels...",
        online_users: "Online Users", bio: "Bio / Status", avatar_url: "Avatar URL", new_pass: "New Password", lang_select: "Language",
        toggle_theme: "Toggle Dark/Light Mode", enable_notif: "Enable Notifications", save: "Save", logout: "Logout", check_updates: "Check for Updates",
        about_desc: "A secure, self-contained messenger with ephemeral server storage and local history persistence.",
        clear_history: "Clear History", delete_chat: "Delete Chat", export_chat: "Export Chat",
        camera: "Camera", gallery: "Gallery", file: "Document", location: "Location",
        type_msg: "Type a message...", type_enc: "Type an encrypted message...", only_owner: "Only owner can post",
        start_chat: "Start chatting", join_code: "Join via Code",
        cancel: "CANCEL", preview: "Preview", send: "Send",
        market_usd: "USD", market_oil: "Oil", market_updated: "Updated"
    },
    fa: {
        tab_chats: "گفتگوها", tab_groups: "گروه‌ها", tab_channels: "کانال‌ها", tab_public: "عمومی", tab_observatory: "رصدخانه", tab_settings: "تنظیمات", tab_about: "درباره",
        search_chats: "جستجوی گفتگو...", search_groups: "جستجوی گروه...", search_channels: "جستجوی کانال...",
        online_users: "کاربران آنلاین", bio: "بیوگرافی / وضعیت", avatar_url: "آدرس آواتار", new_pass: "رمز عبور جدید", lang_select: "زبان / Language",
        toggle_theme: "تغییر پوسته (تاریک/روشن)", enable_notif: "فعال‌سازی اعلان‌ها", save: "ذخیره", logout: "خروج", check_updates: "بررسی بروزرسانی",
        about_desc: "یک پیام‌رسان امن و مستقل با ذخیره‌سازی موقت سرور و پایداری تاریخچه محلی.",
        clear_history: "پاک کردن تاریخچه", delete_chat: "حذف گفتگو", export_chat: "خروجی گرفتن",
        camera: "دوربین", gallery: "گالری", file: "سند", location: "موقعیت",
        type_msg: "پیامی بنویسید...", type_enc: "پیام رمزگذاری شده...", only_owner: "فقط مالک می‌تواند پست بگذارد",
        start_chat: "شروع گفتگو", join_code: "عضویت با کد",
        cancel: "لغو", preview: "پیش‌نمایش", send: "ارسال",
        market_usd: "دلار", market_oil: "نفت", market_updated: "بروزرسانی"
    }
};
let curLang = localStorage.getItem('mw_lang') || 'en';

function setLang(l) {
    curLang = l; localStorage.setItem('mw_lang', l);
    document.body.classList.toggle('rtl', l=='fa');
    document.getElementById('set-lang').value = l;
    applyLang();
    renderLists(); // Re-render lists to update static texts inside them if any
    if(S.id) openChat(S.type, S.id); // Re-open chat to update placeholder
}

function applyLang() {
    const t = TR[curLang];
    document.querySelectorAll('[data-i18n]').forEach(el => {
        if(t[el.dataset.i18n]) el.innerText = t[el.dataset.i18n];
    });
    ['chat-search', 'group-search', 'channel-search'].forEach(id => {
        let el = document.getElementById(id);
        if(el) el.placeholder = t['search_' + id.split('-')[0] + 's'];
    });
    // Update specific elements
    let joinBtn = document.querySelector('#tab-groups button'); if(joinBtn) joinBtn.innerText = t.join_code;
    let joinBtnC = document.querySelector('#tab-channels button'); if(joinBtnC) joinBtnC.innerText = t.join_code;
    let cancelRec = document.querySelector('#rec-ui span[onclick*="stopRec(false)"]'); if(cancelRec) cancelRec.innerText = t.cancel;
}

// Mobile Viewport Fix
function setVh() { document.documentElement.style.setProperty('--vh', (window.innerHeight*0.01)+'px'); }
window.addEventListener('resize', setVh);
setVh();

// --- INDEXEDDB HELPERS ---
const DB_NAME = 'mw_chat_db';
const DB_STORE = 'chats';
let dbPromise = new Promise((resolve, reject) => {
    let req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = e => {
        let db = e.target.result;
        if(!db.objectStoreNames.contains(DB_STORE)) db.createObjectStore(DB_STORE);
    };
    req.onsuccess = e => resolve(e.target.result);
    req.onerror = e => reject(e);
});
async function dbOp(mode, fn) {
    try {
        let db = await dbPromise; 
        return new Promise((res, rej) => { 
            let tx = db.transaction(DB_STORE, mode); 
            let req = fn(tx.objectStore(DB_STORE)); 
            tx.oncomplete = () => { if(mode==='readwrite') res(req ? req.result : null); }; 
            tx.onerror = () => rej(tx.error); 
            if(mode==='readonly') { req.onsuccess = () => res(req.result); req.onerror = () => rej(req.error); }
        });
    } catch(e) { console.error("DB Error", e); return mode==='readonly' ? [] : null; }
}

// --- MODAL UTILS ---
function showModal(title, type, placeholder, callback) {
    const ov = document.getElementById('app-modal');
    const tt = document.getElementById('modal-title');
    const bd = document.getElementById('modal-body');
    const ip = document.getElementById('modal-input');
    const ok = document.getElementById('modal-ok');
    const cc = document.getElementById('modal-cancel');

    ov.style.display = 'flex';
    tt.innerText = title;
    
    if(type === 'prompt') {
        bd.style.display = 'none';
        ip.style.display = 'block';
        ip.value = '';
        ip.placeholder = placeholder || '';
        ip.focus();
        cc.style.display = 'block';
    } else if(type === 'confirm') {
        bd.style.display = 'block';
        bd.innerText = placeholder;
        ip.style.display = 'none';
        cc.style.display = 'block';
        ok.innerText = 'Accept';
    } else {
        bd.style.display = 'block';
        bd.innerText = placeholder; // In alert mode, placeholder is body text
        ip.style.display = 'none';
        cc.style.display = 'none';
    }

    ok.onclick = () => {
        const val = ip.value;
        ov.style.display = 'none';
        if(callback) callback(type==='confirm'?true:val);
    };
    cc.onclick = () => { ov.style.display = 'none'; };
    ip.onkeydown = (e) => {
        if(e.key === 'Enter') ok.click();
        if(e.key === 'Escape') cc.click();
    };
}
function promptModal(t, p, cb) { showModal(t, 'prompt', p, cb); }
function alertModal(t, m) { showModal(t, 'alert', m, null); }
function confirmModal(t, m, cb) { showModal(t, 'confirm', m, cb); }

// --- INIT ---
async function loadKeys() {
    if(!window.crypto || !window.crypto.subtle) return;
    let pub = localStorage.getItem('mw_key_pub');
    let priv = localStorage.getItem('mw_key_priv');
    if (pub && priv) {
        S.keys.pub = await window.crypto.subtle.importKey("jwk", JSON.parse(pub), {name:"ECDH",namedCurve:"P-256"}, true, []);
        S.keys.priv = await window.crypto.subtle.importKey("jwk", JSON.parse(priv), {name:"ECDH",namedCurve:"P-256"}, true, ["deriveKey"]);
        req('update_pubkey', {key: JSON.stringify(await window.crypto.subtle.exportKey("jwk", S.keys.pub))});
    } else {
        let k = await window.crypto.subtle.generateKey({name:"ECDH",namedCurve:"P-256"}, true, ["deriveKey"]);
        S.keys.pub = k.publicKey;
        S.keys.priv = k.privateKey;
        localStorage.setItem('mw_key_pub', JSON.stringify(await window.crypto.subtle.exportKey("jwk", k.publicKey)));
        localStorage.setItem('mw_key_priv', JSON.stringify(await window.crypto.subtle.exportKey("jwk", k.privateKey)));
    }
    // Note: In a real app, we'd upload pubkey here, but we do it above if exists or after gen
}

async function saveSession(u, k) {
    S.e2ee[u] = k;
    localStorage.setItem('mw_sess_' + u, JSON.stringify(await window.crypto.subtle.exportKey("jwk", k)));
}

async function loadSessions() {
    if(!window.crypto || !window.crypto.subtle) return;
    for (let i = 0; i < localStorage.length; i++) {
        let k = localStorage.key(i);
        if (k.startsWith('mw_sess_')) {
            let u = k.split('mw_sess_')[1];
            S.e2ee[u] = await window.crypto.subtle.importKey("jwk", JSON.parse(localStorage.getItem(k)), {name:"AES-GCM",length:256}, false, ["encrypt","decrypt"]);
        }
    }
}

async function init(){
    try {
        await loadKeys();
        await loadSessions();
        // Migration from LocalStorage to IndexedDB
        if(!localStorage.getItem('mw_migrated_v1')){
            try {
                let keys = Object.keys(localStorage);
                for(let k of keys){
                    if(k.startsWith('mw_dm_') || k.startsWith('mw_group_') || k.startsWith('mw_public_')){
                        await dbOp('readwrite', s => s.put(JSON.parse(localStorage.getItem(k)), k));
                        localStorage.removeItem(k);
                    }
                }
                localStorage.setItem('mw_migrated_v1', '1');
            } catch(e){ console.error("Migration error", e); }
        }
        if(localStorage.getItem('mw_theme')=='light') document.body.classList.add('light-mode');
        let fs = localStorage.getItem('mw_fontsize');
        let sc = localStorage.getItem('mw_scale');
        if(fs) { document.body.style.fontSize = fs + 'px'; if(document.getElementById('set-fs')) { document.getElementById('set-fs').value = fs; document.getElementById('lbl-fs').innerText = fs + 'px'; } }
        if(sc) { document.body.style.zoom = sc + '%'; if(document.getElementById('set-scale')) { document.getElementById('set-scale').value = sc; document.getElementById('lbl-scale').innerText = sc + '%'; } }
        setLang(curLang);
        pollLoop();
        window.addEventListener('online', () => setConn(false));
        window.addEventListener('offline', () => setConn(false));
    } catch(e) { console.error("Init failed", e); alert("App failed to initialize: " + e.message); }
}

let progW = 0;
function startProg(){
    let p = document.getElementById('progress-bar');
    let c = document.getElementById('progress-bar-container');
    c.classList.remove('loader-hidden');
    p.style.width = '0%';
    setTimeout(() => p.style.width = '70%', 50);
}
function endProg(){
    let p = document.getElementById('progress-bar');
    let c = document.getElementById('progress-bar-container');
    p.style.width = '100%';
    setTimeout(() => {
        c.classList.add('loader-hidden');
        setTimeout(() => p.style.width = '0%', 800);
    }, 300);
}

async function req(act, data) {
    if(act!='poll' && act!='typing') startProg();
    let r = await fetch('?action='+act, {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': CSRF_TOKEN},
        body: JSON.stringify(data||{})
    });
    if(act!='poll' && act!='typing') endProg();
    return r;
}

function showToast(msg) {
    let t = document.getElementById('toast');
    t.innerText = msg;
    t.classList.add('show');
    setTimeout(()=>t.classList.remove('show'), 3000);
}

// --- CORE ---
async function pollLoop() {
    await poll();
    setTimeout(pollLoop, 2000);
}

function setConn(s){
    let el = document.getElementById('conn-indicator');
    if(s) el.classList.add('status-connected');
    else el.classList.remove('status-connected');
}

async function poll(){
    try {
        let lastPub = 0;
        let pubH = await get('public', 'global');
        if(pubH.length) lastPub = pubH[pubH.length-1].id || 0;
        let r=await req('poll', {last_pub: lastPub});
        let d=await r.json();
        setConn(true);
        S.online=d.online;
        if(d.profile){
            document.getElementById('my-av').style.backgroundImage=`url('${d.profile.avatar}')`;
            document.getElementById('my-name').innerText=d.profile.username;
            if(document.activeElement !== document.getElementById('set-bio')) document.getElementById('set-bio').value=d.profile.bio||'';
            document.getElementById('my-date').innerText="Joined: "+new Date(d.profile.joined_at*1000).toLocaleDateString();
        }
        for(let m of d.dms){
            if(m.type=='delete'){ await removeMsg('dm',m.from_user,m.extra_data); continue; }
            if(m.type=='read'){ 
                let h=await get('dm',m.from_user); 
                h.forEach(x=>{if(x.from_user==ME && x.timestamp<=m.extra_data)x.read=true}); 
                await save('dm',m.from_user,h); if(S.id==m.from_user) renderChat(); 
                continue; 
            }
            if(m.type=='wencrypt_ready'){ handleWeReady(m); continue; }
            if(m.type=='wencrypt_key'){ handleWeKey(m); continue; }
            if(m.type=='enc'){ 
                try{
                    if(!S.e2ee[m.from_user]) await ensureE2EE(m.from_user);
                    m.message=await dec(m.from_user,m.message,m.extra_data);
                }catch(e){m.message="[Encrypted]"} 
            }
            await store('dm',m.from_user,m);
            let prev = m.type==='text' ? m.message : '['+m.type+']';
            notify(m.from_user, prev, 'dm');
            if(S.type=='dm' && S.id==m.from_user && document.hasFocus()) req('send', {to_user:m.from_user, type:'read', extra:m.timestamp});
        }
        S.groups={}; for(let g of d.groups){ S.groups[g.id]=g; let ex=await get('group',g.id); if(!ex.length) await save('group',g.id,[]); }
        for(let m of d.group_msgs){ 
            if(m.type=='delete'){ await removeMsg('group',m.group_id,m.extra_data); continue; }
            await store('group',m.group_id,m); 
            let prev = m.type==='text' ? m.message : '['+m.type+']';
            notify(m.group_id, prev, 'group'); 
        }
        for(let m of d.public_msgs){
            await store('public','global',m);
            if(S.tab!='public') notify('global', m.message, 'public');
        }
        if(S.type=='dm' && d.typing && d.typing.includes(S.id)) document.getElementById('typing-ind').style.display='block'; else document.getElementById('typing-ind').style.display='none';

        await renderLists();
        if(S.type=='dm' && S.id){
             let ou=d.online.find(x=>x.username==S.id);
             let sub=ou?(ou.bio||'Online'):'Offline';
             document.getElementById('chat-sub').innerText=sub;
             if(ou && ou.avatar) document.getElementById('chat-av').style.backgroundImage=`url('${ou.avatar}')`;
        }
} catch(e){ console.error("Poll error:", e); setConn(false); }
}

function notify(id, text, type) {
    if(S.type === type && S.id == id && document.hasFocus()) return;
    if(S.notifs.some(n => n.id == id && n.text == text)) return;
    let title = type=='dm'?id:(type=='public'?'Public Chat':(S.groups[id]?S.groups[id].name:(type=='channel'?'Channel':'Group')));
    S.notifs.unshift({id, type, text, title: title, time:new Date()});
    updateNotifUI();
    let badge = type=='dm'?'badge-chats':(type=='channel'?'badge-channels':'badge-groups');
    if(document.getElementById(badge)) document.getElementById(badge).style.display = 'block';

    if(Notification.permission==='granted'){
        let opts={body:text,icon:'?action=icon',tag:'mw-'+id};
        if(navigator.serviceWorker&&navigator.serviceWorker.controller) navigator.serviceWorker.ready.then(r=>r.showNotification(title,opts));
        else new Notification(title,opts);
    }
}

function updateNotifUI() {
    let c = document.getElementById('notif-count');
    c.innerText = S.notifs.length;
    c.style.display = S.notifs.length > 0 ? 'block' : 'none';
    let l = document.getElementById('notif-list');
    let h = S.notifs.length===0 ? '<div style="padding:10px;text-align:center;color:#666">No notifications</div>' : '';
    S.notifs.slice(0,5).forEach((n,i) => {
        h += `<div class="notif-item" onclick="openFromNotif(${i})">
            <b>${esc(n.title)}</b><span style="font-size:0.7rem;color:#888;float:right">${n.time.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}</span><br>
            ${esc(n.text).substring(0,30)}...
        </div>`;
    });
    l.innerHTML = h;
}

function openFromNotif(idx) {
    let n = S.notifs[idx];
    S.notifs.splice(idx, 1);
    updateNotifUI();
    toggleNotif(false);
    switchTab(n.type == 'dm' ? 'chats' : (n.type=='public'?'public':(n.type=='channel'?'channels':'groups')));
    openChat(n.type, n.id);
}

function toggleNotif(force) {
    let el = document.getElementById('notif-list');
    document.getElementById('chat-menu').style.display='none';
    if(force === false) el.style.display='none'; else el.style.display = (el.style.display=='block'?'none':'block');
}

async function get(t,i){ return (await dbOp('readonly', s => s.get(`mw_${t}_${i}`))) || []; }
async function save(t,i,d){ try { await dbOp('readwrite', s => s.put(d, `mw_${t}_${i}`)); } catch(e){ console.error("Save failed", e); } }
async function store(t,i,m){
    let h = await get(t,i);
    let idx = h.findIndex(x=>x.timestamp==m.timestamp && x.message==m.message);
    if(idx !== -1) {
        if(!m.pending && h[idx].pending) {
            h[idx] = m;
            await save(t,i,h);
            if(S.id==i && S.type==t) renderChat();
        }
        return;
    }
    if(m.type.startsWith('wencrypt_')) return; // Don't store signals
    if(m.type=='react'){
        let tg=h.find(x=>x.timestamp==m.extra_data);
        if(tg){ if(!tg.reacts)tg.reacts={}; tg.reacts[m.from_user]=m.message; await save(t,i,h); if(S.id==i && S.type==t) renderChat(); }
        return;
    }
    h.push(m); await save(t,i,h);
    if(S.id==i && S.type==t) {
        let prev = h.length>1 ? h[h.length-2] : null;
        let show = (t=='public'||t=='group'||t=='channel') && m.from_user!=ME && (!prev || prev.from_user!=m.from_user);
        document.getElementById('msgs').appendChild(createMsgNode(m, show, h));
        scrollToBottom(false);
    }
}
async function removeMsg(t,i,ts){
    let h = await get(t,i);
    let idx=h.findIndex(x=>x.timestamp==ts);
    if(idx!=-1){ h.splice(idx,1); await save(t,i,h); if(S.id==i && S.type==t) renderChat(); }
}

function toggleEncryption(){
    if(S.type=='dm') startE2EE();
    else if(S.type=='group') startWEncrypt();
}
async function startE2EE(){
    if(!window.crypto || !window.crypto.subtle) { alertModal('Error', 'Encryption requires HTTPS'); return; }
    if(S.type!='dm'||S.e2ee[S.id])return;
    startProg();
    if(await ensureE2EE(S.id)){
        alertModal("Security", "Encryption enabled.");
        showProfilePopup();
        document.getElementById('txt').placeholder="Type an encrypted message...";
    } else {
        alertModal("Info", "Encryption unavailable. Using standard connection.");
    }
    endProg();
}
async function ensureE2EE(u){
    if(S.e2ee[u]) return true;
    try {
        let r = await fetch('?action=get_profile&u=' + u);
        let d = await r.json();
        if(d.public_key) {
            let fk = await window.crypto.subtle.importKey("jwk", JSON.parse(d.public_key), {name:"ECDH",namedCurve:"P-256"}, true, []);
            let derived = await window.crypto.subtle.deriveKey({name:"ECDH",public:fk}, S.keys.priv, {name:"AES-GCM",length:256}, false, ["encrypt","decrypt"]);
            await saveSession(u, derived);
            return true;
        }
    } catch(e) { console.error("E2EE Setup failed", e); }
    return false;
}
async function enc(u,txt){
    let iv=window.crypto.getRandomValues(new Uint8Array(12));
    let buf=await window.crypto.subtle.encrypt({name:"AES-GCM",iv:iv},S.e2ee[u],new TextEncoder().encode(txt));
    let b=''; new Uint8Array(buf).forEach(x=>b+=String.fromCharCode(x));
    let i=''; iv.forEach(x=>i+=String.fromCharCode(x));
    return {c:btoa(b),i:btoa(i)};
}
async function dec(u,c,i){
    let d=await window.crypto.subtle.decrypt({name:"AES-GCM",iv:Uint8Array.from(atob(i),c=>c.charCodeAt(0))},S.e2ee[u],Uint8Array.from(atob(c),c=>c.charCodeAt(0)));
    return new TextDecoder().decode(d);
}

// --- WENCRYPT (GROUP E2EE) ---
async function startWEncrypt(){
    if(!confirm("WEncrypt cannot be disabled once started. All members must be online. Proceed?")) return;
    S.we.active = true;
    S.we.ready = [];
    document.getElementById('we-overlay').style.display='flex';
    req('send', {group_id:S.id, type:'wencrypt_ready', message:'READY'});
}

function handleWeReady(m){
    if(S.type!='group' || S.id!=m.group_id || !S.we.active) return;
    if(!S.we.ready.includes(m.from_user)) S.we.ready.push(m.from_user);
    
    // Check if we are owner and everyone is ready
    // We need total member count. We can get it from get_group_details cache or fetch
    fetch('?action=get_group_details&id='+S.id).then(r=>r.json()).then(async d=>{
        let total = d.members.length;
        document.getElementById('we-status').innerText = `Waiting for members... (${S.we.ready.length}/${total})`;
        
        if(d.is_owner && S.we.ready.length >= total){
            // Generate Group Key
            let gk = await window.crypto.subtle.generateKey({name:"AES-GCM",length:256}, true, ["encrypt","decrypt"]);
            let gkExp = await window.crypto.subtle.exportKey("jwk", gk);
            let payload = {};
            
            for(let mem of d.members){
                if(mem.username == ME) { payload[ME] = JSON.stringify(gkExp); continue; }
                if(!mem.public_key) continue; // Skip users without keys
                
                // Derive session key for this user
                let theirPub = await window.crypto.subtle.importKey("jwk", JSON.parse(mem.public_key), {name:"ECDH",namedCurve:"P-256"}, true, []);
                let sessKey = await window.crypto.subtle.deriveKey({name:"ECDH",public:theirPub}, S.keys.priv, {name:"AES-GCM",length:256}, false, ["encrypt"]);
                
                // Encrypt the Group Key with Session Key
                let iv = window.crypto.getRandomValues(new Uint8Array(12));
                let buf = await window.crypto.subtle.encrypt({name:"AES-GCM",iv:iv}, sessKey, new TextEncoder().encode(JSON.stringify(gkExp)));
                
                let b=''; new Uint8Array(buf).forEach(x=>b+=String.fromCharCode(x));
                let i=''; iv.forEach(x=>i+=String.fromCharCode(x));
                payload[mem.username] = btoa(b)+':'+btoa(i);
            }
            req('send', {group_id:S.id, type:'wencrypt_key', message:JSON.stringify(payload)});
        }
    });
}

async function handleWeKey(m){
    if(S.type!='group' || S.id!=m.group_id) return;
    let payload = JSON.parse(m.message);
    if(payload[ME]){
        // If owner sent it to themselves (unencrypted) or encrypted
        let kStr = payload[ME];
        if(m.from_user != ME){
            // Decrypt
            let parts = kStr.split(':');
            let ownerPub = await getOwnerPub(m.group_id, m.from_user); // Need to fetch owner pub key
            if(!ownerPub) return;
            let sessKey = await window.crypto.subtle.deriveKey({name:"ECDH",public:ownerPub}, S.keys.priv, {name:"AES-GCM",length:256}, false, ["decrypt"]);
            let d = await window.crypto.subtle.decrypt({name:"AES-GCM",iv:Uint8Array.from(atob(parts[1]),c=>c.charCodeAt(0))}, sessKey, Uint8Array.from(atob(parts[0]),c=>c.charCodeAt(0)));
            kStr = new TextDecoder().decode(d);
        }
        let gk = await window.crypto.subtle.importKey("jwk", JSON.parse(kStr), {name:"AES-GCM",length:256}, false, ["encrypt","decrypt"]);
        S.e2ee[S.id] = gk;
        S.we.active = false;
        document.getElementById('we-overlay').style.display='none';
        alertModal("WEncrypt", "Group is now encrypted.");
    }
}

async function getOwnerPub(gid, ownerName){
    let r = await fetch('?action=get_group_details&id='+gid);
    let d = await r.json();
    let u = d.members.find(x=>x.username==ownerName);
    if(u && u.public_key) return await window.crypto.subtle.importKey("jwk", JSON.parse(u.public_key), {name:"ECDH",namedCurve:"P-256"}, true, []);
    return null;
}

function switchTab(t){
    S.tab=t;
    document.querySelectorAll('.rail-btn').forEach(e=>e.classList.remove('active'));
    document.getElementById('nav-'+t).classList.add('active');
    document.querySelectorAll('.tab-content').forEach(e=>e.style.display='none');
    
    if(t=='public') openChat('public', 'global');
    if(t=='observatory') {
        document.getElementById('chat-view').style.display='none';
        document.getElementById('observatory-view').style.display='flex';
        loadObservatory();
        updateWorldClocks();
    } else {
        document.getElementById('observatory-view').style.display='none';
        document.getElementById('chat-view').style.display='flex';
    }
    document.getElementById('tab-'+t).style.display='flex';
    if(t=='chats') document.getElementById('badge-chats').style.display='none';
    if(t=='groups') document.getElementById('badge-groups').style.display='none';
    if(t=='channels') document.getElementById('badge-channels').style.display='none';
    document.getElementById('nav-panel').classList.remove('hidden');
    document.getElementById('main-view').classList.remove('active');
}

function showObsFeed() {
    document.getElementById('main-view').classList.add('active');
}
function closeObs() {
    document.getElementById('main-view').classList.remove('active');
}

async function loadObservatory() {
    let r = await fetch('?action=get_observatory');
    let d = await r.json();
    
    if(d.status === 'access_denied') {
        document.getElementById('obs-market-list').innerHTML = '';
        document.getElementById('obs-last-upd').innerText = '';
        let h = '<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;text-align:center;padding:20px;color:#ccc">';
        if(d.state == 1) {
            h += '<div style="font-size:3rem;margin-bottom:20px">⏳</div>';
            h += '<h3>Access Pending</h3><p style="color:#888">Your request to access the Observatory is pending approval.</p>';
        } else {
            h += '<div style="font-size:3rem;margin-bottom:20px">🔭</div>';
            h += '<h3>Restricted Access</h3><p style="color:#888;margin-bottom:20px">The Observatory requires special authorization.</p>';
            h += '<button class="btn-primary" onclick="reqObservatory()">Request Access</button>';
        }
        h += '</div>';
        document.getElementById('obs-news-grid').innerHTML = h;
        return;
    }

    if(d.status !== 'success' || !d.data) return;
    
    const t = TR[curLang];
    const m = d.data.market;
    const n = d.data.news;
    
    // Market
    let mh = '';
    if(m.usd) mh += `<div class="market-row-item"><div class="market-row-label">${t.market_usd}</div><div class="market-row-val">${m.usd}</div></div>`;
    if(m.oil) mh += `<div class="market-row-item"><div class="market-row-label">${t.market_oil}</div><div class="market-row-val">${m.oil}</div></div>`;
    if(m.updated) mh += `<div class="market-row-item"><div class="market-row-label">${t.market_updated}</div><div class="market-row-val" style="font-size:1rem;color:#888">${m.updated}</div></div>`;
    document.getElementById('obs-market-list').innerHTML = mh;
    document.getElementById('obs-last-upd').innerText = t.market_updated + ': ' + (m.updated || '-');

    // News
    let nh = '';
    n.forEach((item, i) => {
        let title = item.title_fa || item.title_en;
        let summary = Array.isArray(item.summary) ? '<ul class="news-summary-list">' + item.summary.map(s => `<li>${s}</li>`).join('') + '</ul>' : item.summary;
        let date = new Date(item.timestamp * 1000);
        let timeStr = date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
        let sentimentColor = item.sentiment > 0 ? '#4caf50' : (item.sentiment < 0 ? '#f44336' : '#9e9e9e');
        let aiLabel = curLang == 'fa' ? 'تحلیل هوش مصنوعی' : 'AI Analysis';
        let readMore = curLang == 'fa' ? 'بیشتر بخوانید &larr;' : 'Read More &rarr;';
        let impact = item.impact ? `<div class="news-impact"><strong>${aiLabel}</strong>${item.impact}</div>` : '';
        
        nh += `<div class="news-card-lg" onclick="window.open('${item.url}', '_blank')">
            <div class="news-card-body">
                <div class="news-card-meta"><span class="news-tag">${item.tag}</span> <span style="display:flex;align-items:center"><span class="sentiment-dot" style="background:${sentimentColor}"></span> ${item.source}</span></div>
                <div class="news-card-title">${title}</div>
                <div class="news-card-summary">${summary}</div>
                ${impact}
            </div>
            <div class="news-card-footer">
                <span>${timeStr}</span>
                <span>${readMore}</span>
            </div>
        </div>`;
    });
    document.getElementById('obs-news-grid').innerHTML = nh;
}

async function reqObservatory() {
    if(confirm("Request access to the Observatory?")) {
        await fetch('?action=request_observatory', {method:'POST', headers:{'X-CSRF-Token': CSRF_TOKEN}});
        loadObservatory();
    }
}

async function renderLists(){
    try {
        let dh='';
        const t = TR[curLang];
        let filter = document.getElementById('chat-search').value.toLowerCase();
        let chatFilter = document.getElementById('chat-search').value.toLowerCase();
        let groupFilter = document.getElementById('group-search') ? document.getElementById('group-search').value.toLowerCase() : '';
        let channelFilter = document.getElementById('channel-search') ? document.getElementById('channel-search').value.toLowerCase() : '';
        let keys = (await dbOp('readonly', s => s.getAllKeys())) || [];
        for(let k of keys){
            if(k.startsWith('mw_dm_')){
                let u=k.split('mw_dm_')[1];
                if(filter && !u.toLowerCase().includes(filter)) continue;
                if(chatFilter && !u.toLowerCase().includes(chatFilter)) continue;
                let h = await get('dm', u);
                let lock = S.e2ee[u] ? '<svg viewBox="0 0 24 24" width="14" style="vertical-align:middle;margin-left:4px;fill:var(--accent)"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-9-2c0-1.66 1.34-3 3-3s3 1.34 3 3v2H9V6zm9 14H6V10h12v10zm-6-3c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2z"/></svg>' : '';
                let lastMsg = h.length ? h[h.length-1] : null;
                let last = t.start_chat;
                if(lastMsg) {
                    if(lastMsg.type === 'image') last = '📷 Image';
                    else if(lastMsg.type === 'audio') last = '🎤 Voice Message';
                    else if(lastMsg.type === 'file') last = '📁 File';
                    else last = lastMsg.message;
                }
                if(last.length>30)last=last.substring(0,30)+'...';
                let ou=S.online.find(x=>x.username==u);
                let av=ou?ou.avatar:'';
                dh+=`<div class="list-item ${S.id==u?'active':''}" onclick="openChat('dm','${u}')" oncontextmenu="onChatListContext(event, 'dm', '${u}')">
                    <div class="avatar" style="background-image:url('${av}')">${av?'':u[0].toUpperCase()}</div>
                    <div style="flex:1"><div style="font-weight:bold;display:flex;align-items:center">${u} ${lock} ${ou?'<span style="color:#0f0;font-size:0.8em;margin-left:4px">●</span>':''}</div><div style="font-size:0.8em;color:#888">${last}</div></div>
                    </div>`;
            }
        }
        document.getElementById('list-chats').innerHTML=dh;
        let gh='';
        let ch='';
        Object.values(S.groups).forEach(g=>{
            let isChan = g.category === 'channel';
            if(isChan && channelFilter && !g.name.toLowerCase().includes(channelFilter)) return;
            if(!isChan && groupFilter && !g.name.toLowerCase().includes(groupFilter)) return;
            
            let lock = S.e2ee[g.id] ? '<svg viewBox="0 0 24 24" width="14" style="vertical-align:middle;margin-left:4px;fill:var(--accent)"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-9-2c0-1.66 1.34-3 3-3s3 1.34 3 3v2H9V6zm9 14H6V10h12v10zm-6-3c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2z"/></svg>' : '';
            let html = `<div class="list-item ${S.id==g.id?'active':''}" onclick="openChat('${isChan?'channel':'group'}',${g.id})" oncontextmenu="onChatListContext(event, '${isChan?'channel':'group'}', ${g.id})">
                <div class="avatar">${isChan?'📢':'#'}</div>
                <div><div style="font-weight:bold;display:flex;align-items:center">${g.name} ${lock}</div><div style="font-size:0.8em;color:#888">${g.type}</div></div>
            </div>`;
            
            if(isChan) ch += html; else gh += html;
        });
        document.getElementById('list-groups').innerHTML=gh;
        document.getElementById('list-channels').innerHTML=ch;
        document.getElementById('online-count').innerText=S.online.length;
        let sp=document.getElementById('app-splash'); if(sp){ sp.style.transition='opacity 0.2s'; sp.style.opacity=0; setTimeout(()=>sp.remove(),200); }
    } catch(e) { console.error("RenderLists error", e); }
}

async function openChat(t,i){
    if(S.id) {
        let c=document.getElementById('msgs');
        if(c.scrollHeight - c.scrollTop - c.clientHeight > 50) S.scroll[S.type+'_'+S.id] = c.scrollTop;
        else delete S.scroll[S.type+'_'+S.id];
    }
    document.getElementById('observatory-view').style.display='none';
    document.getElementById('chat-view').style.display='flex';
    document.getElementById('we-overlay').style.display='none';
    if(S.id!=i) lastRead=0;
    S.type=t; S.id=i;
    renderLists();
    await renderChat(); 
    if(S.scroll[t+'_'+i]!==undefined) {
        let c=document.getElementById('msgs'); c.scrollTop = S.scroll[t+'_'+i];
        requestAnimationFrame(()=>c.scrollTop = S.scroll[t+'_'+i]);
    } else scrollToBottom(true);
    document.getElementById('input-box').style.visibility='visible';
    document.getElementById('main-view').classList.add('active');
        document.getElementById('nav-panel').classList.add('hidden');
    let tit=i, sub='', av='';
    const langT = TR[curLang];
    let canPost = true;
    if(t=='dm'){
        let ou=S.online.find(x=>x.username==i);
        sub=ou?(ou.bio||'Online'):'Offline'; av=ou?ou.avatar:'';
        if(av) document.getElementById('chat-av').style.backgroundImage=`url('${av}')`;
        document.getElementById('chat-av').innerText=av?'':i[0];
    } else if(t=='group' || t=='channel') {
        let g = S.groups[i];
        tit=g.name; sub=t=='channel'?'Channel':'Group';
        document.getElementById('chat-av').innerText=t=='channel'?'📢':'#';
        if(t=='channel' && g.owner_id != <?php echo $_SESSION['uid']; ?>) canPost = false;
    } else if(t=='public') {
        tit="Public Chat"; sub="Global Room (5m TTL)";
        document.getElementById('chat-av').innerText='P';
    }
    document.getElementById('chat-title').innerText=tit;
    document.getElementById('chat-sub').innerText=sub;
    document.getElementById('txt').placeholder = (t=='dm' && S.e2ee[S.id]) ? langT.type_enc : (canPost ? langT.type_msg : langT.only_owner);
    document.getElementById('input-box').style.visibility = canPost ? 'visible' : 'hidden';
    toggleMainBtn();
    if(window.innerWidth > 768) setTimeout(()=>document.getElementById('txt').focus(), 50);
    
    if(t=='dm'){ let h=await get('dm',i); let last=h.filter(x=>x.from_user==i).pop(); if(last && last.timestamp>lastRead){ lastRead=last.timestamp; req('send',{to_user:i,type:'read',extra:last.timestamp}); } }
}

function scrollToMsg(ts){
    let el = document.getElementById('msg-'+ts);
    if(el) {
        el.scrollIntoView({behavior:'smooth', block:'center'});
        el.style.transition = 'background 0.5s';
        el.style.background = 'var(--accent)';
        setTimeout(()=>el.style.background='', 500);
    }
}

function createMsgNode(m, showSender, history){
    let div=document.createElement('div');
    div.id = 'msg-' + m.timestamp;
    div.className=`msg ${m.from_user==ME?'out':'in'} ${m.pinned?'pinned':''}`;
    let sender='';
    if(showSender) sender=`<div class="msg-sender" onclick="if(ME!='${m.from_user}'){openChat('dm','${m.from_user}');switchTab('chats');}">${m.from_user}</div>`;

    let txt=esc(m.message);
    if(m.type=='image') txt=`<img src="${m.message.replace(/"/g, '&quot;')}" onclick="window.open(this.src)" onload="scrollToBottom(false)">`;
    else if(m.type=='audio') txt=`<div class="audio-player">
            <button class="play-btn" onclick="playAudio(this)">
                <svg viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg>
            </button>
            <div class="audio-progress" onclick="seekAudio(this, event)"><div class="audio-bar"></div></div>
            <div class="audio-time">0:00</div>
            <audio src="${m.message}" style="display:none" onloadedmetadata="this.parentElement.querySelector('.audio-time').innerText=formatTime(this.duration)"></audio>
        </div>`;
    else if(m.type=='file') {
        let fname = esc(m.extra_data || 'file');
        let safeName = (m.extra_data || 'file').replace(/'/g, "\\'");
        txt = `<div class="file-att" onclick="downloadFile('${m.message}', '${safeName}')">
            <svg viewBox="0 0 24 24" width="24" fill="currentColor"><path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>
            <span>${fname}</span></div>`;
    }
    
    let rep='';
    if(m.reply_to_id && history){
        let p=history.find(x=>x.timestamp==m.reply_to_id);
        if(p) {
            let rTxt = p.type=='image'?'📷 Image':(p.type=='audio'?'🎤 Audio':(p.type=='file'?'📁 File':esc(p.message).substring(0,30)+'...'));
            rep=`<div style="font-size:0.8em;border-left:2px solid var(--accent);padding-left:4px;margin-bottom:4px;opacity:0.7;cursor:pointer" onclick="scrollToMsg(${m.reply_to_id})">Reply to <b>${esc(p.from_user)}</b>: ${rTxt}</div>`;
        }
    }
    let reacts='';
    if(m.reacts) reacts=`<div class="reaction-bar">${Object.values(m.reacts).join('')}</div>`;
    let stat='';
    if(m.from_user==ME && S.type=='dm') stat = m.read ? '<span style="color:#4fc3f7;margin-left:3px">✓✓</span>' : '<span style="margin-left:3px">✓</span>';
    if(m.pending) stat = '<span style="color:#888;margin-left:3px">🕒</span>';
    div.innerHTML=`${sender}${rep}${txt}<div class="msg-meta">${new Date(m.timestamp*1000).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})} ${stat}</div>${reacts}`;
    
    div.oncontextmenu=(e)=>{
        e.preventDefault();
        showContextMenu(e, 'message', m);
    };
    div.ondblclick=()=>{ sendReact(m.timestamp, '❤️'); };
    return div;
}

async function renderChat(){
    let h = await get(S.type,S.id);
    let c=document.getElementById('msgs'); c.innerHTML='';
    let last=null, lastDate=null;
    h.forEach(m=>{
        let d = new Date(m.timestamp*1000);
        let dateStr = d.toLocaleDateString();
        if(dateStr !== lastDate) {
            let sep = document.createElement('div');
            sep.style.cssText = "text-align:center;font-size:0.8rem;color:#666;margin:10px 0;position:sticky;top:0;z-index:5;";
            sep.innerHTML = `<span style="background:var(--panel);padding:4px 10px;border-radius:10px;border:1px solid var(--border)">${dateStr}</span>`;
            c.appendChild(sep);
            lastDate = dateStr;
        }
        let show=(S.type=='public'||S.type=='group'||S.type=='channel') && m.from_user!=ME && m.from_user!=last;
        c.appendChild(createMsgNode(m, show, h));
        last=m.from_user;
    });
}

function closeChat() {
    if(S.id) {
        let c=document.getElementById('msgs');
        if(c.scrollHeight - c.scrollTop - c.clientHeight > 50) S.scroll[S.type+'_'+S.id] = c.scrollTop;
        else delete S.scroll[S.type+'_'+S.id];
    }
    document.getElementById('main-view').classList.remove('active');
    document.getElementById('nav-panel').classList.remove('hidden');
    S.id=null;
    renderLists();
}

async function send(){
    let txt=document.getElementById('txt').value.trim();
    if(!txt)return;
    
    // Optimistic UI
    document.getElementById('txt').value=''; 
    document.getElementById('txt').style.height='40px';
    toggleMainBtn();
    if(navigator.vibrate) navigator.vibrate(20);
    let replyId = S.reply;
    cancelReply();
    
    let ts = Math.floor(Date.now()/1000);
    let msgObj = {
        from_user: ME,
        message: txt,
        type: 'text',
        timestamp: ts,
        reply_to_id: replyId,
        pending: true
    };
    await store(S.type, S.id, msgObj);
    scrollToBottom(true);

    // Prepare Network Request
    let load = { message: txt, type: 'text', reply_to: replyId, timestamp: ts };
    if(S.type=='dm') load.to_user=S.id; else if(S.type=='group'||S.type=='channel') load.group_id=S.id; else if(S.type=='public') load.group_id=-1;

    if(S.type=='dm' && S.e2ee[S.id]){
        try {
            let e=await enc(S.id,txt);
            load.message=e.c; load.extra=e.i; load.type='enc';
        } catch(e){ console.error("Encryption failed, sending plain", e); }
    }

    try {
        let r = await req('send', load);
        let d = await r.json();
        if(d.status === 'success') {
            let h = await get(S.type, S.id);
            let m = h.find(x => x.timestamp == ts && x.message == txt);
            if(m) { delete m.pending; await save(S.type, S.id, h); renderChat(); }
        }
    } catch(e) { console.error(e); }
}

// --- CONTEXT MENU ---
function showContextMenu(e, type, data) {
    const t = TR[curLang];
    e.preventDefault();
    S.ctx = {type, data};
    let menu = document.getElementById('ctx-menu');
    let html = '';
    
    if(type == 'message') {
        html = `<div class="ctx-reactions">
        <span class="ctx-reaction" onclick="ctxAction('react','❤️')">❤️</span>
        <span class="ctx-reaction" onclick="ctxAction('react','😂')">😂</span>
        <span class="ctx-reaction" onclick="ctxAction('react','😮')">😮</span>
        <span class="ctx-reaction" onclick="ctxAction('react','😢')">😢</span>
        <span class="ctx-reaction" onclick="ctxAction('react','👍')">👍</span>
        </div>
        <div class="ctx-item" onclick="ctxAction('reply')">Reply</div>
        <div class="ctx-item" onclick="ctxAction('forward')">Forward</div>
        <div class="ctx-item" onclick="ctxAction('copy')">Copy</div>
        <div class="ctx-item" onclick="ctxAction('pin')">Pin Message</div>
        <div class="ctx-item" onclick="ctxAction('details')">Details</div>
        <div class="ctx-separator"></div>
        <div class="ctx-item red-text" onclick="ctxAction('delete')">Delete</div>`; // Translations for context menu can be added similarly
    } else if(type == 'chat_list') {
        html = `<div class="ctx-item" onclick="ctxAction('open')">Open</div>
        <div class="ctx-item" onclick="ctxAction('clear')">${t.clear_history}</div>
        <div class="ctx-separator"></div>
        <div class="ctx-item red-text" onclick="ctxAction('del_chat')">${t.delete_chat}</div>`;
    } else {
        html = `<div class="ctx-item" onclick="ctxAction('theme')">Toggle Theme</div>
        <div class="ctx-item" onclick="ctxAction('settings')">Settings</div>
        <div class="ctx-item" onclick="ctxAction('about')">About</div>`;
    }
    
    menu.innerHTML = html;
    menu.style.display = 'block';
    
    let x = e.clientX, y = e.clientY;
    if (x + 180 > window.innerWidth) x = window.innerWidth - 190;
    if (y + menu.offsetHeight > window.innerHeight) y = window.innerHeight - menu.offsetHeight;
    menu.style.left = x + 'px';
    menu.style.top = y + 'px';
    if(navigator.vibrate) navigator.vibrate(30);
}

function onChatListContext(e, type, id) { showContextMenu(e, 'chat_list', {type, id}); }

async function ctxAction(act, arg) {
    document.getElementById('ctx-menu').style.display='none';
    let c = S.ctx;
    if(!c) return;
    
    if(c.type == 'message') {
        let m = c.data;
        if(act=='react') await sendReact(m.timestamp, arg);
        else if(act=='reply') { S.reply=m.timestamp; document.getElementById('reply-ui').style.display='flex'; let snip=m.type=='text'?esc(m.message).substring(0,30):'['+m.type+']'; document.getElementById('reply-txt').innerHTML=`<div style="font-size:0.75rem;color:var(--accent);margin-bottom:2px">Replying to ${m.from_user}</div><div style="color:var(--text);opacity:0.9;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${snip}</div>`; document.getElementById('del-btn').style.display='none'; document.getElementById('txt').focus(); }
        else if(act=='forward') promptModal("Forward", "Username:", u=>{ if(u) req('send',{message:m.message,type:m.type,extra:m.extra_data,to_user:u}); });
        else if(act=='copy') { if(m.type=='text') { navigator.clipboard.writeText(m.message); showToast('Copied to clipboard'); } }
        else if(act=='pin') { let h=await get(S.type,S.id); let t=h.find(x=>x.timestamp==m.timestamp); if(t){t.pinned=!t.pinned; await save(S.type,S.id,h); renderChat();} }
        else if(act=='details') alertModal("Details", `From: ${m.from_user}\nSent: ${new Date(m.timestamp*1000).toLocaleString()}`);
        else if(act=='delete') { if(m.from_user!=ME)return; S.reply=m.timestamp; await deleteMsg(); }
    } else if(c.type == 'chat_list') {
        let d = c.data;
        if(act=='open') { openChat(d.type, d.id); switchTab(d.type=='dm'?'chats':'groups'); }
        else if(act=='clear') { if(confirm("Clear history?")) { await save(d.type, d.id, []); if(S.id==d.id) renderChat(); renderLists(); } }
        else if(act=='del_chat') { if(confirm("Delete chat?")) { await dbOp('readwrite', s=>s.delete(`mw_${d.type}_${d.id}`)); if(S.id==d.id) closeChat(); renderLists(); } }
    } else {
        if(act=='theme') toggleTheme();
        else if(act=='settings') switchTab('settings');
        else if(act=='about') switchTab('about');
    }
}

async function sendReact(ts,e){
    let ld={message:e,type:'react',extra:ts};
    if(S.type=='dm')ld.to_user=S.id; else if(S.type=='group'||S.type=='channel') ld.group_id=S.id; else if(S.type=='public') ld.group_id=-1;
    req('send', ld);
    let h = await get(S.type,S.id);
    let m=h.find(x=>x.timestamp==ts);
    if(m){ if(!m.reacts)m.reacts={}; m.reacts[ME]=e; await save(S.type,S.id,h); renderChat(); }
}

async function deleteMsg(){
    if(!S.reply)return;
    let ld={message:'DEL', type:'delete', extra:S.reply};
    if(S.type=='dm')ld.to_user=S.id; else if(S.type=='group'||S.type=='channel') ld.group_id=S.id; else if(S.type=='public') ld.group_id=-1;
    req('send', ld);
    await removeMsg(S.type,S.id,S.reply); cancelReply();
}

function toggleMenu(e){
    if(e && e.target.closest('.menu-dropdown')) return;
    let m=document.getElementById('chat-menu');
    let wasVisible = m.style.display=='block';
    toggleNotif(false);
    if(!wasVisible) m.style.display='block';
}
async function clearChat(){
    if(!confirm("Clear history?")) return;
    await save(S.type, S.id, []); renderChat(); toggleMenu();
}
async function exportChat(){
    let h = await get(S.type, S.id);
    let blob = new Blob([JSON.stringify(h, null, 2)], {type : 'application/json'});
    let a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `chat_${S.type}_${S.id}.json`;
    a.click(); toggleMenu();
}
async function deleteChat(){
    if(!confirm("Delete chat permanently?")) return;
    await dbOp('readwrite', s=>s.delete(`mw_${S.type}_${S.id}`));
    closeChat(); switchTab('chats'); toggleMenu();
}
function toggleTheme(){
    document.body.classList.toggle('light-mode');
    localStorage.setItem('mw_theme', document.body.classList.contains('light-mode')?'light':'dark');
}

function applyAppearance(){
    let fs = document.getElementById('set-fs').value;
    let sc = document.getElementById('set-scale').value;
    document.getElementById('lbl-fs').innerText = fs + 'px';
    document.getElementById('lbl-scale').innerText = sc + '%';
    document.body.style.fontSize = fs + 'px';
    document.body.style.zoom = sc + '%';
    localStorage.setItem('mw_fontsize', fs);
    localStorage.setItem('mw_scale', sc);
}

function checkUpdates(){
    if(!('serviceWorker' in navigator)){ alertModal('Info','Service Worker not active.'); return; }
    navigator.serviceWorker.ready.then(r=>{
        r.update().then(()=>{
            if(r.installing || r.waiting) alertModal('Update','New version found! Restart app to apply.');
            else alertModal('Info','You are up to date.');
        });
    });
}

function enableNotifs(){
    if(!('Notification' in window)){ alertModal('Error','Notifications not supported'); return; }
    Notification.requestPermission().then(p=>{
        if(p==='granted') alertModal('Success','Notifications enabled');
        else alertModal('Info','Notifications denied');
    });
}

function handleAttClick(e) {
    if(window.innerWidth > 768) {
        pickMedia('file');
    } else {
        let m = document.getElementById('att-menu');
        let wasVisible = m.style.display=='grid';
        toggleNotif(false);
        document.getElementById('chat-menu').style.display='none';
        m.style.display = wasVisible ? 'none' : 'grid';
        if(!wasVisible) document.getElementById('txt').blur();
        e.stopPropagation();
    }
}
function pickMedia(type) {
    let f = document.getElementById('file');
    f.value = ''; f.removeAttribute('capture'); f.removeAttribute('accept');
    if(type === 'camera') { f.accept = 'image/*'; f.setAttribute('capture', 'environment'); }
    else if(type === 'gallery') { f.accept = 'image/*'; }
    f.click();
    document.getElementById('att-menu').style.display='none';
}
function sendLocation() {
    if(!navigator.geolocation) return alertModal('Error', 'Geolocation not supported');
    startProg();
    navigator.geolocation.getCurrentPosition(pos => {
        endProg();
        let link = `https://www.google.com/maps?q=${pos.coords.latitude},${pos.coords.longitude}`;
        let ts = Math.floor(Date.now()/1000);
        let ld = {message: link, type: 'text', timestamp: ts};
        if(S.type=='dm') ld.to_user=S.id; else if(S.type=='group'||S.type=='channel') ld.group_id=S.id; else ld.group_id=-1;
        req('send', ld);
        store(S.type,S.id,{from_user:ME,message:link,type:'text',timestamp:ts});
        scrollToBottom(true);
        document.getElementById('att-menu').style.display='none';
    }, err => { endProg(); alertModal('Error', 'Location access denied'); });
}

async function uploadFile(inp){
    let f=inp.files[0]; if(!f)return;
    inp.value = ''; // Reset
    
    if(f.type.startsWith('image/') && f.type !== 'image/gif'){
        startProg();
        try {
            let img = await new Promise((res,rej)=>{let i=new Image();i.onload=()=>res(i);i.onerror=rej;i.src=URL.createObjectURL(f);});
            let cvs = document.createElement('canvas');
            let w=img.width, h=img.height, max=1600;
            if(w>max||h>max){ if(w>h){h*=max/w;w=max;}else{w*=max/h;h=max;} }
            cvs.width=w; cvs.height=h;
            cvs.getContext('2d').drawImage(img,0,0,w,h);
            let blob = await new Promise(r=>cvs.toBlob(r,'image/jpeg',0.8));
            pendingFile = new File([blob], f.name, {type:'image/jpeg'});
            
            // Show Preview
            document.getElementById('preview-img').src = URL.createObjectURL(pendingFile);
            document.getElementById('preview-info').innerText = `${(pendingFile.size/1024).toFixed(1)} KB`;
            document.getElementById('media-preview').style.display = 'flex';
        } catch(e){ console.log("Compression failed", e); alertModal('Error', 'Image processing failed'); }
        endProg();
    } else {
        sendFile(f);
    }
}

function sendPreview() {
    if(pendingFile) sendFile(pendingFile);
    closePreview();
}

function closePreview() {
    document.getElementById('media-preview').style.display = 'none';
    let img = document.getElementById('preview-img');
    if(img.src) URL.revokeObjectURL(img.src);
    document.getElementById('preview-img').src = '';
    pendingFile = null;
}

async function sendFile(fileToSend) {
    startProg();
    let ts = Math.floor(Date.now()/1000);
    let replyId = S.reply;
    cancelReply();
    
    // Optimistic Render
    let r = new FileReader();
    r.onload = async () => {
        let type = fileToSend.type.startsWith('image/') ? 'image' : 'file';
        await store(S.type,S.id,{from_user:ME,message:r.result,type:type,timestamp:ts,extra_data:fileToSend.name, reply_to_id:replyId, pending:true});
        scrollToBottom(true);
    };
    r.readAsDataURL(fileToSend);

    let fd = new FormData();
    fd.append('file', fileToSend);
    fd.append('timestamp', ts);
    if(replyId) fd.append('reply_to', replyId);
    if(S.type=='dm') fd.append('to_user', S.id);
    else if(S.type=='group'||S.type=='channel') fd.append('group_id', S.id);
    else fd.append('group_id', -1);

    try {
        let res = await fetch('?action=upload_msg', { method:'POST', body:fd, headers:{'X-CSRF-Token': CSRF_TOKEN} });
        let d = await res.json();
        endProg();
        if(d.status!='success') {
            alertModal('Error', d.message||'Upload failed');
            let h = await get(S.type, S.id);
            let idx = h.findIndex(x => x.timestamp == ts && x.extra_data == fileToSend.name);
            if(idx!=-1) { h.splice(idx, 1); await save(S.type, S.id, h); renderChat(); }
        } else {
            let h = await get(S.type, S.id);
            let m = h.find(x => x.timestamp == ts && x.extra_data == fileToSend.name);
            if(m) { delete m.pending; await save(S.type, S.id, h); renderChat(); }
        }
    } catch(e) {
        endProg();
        console.error(e);
        alertModal('Error', 'Upload failed');
        let h = await get(S.type, S.id);
        let idx = h.findIndex(x => x.timestamp == ts && x.extra_data == fileToSend.name);
        if(idx!=-1) { h.splice(idx, 1); await save(S.type, S.id, h); renderChat(); }
    }
}

function downloadFile(data, name){
    let a = document.createElement('a'); a.href = data; a.download = name; a.click();
}

function cancelReply(){ S.reply=null; document.getElementById('reply-ui').style.display='none'; document.getElementById('del-btn').style.display='none'; }
function promptChat(){ promptModal("New Chat", "Username:", async (u)=>{ if(u){ let ex=await get('dm',u); if(!ex.length) await save('dm',u,[]); openChat('dm',u); switchTab('chats'); }}); }

function createGroup(){ createEntity('group'); }
function createChannel(){ createEntity('channel'); }

function createEntity(type){ 
    let label = type=='channel'?'Channel':'Group';
    alertModal("Create "+label, "");
    document.getElementById('modal-ok').style.display='none';
    document.getElementById('modal-cancel').style.display='block';
    document.getElementById('modal-body').innerHTML = `
        <input id="ng-name" class="form-input" placeholder="${label} Name">
        <select id="ng-type" class="form-select">
            <option value="public">Public (Code)</option>
            <option value="discoverable">Discoverable (Listed)</option>
            <option value="private">Private (Invite Only)</option>
        </select>
        <button class="btn-primary" style="width:100%;margin-top:10px" onclick="doCreateGroup('${type}')">Create</button>
    `;
}
function doCreateGroup(cat){
    let n=document.getElementById('ng-name').value;
    let t=document.getElementById('ng-type').value;
    let btn=document.querySelector('#modal-body button');
    if(n) {
        btn.disabled=true; btn.innerText='Creating...';
        req('create_group',{name:n,type:t,category:cat}).then(r=>r.json()).then(d=>{
        if(d.status=='success'){ document.getElementById('app-modal').style.display='none'; renderLists(); }
        else { alert(d.message||'Error'); btn.disabled=false; btn.innerText='Create'; }
    }).catch(()=>{ alert('Connection failed'); btn.disabled=false; btn.innerText='Create'; });
    }
}

function joinGroup(){ 
    alertModal("Join Group", "");
    document.getElementById('modal-body').innerHTML = `
        <input id="jg-code" class="form-input" placeholder="Invite Code">
        <input id="jg-pass" class="form-input" type="password" placeholder="Password (Optional)">
        <button class="btn-primary" style="width:100%;margin-top:10px" onclick="doJoinGroup()">Join</button>
    `;
}
function doJoinGroup(){
    let c=document.getElementById('jg-code').value;
    let p=document.getElementById('jg-pass').value;
    if(c) req('join_group',{code:c, password:p}).then(r=>r.json()).then(d=>{
        if(d.status=='success'){ document.getElementById('app-modal').style.display='none'; renderLists(); }
        else alert(d.message);
    });
}

function saveSettings(){ req('update_profile',{bio:document.getElementById('set-bio').value,avatar:document.getElementById('set-av').value,new_password:document.getElementById('set-pw').value}); alertModal("Settings", "Profile updated."); }

async function discover(cat){ startProg(); alertModal("Discover "+(cat=='channel'?'Channels':'Groups'), '<div class="tab-loader" style="min-height:150px"><div class="rail-letters"><span>m</span><span>o</span><span>R</span><span>e</span></div><div class="rail-dot"></div></div>'); let r=await fetch('?action=get_discoverable_groups&cat='+cat); endProg(); let d=await r.json(); let h='<div style="max-height:300px;overflow-y:auto">'; d.items.forEach(g=>{ h+=`<div style="padding:10px;border-bottom:1px solid #333;display:flex;justify-content:space-between;align-items:center"><div><b>${g.name}</b><br><span style="color:#888;font-size:0.8rem">Code: ${g.join_code}</span></div><button class="btn-sec" onclick="req('join_group',{code:'${g.join_code}'}).then(()=>{document.getElementById('app-modal').style.display='none';renderLists()})">Join</button></div>`; }); h+='</div>'; document.getElementById('modal-body').innerHTML=h; }

async function showProfilePopup() {
    if(S.type === 'dm') {
        startProg();
        let r = await fetch('?action=get_profile&u='+S.id);
        endProg();
        let p = await r.json();
        if(p.status === 'error') return;
        
        let html = `<div style="text-align:center;margin-bottom:15px">
            <div class="avatar" style="width:80px;height:80px;margin:0 auto 10px auto;font-size:2rem;background-image:url('${p.avatar||''}')">${p.avatar?'':p.username[0]}</div>
            <b>${p.username}</b><br>
            <span style="color:#888;font-size:0.8rem">${p.bio||'-'}</span><br>
            <div style="font-size:0.8rem;color:#666;margin-top:5px">
                Joined: ${new Date(p.joined_at*1000).toLocaleDateString()}<br>
                Last Seen: ${new Date(p.last_seen*1000).toLocaleString()}
            </div>
            ${!S.e2ee[S.id] ? `<button class="btn-sec" style="margin-top:15px;width:100%" onclick="startE2EE();document.getElementById('app-modal').style.display='none'">Enable End-to-End Encryption</button>` : `<div style="margin-top:15px;color:var(--accent)">🔒 Encrypted</div>`}
        </div>`;
        alertModal("Profile", ""); document.getElementById('modal-body').innerHTML = html;
    } else if (S.type === 'group' || S.type === 'channel') {
        startProg();
        let r = await fetch('?action=get_group_details&id='+S.id);
        endProg();
        let d = await r.json();
        if(d.status === 'error') return;
        
        let html = `<div style="text-align:center;margin-bottom:15px">
            <b>${d.group.name}</b><br>
            <span style="color:#888;font-size:0.8rem">${d.group.category=='channel'?'Channel':'Group'} - ${d.group.type} ${d.group.join_code ? '| Code: '+d.group.join_code : ''}</span><br>
            ${d.is_owner && d.group.type=='private' ? `<button class="btn-sec" style="font-size:0.7rem;margin-top:5px" onclick="groupSettings(${S.id})">Manage Invite</button>` : ''}
            ${!S.e2ee[S.id] && d.group.category!='channel' ? `<button class="btn-sec" style="margin-top:10px;width:100%" onclick="startWEncrypt();document.getElementById('app-modal').style.display='none'">Enable WEncrypt</button>` : ``}
        </div>
        <div style="max-height:200px;overflow-y:auto;text-align:left;margin-bottom:15px;background:#222;padding:10px;border-radius:8px">
            <div style="font-size:0.8rem;color:#aaa;margin-bottom:5px">Members (${d.members.length})</div>
            ${d.members.map(m=>`<div style="padding:5px;border-bottom:1px solid #333;display:flex;align-items:center">
                <div class="avatar" style="width:24px;height:24px;font-size:0.8rem;margin-right:8px;background-image:url('${m.avatar||''}')">${m.avatar?'':m.username[0]}</div>
                <span>${m.username}</span> ${m.public_key?'<span title="Key Available" style="color:#0f0;font-size:0.6rem;margin-left:5px">🔑</span>':''}
            </div>`).join('')}
        </div>
        <div style="display:flex;gap:10px;justify-content:center">
            <button class="btn-modal btn-sec" style="color:#f55;border-color:#f55" onclick="leaveGroup(${S.id})">Leave Group</button>
            ${d.is_owner ? `<button class="btn-modal btn-sec" style="color:#f55;border-color:#f55" onclick="nukeGroup(${S.id})">Delete Group</button>` : ''}
        </div>`;
        
        alertModal("Group Info", ""); 
        document.getElementById('modal-body').innerHTML = html;
    }
}

function groupSettings(gid){
    alertModal("Group Settings", "");
    document.getElementById('modal-body').innerHTML = `
        <div class="form-group"><label>Enable Joining</label> <input type="checkbox" id="gs-join"></div>
        <div class="form-group"><label>Code Suffix (Letter)</label><input id="gs-suff" class="form-input" maxlength="1" placeholder="A-Z"></div>
        <div class="form-group"><label>Password (Optional)</label><input id="gs-pass" class="form-input" type="password"></div>
        <div class="form-group"><label>Expiry (Minutes)</label><input id="gs-exp" class="form-input" type="number" placeholder="60"></div>
        <button class="btn-primary" style="width:100%;margin-top:10px" onclick="saveGroupSettings(${gid})">Generate New Code</button>
    `;
}
function saveGroupSettings(gid){
    let j = document.getElementById('gs-join').checked ? 1 : 0;
    let s = document.getElementById('gs-suff').value;
    let p = document.getElementById('gs-pass').value;
    let e = document.getElementById('gs-exp').value;
    req('update_group_settings', {group_id:gid, join_enabled:j, generate_code:true, suffix:s, password:p, expiry:e}).then(r=>r.json()).then(d=>{
        if(d.status=='success') { alert("Settings updated & Code generated"); showProfilePopup(); }
        else alert(d.message);
    });
}

function leaveGroup(gid){
    if(confirm("Leave this group?")) req('leave_group', {group_id: gid}).then(d=>{ if(d.status=='success'){ closeChat(); delete S.groups[gid]; renderLists(); document.getElementById('app-modal').style.display='none'; } });
}

function nukeGroup(gid){
    if(confirm("Delete group for everyone?")) req('delete_group', {group_id: gid}).then(d=>{ if(d.status=='success'){ closeChat(); delete S.groups[gid]; renderLists(); document.getElementById('app-modal').style.display='none'; } });
}

function scrollToBottom(force){ 
    let c=document.getElementById('msgs'); 
    if(force) { c.scrollTop=c.scrollHeight; return; }
    if(c.scrollHeight - c.scrollTop - c.clientHeight < 150) c.scrollTo({ top: c.scrollHeight, behavior: 'smooth' });
}
function esc(t){ return t?t.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"):"" }

document.getElementById('txt').onkeydown=e=>{if(e.key=='Enter' && !e.shiftKey){e.preventDefault();send()}};
document.getElementById('txt').onkeydown=e=>{if(e.key=='Enter' && !e.shiftKey){e.preventDefault();handleMainBtn()}};
document.getElementById('txt').addEventListener('focus', () => { document.getElementById('att-menu').style.display = 'none'; });

async function startRec(){
    try{
        let s=await navigator.mediaDevices.getUserMedia({audio:true});
        recMime='';
        if(MediaRecorder.isTypeSupported("audio/webm;codecs=opus")) recMime="audio/webm;codecs=opus";
        else if(MediaRecorder.isTypeSupported("audio/mp4")) recMime="audio/mp4";
        
        let opts = recMime ? {mimeType: recMime} : {};
        mediaRec=new MediaRecorder(s, opts); audChunks=[];
        mediaRec.ondataavailable=e=>{ if(e.data.size>0) audChunks.push(e.data); };
        mediaRec.start();
        document.getElementById('txt').style.display='none'; document.getElementById('btn-send').style.display='none'; document.getElementById('btn-att').style.display='none';
        document.getElementById('rec-ui').style.display='flex';
    }catch(e){console.error(e);alertModal('Error','Mic access denied');}
}
function stopRec(send){
    if(!mediaRec || mediaRec.state==='inactive')return;
    mediaRec.onstop=()=>{
        mediaRec.stream.getTracks().forEach(t=>t.stop());
        document.getElementById('txt').style.display='block'; document.getElementById('btn-send').style.display='flex'; document.getElementById('btn-att').style.display='flex';
        document.getElementById('rec-ui').style.display='none';
        if(send && audChunks.length > 0){
            let mime = recMime || mediaRec.mimeType || 'audio/webm';
            let b=new Blob(audChunks,{type:mime}); 
            if(b.size < 1000) { alertModal('Error','Recording too short'); return; }
            if(b.size > 10485760) { alertModal('Error','Audio too large'); return; }
            let r=new FileReader();
            r.onload=async ()=>{ 
                let ts=Math.floor(Date.now()/1000);
                let ld={message:r.result,type:'audio',timestamp:ts}; if(S.type=='dm')ld.to_user=S.id; else if(S.type=='group'||S.type=='channel') ld.group_id=S.id; else if(S.type=='public') ld.group_id=-1; req('send',ld); await store(S.type,S.id,{from_user:ME,message:r.result,type:'audio',timestamp:ts}); 
            };
            r.readAsDataURL(b);
        }
    };
    mediaRec.stop();
}

function playAudio(btn) {
    let player = btn.parentElement.querySelector('audio');
    let bar = btn.parentElement.querySelector('.audio-bar');
    let timeDisplay = btn.parentElement.querySelector('.audio-time');

    if (currentAudio && currentAudio !== player) {
        currentAudio.pause();
        if(currentBtn) {
            currentBtn.innerHTML = '<svg viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg>';
            currentBtn.classList.remove('playing');
        }
        clearInterval(updateInterval);
    }

    if (player.paused) {
        player.play();
        currentAudio = player;
        currentBtn = btn;
        btn.innerHTML = '<svg viewBox="0 0 24 24"><path d="M6 19h4V5H6v14zm8-14v14h4V5h-4z"/></svg>';
        btn.classList.add('playing');
        
        updateInterval = setInterval(() => {
            let pct = (player.currentTime / player.duration) * 100;
            bar.style.width = pct + '%';
            timeDisplay.innerText = formatTime(player.currentTime);
        }, 100);
        
        player.onended = () => {
            btn.innerHTML = '<svg viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg>';
            btn.classList.remove('playing');
            clearInterval(updateInterval);
            bar.style.width = '0%';
            timeDisplay.innerText = formatTime(player.duration);
        };
    } else {
        player.pause();
        btn.innerHTML = '<svg viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg>';
        btn.classList.remove('playing');
        clearInterval(updateInterval);
    }
}
function seekAudio(progress, e) {
    let player = progress.parentElement.querySelector('audio');
    if(!player || !player.duration) return;
    let rect = progress.getBoundingClientRect();
    let pos = (e.clientX - rect.left) / rect.width;
    player.currentTime = pos * player.duration;
    let bar = progress.querySelector('.audio-bar');
    bar.style.width = (pos * 100) + '%';
}
function formatTime(s) {
    if(isNaN(s) || !isFinite(s)) return "0:00";
    let m = Math.floor(s / 60);
    let sec = Math.floor(s % 60);
    return m + ':' + (sec < 10 ? '0' : '') + sec;
}

function handleMainBtn() {
    let txt = document.getElementById('txt').value.trim();
    if (txt) send();
    else startRec();
}

function toggleMainBtn() {
    let hasText = document.getElementById('txt').value.trim().length > 0;
    document.getElementById('icon-mic').style.display = hasText ? 'none' : 'block';
    document.getElementById('icon-send').style.display = hasText ? 'block' : 'none';
}

document.getElementById('txt').oninput=function(){
    this.style.height='auto'; this.style.height=Math.min(this.scrollHeight,150)+'px';
    toggleMainBtn();
    if(S.type=='dm' && Date.now()-lastTyping>2000){ lastTyping=Date.now(); req('typing',{to:S.id}); }
};
document.getElementById('msgs').onscroll = (e)=>{
    let c=e.target;
    let b=document.getElementById('scroll-btn');
    if(c.scrollHeight - c.scrollTop - c.clientHeight > 200) b.style.display='flex'; else b.style.display='none';
};
window.onclick=(e)=>{
    if(!e.target.closest('.notif-btn') && !e.target.closest('.menu-btn'))toggleNotif(false);
    if(!e.target.closest('.menu-btn'))document.getElementById('chat-menu').style.display='none';
    if(!e.target.closest('.ctx-menu') && !e.target.closest('.msg')) document.getElementById('ctx-menu').style.display='none';
    if(!e.target.closest('#att-menu') && !e.target.closest('#btn-att') && document.getElementById('att-menu')) document.getElementById('att-menu').style.display='none';
};
window.oncontextmenu = (e) => {
    if(e.defaultPrevented) return;
    if(e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.isContentEditable) return;
    showContextMenu(e, 'app', null);
};
window.onkeydown = (e) => {
    if(e.key === 'Escape') {
        if(document.getElementById('app-modal').style.display === 'flex') document.getElementById('modal-cancel').click();
        else if(document.getElementById('media-preview').style.display === 'flex') closePreview();
        else if(document.getElementById('main-view').classList.contains('active')) closeChat();
    }
};
window.onfocus=async ()=>{ 
    if(S.type=='dm'&&S.id) {
        let h=await get('dm',S.id); 
        let last=h.filter(x=>x.from_user==S.id).pop(); 
        if(last && last.timestamp>lastRead){ 
            lastRead=last.timestamp; 
            req('send',{to_user:S.id,type:'read',extra:last.timestamp}); 
        }
    }
};

// Mobile Swipe Back
let tSX=0, tSY=0;
const mv = document.getElementById('main-view');
mv.addEventListener('touchstart', e => { tSX=e.changedTouches[0].screenX; tSY=e.changedTouches[0].screenY; }, {passive:true});
mv.addEventListener('touchend', e => {
    if(window.innerWidth > 768) return;
    let tEX=e.changedTouches[0].screenX, tEY=e.changedTouches[0].screenY;
    if(tEX - tSX > 80 && Math.abs(tEY - tSY) < 60 && tSX < 50) closeChat();
}, {passive:true});

function updateWorldClocks() {
    if(S.tab !== 'observatory') return;
    const el = document.getElementById('obs-clocks');
    if(!el) return;
    const zones = [
        { label: 'Washington DC', tz: 'America/New_York', flag: '🇺🇸' },
        { label: 'Tel Aviv', tz: 'Asia/Jerusalem', flag: '🇮🇱' },
        { label: 'Tehran', tz: 'Asia/Tehran', flag: '🇮🇷' }
    ];
    let h = '';
    const now = new Date();
    zones.forEach(z => {
        try {
            const parts = new Intl.DateTimeFormat('en-US', { timeZone: z.tz, hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }).formatToParts(now);
            const timeHtml = parts.map(p => p.type === 'second' ? `<span style="font-size:0.8em;opacity:0.7">${p.value}</span>` : p.value).join('');
            const date = new Intl.DateTimeFormat('en-US', { timeZone: z.tz, month: 'short', day: 'numeric' }).format(now);
            h += `<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                <div style="display:flex;align-items:center;gap:8px;color:var(--text);font-size:0.9rem"><span>${z.flag}</span> ${z.label}</div>
                <div style="text-align:right">
                    <div style="font-size:1rem;font-weight:bold;color:var(--accent);font-family:monospace">${timeHtml}</div>
                    <div style="font-size:0.7rem;color:#888">${date}</div>
                </div>
            </div>`;
        } catch(e) {}
    });
    el.innerHTML = h;
}
setInterval(updateWorldClocks, 1000);

if('serviceWorker' in navigator)navigator.serviceWorker.register('?action=sw');
init().catch(e=>console.error(e));
</script>
</body>
</html>