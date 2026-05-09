<?php
// LIGHTWEIGHT MODE: set to true to disable the Observatory and all external resource loading
$lightweightMode = true;

if ($lightweightMode) {
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data: blob:; media-src 'self' data: blob:; connect-src 'self' data: blob:; frame-ancestors 'none';");
} else {
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob:; media-src 'self' data: blob:; connect-src 'self' data: blob: https://fonts.googleapis.com https://fonts.gstatic.com; frame-ancestors 'none';");
}
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', 1);
if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
    ini_set('session.cookie_secure', 1);
}
session_start();
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// ADMIN CREDENTIALS
$adminUser = '';
$adminPass = ''; // Set these to enable Admin Panel

// -------------------------------------------------------------------------
// 1. CONFIGURATION & DATABASE
// -------------------------------------------------------------------------
$dbFile = __DIR__ . '/chat_mw.db';

// Auto-create or update .htaccess to protect database files
$htaccessFile = __DIR__ . '/.htaccess';
$htaccessRule = "<FilesMatch \"^(chat_mw\.db|chat_mw\.db-shm|chat_mw\.db-wal)$\">\nRequire all denied\n</FilesMatch>";
if (!file_exists($htaccessFile)) {
    @file_put_contents($htaccessFile, $htaccessRule . "\n");
} else {
    $currentHtaccess = @file_get_contents($htaccessFile);
    if ($currentHtaccess !== false && strpos($currentHtaccess, 'chat_mw\.db') === false) {
        @file_put_contents($htaccessFile, "\n# moreweb Messenger DB Protection\n" . $htaccessRule . "\n", FILE_APPEND);
    }
}

try {
    $db = new PDO("sqlite:$dbFile");
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $db->exec("PRAGMA journal_mode=WAL;");
    $db->exec("PRAGMA synchronous = NORMAL;");
    $db->exec("PRAGMA temp_store = MEMORY;");

    // Enable auto-vacuum to automatically free disk space on deletions
    $av = (int)$db->query("PRAGMA auto_vacuum")->fetchColumn();
    if ($av !== 1) {
        $db->exec("PRAGMA auto_vacuum = FULL;");
        try {
            $db->exec("VACUUM;");
        } catch (PDOException $e) {
            $db->exec("PRAGMA auto_vacuum = 0;"); // Revert so it attempts again later
        }
    }

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

    if ($ver < 7) {
        // Custom status, block list, username change support, message pinning column, read receipts table
        $cols = $db->query("PRAGMA table_info(users)")->fetchAll(PDO::FETCH_COLUMN, 1);
        if (!in_array('status_text', $cols)) $db->exec("ALTER TABLE users ADD COLUMN status_text TEXT");

        $db->exec("CREATE TABLE IF NOT EXISTS blocked_users (
            blocker_id INTEGER,
            blocked_id INTEGER,
            PRIMARY KEY (blocker_id, blocked_id)
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS read_receipts (
            message_id INTEGER,
            user_id INTEGER,
            read_at INTEGER,
            PRIMARY KEY (message_id, user_id)
        )");

        $db->exec("PRAGMA user_version = 7");
    }

} catch (PDOException $e) { error_log("DB Error: " . $e->getMessage()); die("A database error occurred. Please check the server logs."); }

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
    echo "const CACHE='mw-v3';self.addEventListener('install',e=>{e.waitUntil(caches.open(CACHE).then(c=>c.addAll(['index.php','?action=icon'])));self.skipWaiting()});self.addEventListener('activate',e=>e.waitUntil(caches.keys().then(ks=>Promise.all(ks.map(k=>{if(k!==CACHE)return caches.delete(k)}))).then(()=>self.clients.claim())));self.addEventListener('fetch',e=>{if(e.request.method!='GET')return;e.respondWith(fetch(e.request).then(r=>{let rc=r.clone();caches.open(CACHE).then(c=>c.put(e.request,rc));return r}).catch(()=>caches.match(e.request).then(r=>r||new Response('',{status:404}))))});self.addEventListener('notificationclick',e=>{e.notification.close();e.waitUntil(clients.matchAll({type:'window',includeUncontrolled:true}).then(cl=>{for(let c of cl){if(c.url&&'focus'in c)return c.focus();}if(clients.openWindow)return clients.openWindow('index.php');}));});";
    exit;
}
if ($action === 'ping') {
    header('Content-Type: application/json');
    echo json_encode(['status'=>'pong', 'time'=>time()]);
    exit;
}

if ($action === 'get_profile') {
    header('Content-Type: application/json');
    $u = $_GET['u'] ?? '';
    $stmt = $db->prepare("SELECT username, avatar, bio, status_text, joined_at, last_seen, public_key FROM users WHERE lower(username) = lower(?)");
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
    if ($lightweightMode) { echo json_encode(['status'=>'disabled']); exit; }
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

    if (!isset($_SERVER['HTTP_X_CSRF_TOKEN']) || !hash_equals($_SESSION['csrf_token'], $_SERVER['HTTP_X_CSRF_TOKEN'])) {
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
        if (strtolower($user) === 'me') { echo json_encode(['status'=>'error','message'=>'Username reserved']); exit; }
        if (!preg_match('/^[a-zA-Z0-9_-]+$/', $user)) { echo json_encode(['status'=>'error','message'=>'Use letters, numbers, -, _ only']); exit; }

        $stmt = $db->prepare("SELECT 1 FROM users WHERE lower(username) = lower(?)");
        $stmt->execute([$user]);
        if ($stmt->fetch()) { echo json_encode(['status'=>'error','message'=>'Username taken']); exit; }

        if (strlen($input['password'] ?? '') < 8) { echo json_encode(['status'=>'error','message'=>'Password must be at least 8 characters']); exit; }
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
        // Rate limit: max 10 login attempts per 10 minutes per IP
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $rateLimitKey = 'login_attempts_' . md5($ip);
        if (!isset($_SESSION[$rateLimitKey])) $_SESSION[$rateLimitKey] = ['count' => 0, 'window_start' => time()];
        $rl = &$_SESSION[$rateLimitKey];
        if (time() - $rl['window_start'] > 600) { $rl['count'] = 0; $rl['window_start'] = time(); }
        $rl['count']++;
        if ($rl['count'] > 10) {
            http_response_code(429);
            echo json_encode(['status' => 'error', 'message' => 'Too many login attempts. Try again later.']);
            exit;
        }
        if (!empty($adminUser) && !empty($adminPass) && ($input['username'] ?? '') === $adminUser && ($input['password'] ?? '') === $adminPass) {
            $rl['count'] = 0;
            session_regenerate_id(true);
            $_SESSION['admin'] = true;
            echo json_encode(['status' => 'success']);
            exit;
        }
        $stmt = $db->prepare("SELECT id, username, password FROM users WHERE lower(username) = lower(?)");
        $stmt->execute([$input['username']]);
        $row = $stmt->fetch();
        if ($row && password_verify($input['password'], $row['password'])) {
            $rl['count'] = 0;
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
        if ($lightweightMode || !isset($_SESSION['uid'])) exit;
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
                // Cleanup orphaned members from groups owned by this user
                $db->prepare("DELETE FROM group_members WHERE group_id IN (SELECT id FROM groups WHERE owner_id = ?)")->execute([$uid]);
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
            if (preg_match('/^(https?:\/\/|data:image\/)/i', $input['avatar'])) {
                $db->prepare("UPDATE users SET avatar = ? WHERE id = ?")->execute([$input['avatar'], $myId]);
            }
        }
        if (!empty($input['new_password'])) {
            if (strlen($input['new_password']) < 8) { echo json_encode(['status'=>'error','message'=>'Password must be at least 8 characters']); exit; }
            $db->prepare("UPDATE users SET password = ? WHERE id = ?")->execute([password_hash($input['new_password'], PASSWORD_DEFAULT), $myId]);
        }
        if (isset($input['bio'])) {
            $db->prepare("UPDATE users SET bio = ? WHERE id = ?")->execute([substr($input['bio'], 0, 200), $myId]);
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
        $ts = round(microtime(true) * 1000);
        $reply = $input['reply_to'] ?? null;
        $extra = $input['extra'] ?? null;
        $type = $input['type'] ?? 'text';
        $msg = $input['message'] ?? '';
        if (!is_string($msg)) { echo json_encode(['status'=>'error','message'=>'Invalid message']); exit; }
        if (strlen($msg) > 15000000) { echo json_encode(['status'=>'error','message'=>'Message too long']); exit; }

        if (isset($input['to_user'])) {
            // Check recipient exists
            $chkUser = $db->prepare("SELECT id FROM users WHERE lower(username) = lower(?)");
            $chkUser->execute([$input['to_user']]);
            if (!$chkUser->fetch() && $input['to_user'] !== $me) {
                echo json_encode(['status'=>'error','message'=>'User not found']); exit;
            }
            // Check if sender is blocked (skip for system message types)
            if (!in_array($type, ['signal', 'wsync', 'read', 'delete', 'edit'])) {
                $blkStmt = $db->prepare("SELECT 1 FROM blocked_users WHERE blocker_id = (SELECT id FROM users WHERE lower(username)=lower(?)) AND blocked_id = ?");
                $blkStmt->execute([$input['to_user'], $myId]);
                if ($blkStmt->fetch()) { echo json_encode(['status'=>'error','message'=>'Blocked']); exit; }
            }
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
        echo json_encode(['status' => 'success', 'timestamp' => $ts]);
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
        $type = 'file';
        if (strpos($mime, 'image') === 0) $type = 'image';
        else if (strpos($mime, 'video') === 0) $type = 'video';
        else if (strpos($mime, 'audio') === 0) $type = 'audio';
        $extra = $_FILES['file']['name'];
        $ts = round(microtime(true) * 1000);
        $reply = $_POST['reply_to'] ?? null;
        
        if (!empty($_POST['to_user'])) {
            // Verify recipient exists
            $chkUser = $db->prepare("SELECT id FROM users WHERE lower(username) = lower(?)");
            $chkUser->execute([$_POST['to_user']]);
            if (!$chkUser->fetch() && $_POST['to_user'] !== $me) {
                echo json_encode(['status'=>'error','message'=>'User not found']); exit;
            }
            // Check if sender is blocked by recipient
            $blkStmt = $db->prepare("SELECT 1 FROM blocked_users WHERE blocker_id = (SELECT id FROM users WHERE lower(username)=lower(?)) AND blocked_id = ?");
            $blkStmt->execute([$_POST['to_user'], $myId]);
            if ($blkStmt->fetch()) { echo json_encode(['status'=>'error','message'=>'Blocked']); exit; }
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
        echo json_encode(['status' => 'success', 'timestamp' => $ts]);
        exit;
    }

    // GROUPS
    if ($action === 'create_group') {
        $type = $input['type'];
        if (!in_array($type, ['public', 'discoverable', 'private'])) { echo json_encode(['status'=>'error','message'=>'Invalid type']); exit; }
        $cat = $input['category'] ?? 'group';
        if (!in_array($cat, ['group', 'channel'])) { echo json_encode(['status'=>'error','message'=>'Invalid category']); exit; }
        $code = ($type === 'public' || $type === 'discoverable') ? rand(100000, 999999) : null;
        $joinEnabled = ($type === 'private') ? 0 : 1;
        
        $groupName = trim($input['name'] ?? '');
        if (strlen($groupName) < 1 || strlen($groupName) > 100) { echo json_encode(['status'=>'error','message'=>'Group name must be 1-100 characters']); exit; }
        try {
            $db->prepare("INSERT INTO groups (name, type, owner_id, join_code, created_at, join_enabled, category) VALUES (?, ?, ?, ?, ?, ?, ?)")
               ->execute([$groupName, $type, $myId, $code, time(), $joinEnabled, $cat]);
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
        usleep(200000); // Mitigation against brute-forcing
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

    // BLOCK USER
    if ($action === 'block_user') {
        $target = $input['username'] ?? '';
        $unblock = $input['unblock'] ?? false;
        $tStmt = $db->prepare("SELECT id FROM users WHERE lower(username) = lower(?)");
        $tStmt->execute([$target]);
        $tRow = $tStmt->fetch();
        if (!$tRow) { echo json_encode(['status'=>'error','message'=>'User not found']); exit; }
        if ($unblock) {
            $db->prepare("DELETE FROM blocked_users WHERE blocker_id = ? AND blocked_id = ?")->execute([$myId, $tRow['id']]);
        } else {
            try { $db->prepare("INSERT INTO blocked_users (blocker_id, blocked_id) VALUES (?, ?)")->execute([$myId, $tRow['id']]); } catch(Exception $e) {}
        }
        echo json_encode(['status'=>'success']); exit;
    }
    if ($action === 'get_blocked') {
        $stmt = $db->prepare("SELECT u.username FROM blocked_users b JOIN users u ON b.blocked_id = u.id WHERE b.blocker_id = ?");
        $stmt->execute([$myId]);
        echo json_encode(['status'=>'success', 'blocked'=>$stmt->fetchAll(PDO::FETCH_COLUMN)]); exit;
    }

    // USERNAME CHANGE
    if ($action === 'change_username') {
        $newUser = trim($input['username'] ?? '');
        if (strlen($newUser) < 2 || strlen($newUser) > 30) { echo json_encode(['status'=>'error','message'=>'Username must be 2-30 characters']); exit; }
        if (!preg_match('/^[a-zA-Z0-9_-]+$/', $newUser)) { echo json_encode(['status'=>'error','message'=>'Use letters, numbers, -, _ only']); exit; }
        if (strtolower($newUser) === 'me') { echo json_encode(['status'=>'error','message'=>'Username reserved']); exit; }
        $chk = $db->prepare("SELECT 1 FROM users WHERE lower(username) = lower(?) AND id != ?");
        $chk->execute([$newUser, $myId]);
        if ($chk->fetch()) { echo json_encode(['status'=>'error','message'=>'Username taken']); exit; }
        $db->prepare("UPDATE users SET username = ? WHERE id = ?")->execute([$newUser, $myId]);
        // Update messages from old username
        $db->prepare("UPDATE messages SET from_user = ? WHERE from_user = ?")->execute([$newUser, $me]);
        $db->prepare("UPDATE messages SET to_user = ? WHERE to_user = ?")->execute([$newUser, $me]);
        session_regenerate_id(true);
        $_SESSION['user'] = $newUser;
        echo json_encode(['status'=>'success', 'username'=>$newUser]); exit;
    }

    // CUSTOM STATUS
    if ($action === 'update_status') {
        $status = substr($input['status'] ?? '', 0, 80);
        $db->prepare("UPDATE users SET status_text = ? WHERE id = ?")->execute([$status, $myId]);
        echo json_encode(['status'=>'success']); exit;
    }

    // PIN MESSAGE (server-side — stores in extra_data for group messages)
    if ($action === 'pin_message') {
        $msgId = (int)($input['message_id'] ?? 0);
        $pin = $input['pin'] ?? true;
        // Only update local; pinning is handled client-side via IndexedDB already
        // This is a no-op on server but kept for future server-side pinning
        echo json_encode(['status'=>'success']); exit;
    }

    // GROUP INVITE LINK (get join_code for sharing) — only members of the group may fetch it
    if ($action === 'get_invite_link') {
        $gid = (int)($input['group_id'] ?? 0);
        $memChk = $db->prepare("SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?");
        $memChk->execute([$gid, $myId]);
        if (!$memChk->fetch()) { echo json_encode(['status'=>'error','message'=>'Not a member']); exit; }
        $stmt = $db->prepare("SELECT join_code FROM groups WHERE id = ?");
        $stmt->execute([$gid]);
        $grp = $stmt->fetch();
        if (!$grp) { echo json_encode(['status'=>'error','message'=>'Group not found']); exit; }
        echo json_encode(['status'=>'success','join_code'=>$grp['join_code']]); exit;
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
            $now_ms = round(microtime(true) * 1000);
            $t24h = $now_ms - 86400000;
            $t7d = $now_ms - 604800000;

            // 1. DMs (group_id IS NULL) -> 24h
            $db->prepare("DELETE FROM messages WHERE group_id IS NULL AND timestamp < ?")->execute([$t24h]);
            // 2. Groups (category='group') -> 24h
            $db->prepare("DELETE FROM messages WHERE group_id IN (SELECT id FROM groups WHERE category = 'group') AND timestamp < ?")->execute([$t24h]);
            // 3. Channels (category='channel') NOT discoverable -> 7 days
            $db->prepare("DELETE FROM messages WHERE group_id IN (SELECT id FROM groups WHERE category = 'channel' AND type != 'discoverable') AND timestamp < ?")->execute([$t7d]);
            // 4. Public Chat (group_id = -1) -> 5 mins (Keep existing ephemeral nature)
            $t5m = $now_ms - 300000;
            $db->prepare("DELETE FROM messages WHERE group_id = -1 AND timestamp < ?")->execute([$t5m]);
        }

        // Self Profile
        $myProfile = $db->prepare("SELECT username, avatar, joined_at, bio, status_text FROM users WHERE id = ?");
        $myProfile->execute([$myId]);

        // ACKs
        if (!empty($input['ack_dms'])) {
            $ids = array_map('intval', (array)$input['ack_dms']);
            if ($ids) {
                $placeholders = implode(',', array_fill(0, count($ids), '?'));
                $params = array_merge($ids, [$me]);
                $db->prepare("DELETE FROM messages WHERE id IN ($placeholders) AND to_user = ?")->execute($params);
            }
        }
        if (!empty($input['group_cursors'])) {
            $stmt = $db->prepare("UPDATE group_members SET last_received_id = ? WHERE group_id = ? AND user_id = ?");
            foreach ($input['group_cursors'] as $gid => $lid) {
                $stmt->execute([(int)$lid, (int)$gid, $myId]);
            }
        }

        // DMs (Fetch)
        $stmt = $db->prepare("SELECT * FROM messages WHERE to_user = ? ORDER BY id ASC LIMIT 200");
        $stmt->execute([$me]);
        $dms = $stmt->fetchAll();

        // Groups
        $groups = $db->prepare("SELECT g.id, g.name, g.type, g.join_code, g.category, g.owner_id, gm.last_received_id FROM groups g JOIN group_members gm ON g.id=gm.group_id WHERE gm.user_id=?");
        $groups->execute([$myId]);
        $myGroups = $groups->fetchAll();
    
        $grpMsgs = [];
        foreach ($myGroups as $g) {
            // For channels: if last_received_id is 0 (new member / late joiner), fetch recent history
            $lastId = (int)$g['last_received_id'];
            if ($lastId === 0) {
                // Fetch recent 50 messages for late joiners
                $stmt = $db->prepare("SELECT * FROM messages WHERE group_id = ? ORDER BY id DESC LIMIT 50");
                $stmt->execute([$g['id']]);
                $msgs = array_reverse($stmt->fetchAll());
            } else {
                $stmt = $db->prepare("SELECT * FROM messages WHERE group_id = ? AND id > ? ORDER BY id ASC");
                $stmt->execute([$g['id'], $lastId]);
                $msgs = $stmt->fetchAll();
            }
            if($msgs) {
                $grpMsgs = array_merge($grpMsgs, $msgs);
            }
        }
    
        // Online Users
        $online = $db->prepare("SELECT username, avatar, last_seen, bio, status_text FROM users WHERE last_seen > ?");
        $online->execute([time()-300]);

        // Typing
        $typing = $db->prepare("SELECT username FROM users WHERE typing_to = ? AND typing_at > ?");
        $typing->execute([$me, time() - 5]);

        // Public Chat
        $lastPub = $input['last_pub'] ?? 0;
        $db->prepare("DELETE FROM messages WHERE group_id = -1 AND timestamp < ?")->execute([round(microtime(true) * 1000) - 300000]);
        $stmt = $db->prepare("SELECT * FROM messages WHERE group_id = -1 AND id > ? ORDER BY id ASC");
        $stmt->execute([$lastPub]);
        $pubMsgs = $stmt->fetchAll();

        echo json_encode(['profile' => $myProfile->fetch(), 'dms' => $dms, 'groups' => $myGroups, 'group_msgs' => $grpMsgs, 'public_msgs' => $pubMsgs, 'online' => $online->fetchAll(), 'typing' => $typing->fetchAll(PDO::FETCH_COLUMN)]);
        exit;
    }
}

if ($action === 'logout') {
    // Invalidate persistent auth token if one was used
    if (isset($_SESSION['uid'])) {
        try {
            $db->prepare("DELETE FROM auth_tokens WHERE user_id = ?")->execute([$_SESSION['uid']]);
        } catch (Exception $e) {}
    }
    session_destroy();
    header("Location: index.php");
    exit;
}

// -------------------------------------------------------------------------
// FRONTEND
// -------------------------------------------------------------------------
$localPoppins = null;
if (file_exists(__DIR__ . '/Poppins-Thin.ttf')) $localPoppins = 'Poppins-Thin.ttf';
elseif (file_exists(__DIR__ . '/fonts/Poppins-Thin.ttf')) $localPoppins = 'fonts/Poppins-Thin.ttf';
?><?php if (isset($_SESSION['admin']) && !empty($adminUser)) { ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Admin Panel - moreweb Messenger</title>
<?php if (!$lightweightMode): ?><link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap" rel="stylesheet"><?php endif; ?>
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
        function esc(t){return t?String(t).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#039;"):""}
        let tbody = document.querySelector('#users-table tbody');
        tbody.innerHTML = '';
        if(!d.users.length) { tbody.innerHTML = '<tr><td colspan="6">No users found</td></tr>'; }
        d.users.forEach(u => {
            let obsBtn = '';
            if(u.observatory_access == 1) obsBtn = `<button class="btn action-btn" style="background:#4caf50;margin-right:5px" onclick="apprObs(${u.id}, 1)">Approve</button><button class="btn btn-danger action-btn" onclick="apprObs(${u.id}, 0)">Deny</button>`;
            else if(u.observatory_access == 2) obsBtn = `<span style="color:#4caf50;margin-right:5px">Active</span><button class="btn btn-danger action-btn" style="padding:2px 6px;font-size:0.7rem" onclick="apprObs(${u.id}, 0)">Revoke</button>`;
            else obsBtn = `<span style="color:#666">None</span>`;

            let tr = document.createElement('tr');
            tr.innerHTML = `<td>${parseInt(u.id)}</td><td></td><td>${esc(new Date(u.joined_at*1000).toLocaleDateString())}</td><td>${esc(new Date(u.last_seen*1000).toLocaleString())}</td><td>${obsBtn}</td><td><button class="btn btn-danger action-btn" onclick="delUser(${parseInt(u.id)})">Delete</button></td>`;
            tr.cells[1].textContent = u.username;
            tbody.appendChild(tr);
        });

        // Groups
        let gtbody = document.querySelector('#groups-table tbody');
        gtbody.innerHTML = '';
        if(!d.groups.length) { gtbody.innerHTML = '<tr><td colspan="6">No groups found</td></tr>'; }
        d.groups.forEach(g => {
            let tr = document.createElement('tr');
            tr.innerHTML = `<td>${parseInt(g.id)}</td><td></td><td></td><td>${parseInt(g.owner_id)}</td><td>${esc(new Date(g.created_at*1000).toLocaleDateString())}</td><td><button class="btn btn-danger action-btn" onclick="delGroup(${parseInt(g.id)})">Delete</button></td>`;
            tr.cells[1].textContent = g.name;
            tr.cells[2].textContent = g.type;
            gtbody.appendChild(tr);
        });
    }
}
async function delUser(id) {
    if(confirm(`Delete user ID ${parseInt(id)}? This cannot be undone.`)) {
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
<?php if (!$lightweightMode): ?>
<link rel="preconnect" href="https://fonts.googleapis.com" crossorigin>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Roboto:wght@100;300;400;500&display=swap" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@100;300;400;700&family=Roboto:wght@100;300;400;500&display=swap" rel="stylesheet">
<?php endif; ?>
<?php if ($localPoppins): ?><style>@font-face{font-family:'Poppins';src:url('<?php echo $localPoppins; ?>') format('truetype');font-weight:100;font-style:normal;}</style><?php endif; ?>
<style>
    :root { --purple: #a855f7; --glow-color: rgba(147, 51, 234, 0.3); }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
        background-color: #000; height: 100vh; overflow: hidden; font-family: 'Poppins', sans-serif;
        display: flex; justify-content: center; align-items: center;
        background-image: 
            radial-gradient(circle at 20% 20%, var(--glow-color) 0%, transparent 40%),
            radial-gradient(circle at 80% 80%, var(--glow-color) 0%, transparent 40%),
            radial-gradient(circle at 50% 50%, rgba(138, 43, 226, 0.15) 0%, transparent 60%);
    }
    #stage { position: relative; z-index: 10; display: flex; justify-content: center; align-items: center; width: 100%; height: 100%; }
    .logo-grid { display: grid; grid-template-columns: repeat(2, 100px); grid-template-rows: repeat(2, 85px); transition: all 0.8s cubic-bezier(0.7, 0, 0.3, 1); }
    .letter { font-size: 6rem; font-weight: 100; color: white; text-align: center; line-height: 1; transition: all 0.7s cubic-bezier(0.7, 0, 0.3, 1); text-shadow: 0 0 30px rgba(168, 85, 247, 0.5); user-select: none; }
    .implode .logo-grid { transform: scale(0); filter: blur(20px); opacity: 0; }
    .implode .letter:nth-child(1) { transform: translate(50px, 42px); }
    .implode .letter:nth-child(2) { transform: translate(-50px, 42px); }
    .implode .letter:nth-child(3) { transform: translate(50px, -42px); }
    .implode .letter:nth-child(4) { transform: translate(-50px, -42px); }
    #auth-card { position: absolute; width: 320px; opacity: 0; transform: scale(1.1); filter: blur(10px); transition: all 1s cubic-bezier(0.2, 1, 0.3, 1); pointer-events: none; }
    .active-stage #auth-card { opacity: 1; transform: scale(1); filter: blur(0); pointer-events: all; transition-delay: 0.4s; }
    .tabs { display: flex; justify-content: flex-start; gap: 25px; margin-bottom: 30px; padding-left: 5px; }
    .tab { color: rgba(255, 255, 255, 0.3); cursor: pointer; font-weight: 100; font-size: 1.1rem; letter-spacing: 2px; transition: 0.3s; border-bottom: 1px solid transparent; padding-bottom: 4px; }
    .tab.active { color: white; border-bottom: 1px solid var(--purple); text-shadow: 0 0 10px var(--purple); }
    input { width: 100%; padding: 15px; background: rgba(255, 255, 255, 0.03); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 8px; color: white; margin-bottom: 15px; font-family: inherit; outline: none; transition: 0.4s; }
    input:focus { background: rgba(168, 85, 247, 0.1); border-color: var(--purple); box-shadow: 0 0 20px rgba(168, 85, 247, 0.2); }
    .btn { width: 100%; padding: 15px; background: white; border: none; border-radius: 8px; font-weight: 400; cursor: pointer; transition: 0.4s; font-family: inherit; }
    .btn:hover { background: var(--purple); color: white; box-shadow: 0 0 30px var(--purple); }
    .btn:disabled { opacity: 0.5; cursor: default; }
    .hide { display: none; }
    .lang-toggle { position: absolute; top: 20px; right: 20px; display: flex; gap: 15px; z-index: 20; }
    .lang-opt { font-weight: 500; color: #9aa0a6; cursor: pointer; transition: 0.2s; font-size: 0.9rem; }
    .lang-opt.active { color: #e8eaed; font-weight: 700; }
    .rtl { direction: rtl; }
    .github-link-login { position: absolute; bottom: 20px; left: 50%; transform: translateX(-50%); color: #a855f7; text-decoration: none; font-size: 0.9rem; display: flex; align-items: center; gap: 8px; z-index: 20; transition: color 0.2s; }
    .github-link-login:hover { color: #d8b4fe; }
    #err { color: #f55; font-size: 0.85rem; margin-bottom: 15px; text-align: left; padding-left: 5px; }
    @keyframes gradientBG { 0% {background-position: 0% 50%;} 50% {background-position: 100% 50%;} 100% {background-position: 0% 50%;} }
    #login-bg { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: 0; background: linear-gradient(-45deg, #0f0518, #3b0764, #6b21a8, #0f0518); background-size: 400% 400%; animation: gradientBG 3s ease infinite; opacity: 0; transition: opacity 1.5s ease-in-out; }
    body.login-process #login-bg { opacity: 1; }
    @keyframes letterAppear { from { opacity: 0; transform: scale(0.9); } to { opacity: 1; transform: scale(1); } }
    .splash-screen { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: #000000; z-index: 9999; display: flex; justify-content: center; align-items: center; pointer-events: none; transition: opacity 0.4s cubic-bezier(0.4, 0, 0.2, 1); }
    .splash-screen .word { display: grid; grid-template-columns: 1fr 1fr; grid-template-rows: 1fr 1fr; gap: 0.15em; color: #FFFFFF; font-family: 'Poppins', sans-serif; font-weight: 100; font-size: clamp(8rem, 15vw, 10rem); line-height: 0.8; text-shadow: 0 0 30px #bf00ff; direction: ltr; opacity: 0; }
    .splash-screen .letter { display: flex; justify-content: center; align-items: center; }
    .splash-screen .m-letter { position: relative; display: inline-flex; justify-content: center; align-items: center; border-radius: 50%; }
    .splash-screen .m-letter::after { content: ''; position: absolute; top: 53%; left: 50%; width: 2.2em; height: 2.2em; border: 2px solid rgba(191, 0, 255, 0.15); border-top: 2px solid #bf00ff; border-radius: 50%; opacity: 0; pointer-events: none; box-shadow: 0 0 20px rgba(191, 0, 255, 0.4); }
    .fonts-loaded .splash-screen .word { opacity: 1; animation: focusOnM 0.7s cubic-bezier(0.76, 0, 0.24, 1) 0.2s forwards; }
    .fonts-loaded .splash-screen .letter-fade { animation: fadeOut 0.7s cubic-bezier(0.76, 0, 0.24, 1) 0.2s forwards; }
    .fonts-loaded .splash-screen .m-letter::after { animation: fadeInRing 0.7s cubic-bezier(0.76, 0, 0.24, 1) 0.2s forwards, spinRing 1.2s linear 0.2s infinite; }
    @keyframes focusOnM { 0% { transform: scale(1) translate(0, 0); } 100% { transform: scale(0.7) translate(25%, 25%); } }
    @keyframes fadeOut { 0% { opacity: 1; } 100% { opacity: 0; } }
    @keyframes fadeInRing { 0% { opacity: 0; } 100% { opacity: 1; } }
    @keyframes spinRing { 0% { transform: translate(-50%, -50%) rotate(0deg); } 100% { transform: translate(-50%, -50%) rotate(360deg); } }

</style>
</head>
<body>

<div class="splash-screen" id="login-splash">
    <div class="word">
        <div class="letter"><span class="m-letter">m</span></div>
        <div class="letter letter-fade">o</div>
        <div class="letter letter-fade">r</div>
        <div class="letter letter-fade">e</div>
    </div>
</div>

<div class="lang-toggle">
    <div class="lang-opt active" id="l-en" onclick="setLang('en')">EN</div>
    <div class="lang-opt" id="l-fa" onclick="setLang('fa')">فا</div>
</div>

<div id="login-bg"></div>
<div id="stage">
    <div class="logo-grid" id="logo">
        <div class="letter">m</div>
        <div class="letter">o</div>
        <div class="letter">r</div>
        <div class="letter">e</div>
    </div>

    <div id="auth-card">
        <div id="ttl" style="font-weight:100;font-size:3rem;color:white;margin-bottom:10px;text-shadow:0 0 20px rgba(168,85,247,0.5)">Welcome</div>
        <div class="tabs">
            <div class="tab active" id="t-login" onclick="switchTab('login')">login</div>
            <div class="tab" id="t-register" onclick="switchTab('register')">register</div>
        </div>
        <div id="err" style="color:#f55;display:none;margin-bottom:15px;font-size:0.875rem"></div>
        <div id="login-form">
            <input type="text" id="li-u" placeholder="username" autocomplete="username">
            <input type="password" id="li-p" placeholder="password" autocomplete="current-password">
            <button class="btn" onclick="sub()">Sign In</button>
        </div>

        <div id="register-form" class="hide">
            <input type="text" id="rg-u" placeholder="username" autocomplete="username">
            <input type="password" id="rg-p" placeholder="password" autocomplete="new-password">
            <button class="btn" onclick="sub()">Register</button>
        </div>
    </div>
</div>

<a href="https://github.com/iWebbIO/php-messenger" target="_blank" class="github-link-login">
    <svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/></svg>
    GitHub Repository
</a>
<script>
const CSRF_TOKEN = "<?php echo $_SESSION['csrf_token']; ?>";
let reg=false;
const TR = {
    en: { ttl: "Welcome", signin: "Sign In", signup: "Sign Up", user: "Username", pass: "Password", no_acc: "Need an account? Create one", has_acc: "Already have an account? Sign In", create: "Create Account", err: "Please fill in all fields", proc: "Processing..." },
    fa: { ttl: "خوش آمدید", signin: "ورود", signup: "ثبت نام", user: "نام کاربری", pass: "رمز عبور", no_acc: "حساب ندارید؟ یکی بسازید", has_acc: "حساب دارید؟ وارد شوید", create: "ایجاد حساب", err: "لطفا تمام فیلدها را پر کنید", proc: "در حال پردازش..." }
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
    document.getElementById('ttl').innerText = t.ttl;
    document.getElementById('t-login').innerText = t.signin.toLowerCase();
    document.getElementById('t-register').innerText = t.signup.toLowerCase();
    document.getElementById('li-u').placeholder = t.user.toLowerCase();
    document.getElementById('rg-u').placeholder = t.user.toLowerCase();
    document.getElementById('li-p').placeholder = t.pass.toLowerCase();
    document.getElementById('rg-p').placeholder = t.pass.toLowerCase();
    document.querySelector('#login-form .btn').innerText = t.signin;
    document.querySelector('#register-form .btn').innerText = t.signup;
}
function switchTab(mode) {
    reg = (mode === 'register');
    const tabs = document.querySelectorAll('.tab');
    const login = document.getElementById('login-form');
    const register = document.getElementById('register-form');
    tabs.forEach(t => t.classList.remove('active'));
    if(!reg) {
        tabs[0].classList.add('active'); login.classList.remove('hide'); register.classList.add('hide');
    } else {
        tabs[1].classList.add('active'); login.classList.add('hide'); register.classList.remove('hide');
    }
    document.getElementById('err').style.display = 'none';
}

async function sub(){
    let u = reg ? document.getElementById('rg-u').value.trim() : document.getElementById('li-u').value.trim();
    let p = reg ? document.getElementById('rg-p').value : document.getElementById('li-p').value;
    if(!u||!p){let e=document.getElementById('err');e.innerText="Please fill in all fields";e.style.display='block';return;}
    document.body.classList.add('login-process');
    let btn = reg ? document.querySelector('#register-form .btn') : document.querySelector('#login-form .btn');
    btn.disabled=true; let oldText = btn.innerText; btn.innerText=TR[curLang].proc;
    try {
        let r=await fetch('?action='+(reg?'register':'login'),{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF_TOKEN},body:JSON.stringify({username:u,password:p})});
        let txt = await r.text();
        let d;
        try { d = JSON.parse(txt); } catch(e) { throw new Error(txt.substring(0, 150) || 'Server Error'); }
        
        if(d.status=='success'){ if(d.token)localStorage.setItem('mw_auth_token',d.token); location.reload(); }
        else{ throw new Error(d.message); }
    } catch(e) {
        document.body.classList.remove('login-process');
        let el=document.getElementById('err');el.innerText=e.message;el.style.display='block';btn.disabled=false;btn.innerText=oldText;
    }
}
if(localStorage.getItem('mw_auth_token')){
    document.body.classList.add('login-process');
    fetch('?action=restore_session',{
        method:'POST', headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF_TOKEN},
        body:JSON.stringify({token:localStorage.getItem('mw_auth_token')})
    })
    .then(r=>r.text())
    .then(t=>{ try { return JSON.parse(t); } catch(e){ throw new Error(); } })
    .then(d=>{
        if(d.status=='success')location.reload(); else throw new Error();
    })
    .catch(()=>{ localStorage.removeItem('mw_auth_token'); document.body.classList.remove('login-process'); });
}
setLang(curLang);
if('serviceWorker' in navigator)navigator.serviceWorker.register('?action=sw');

Promise.all([
    new Promise(resolve => document.addEventListener('DOMContentLoaded', resolve)),
    document.fonts.ready
]).then(() => {
    document.body.classList.add('fonts-loaded');
    const splash = document.getElementById('login-splash');
    if (splash) {
        const word = splash.querySelector('.word');
        word.addEventListener('animationend', (e) => {
            if (e.animationName === 'focusOnM') {
                setTimeout(() => {
                    splash.style.opacity = '0';
                    setTimeout(() => { splash.remove(); }, 400);
                }, 250); 
            }
        });
    }
});
window.addEventListener('load', () => {
    const stage = document.getElementById('stage');
    setTimeout(() => {
        stage.classList.add('implode');
        setTimeout(() => {
            stage.classList.add('active-stage');
            // Auto-focus first input
            document.getElementById('li-u').focus();
        }, 200);
    }, 1500);
});
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
<?php if (!$lightweightMode): ?><link href="https://fonts.googleapis.com/css2?family=Poppins:wght@100;300;400;700&display=swap" rel="stylesheet"><?php endif; ?>
<?php if ($localPoppins): ?><style>@font-face{font-family:'Poppins';src:url('<?php echo $localPoppins; ?>') format('truetype');font-weight:100;font-style:normal;}</style><?php endif; ?>
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

    .list-item, .msg { content-visibility: auto; contain-intrinsic-size: 0 50px; }

    .e2ee-on { color: var(--accent); }
    * { -webkit-tap-highlight-color: transparent; }
    body { margin:0; font-family:'Calibri', sans-serif; background:var(--bg); color:var(--text); height:100vh; height:calc(var(--vh, 1vh) * 100); display:flex; overflow:hidden; overscroll-behavior-y: none; }
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

    .nav-panel { width:clamp(280px, 30vw, 400px); background:var(--panel); border-right:1px solid var(--border); display:flex; flex-direction:column; min-height:0; }
    .nav-panel.full-width { width: auto; flex: 1; border-right: none; }
    .panel-header { padding:20px; font-weight:bold; font-size:1.2rem; border-bottom:1px solid var(--border); display:flex; justify-content:space-between; align-items:center; }
    .list-area { flex:1; overflow-y:auto; overscroll-behavior-y: contain; }
    .list-item { padding:15px; border-bottom:1px solid var(--border); display:flex; align-items:center; cursor:pointer; transition:0.2s; position:relative; user-select:none; }
    @media (hover: hover) { .list-item:hover { background:rgba(255,255,255,0.1); } }
    .list-item:active { background:rgba(255,255,255,0.05); }
    .list-item { contain: layout; }
    .list-item.active { background:rgba(255,255,255,0.15); border-left:4px solid var(--accent); padding-left:11px; }
    @media (min-width: 851px) {
        .list-item[data-key="global"].active {
            border: 2px solid #ffeb3b;
            border-radius: 10px;
            padding-left: 15px;
            z-index: 5;
        }
    }
    .avatar { width:40px; height:40px; border-radius:50%; background:#444; margin-right:12px; display:flex; align-items:center; justify-content:center; font-weight:bold; background-size:cover; flex-shrink:0; }
    
    .main-view { flex:1; display:flex; flex-direction:column; background:var(--bg); background-image:radial-gradient(var(--pattern) 1px, transparent 1px); background-size:20px 20px; position:relative; min-height:0; min-width:0; }
    .main-view { flex:1; display:flex; flex-direction:column; background:var(--bg); background-image:radial-gradient(var(--pattern) 1px, transparent 1px); background-size:20px 20px; position:relative; min-height:0; min-width:0; will-change: transform; }
    .chat-header { height:60px; background:var(--panel); border-bottom:1px solid var(--border); display:flex; align-items:center; justify-content:space-between; padding:0 20px; flex-shrink: 0; z-index: 100; position: relative; }
    .header-actions { display:flex; gap:15px; position:relative; }
    .chat-info-clickable { cursor: pointer; }
    
    .notif-btn { position:relative; cursor:pointer; color:var(--text); opacity:0.8; }
    .notif-badge { position:absolute; top:-5px; right:-5px; background:#f44; color:#fff; font-size:0.6rem; padding:1px 4px; border-radius:8px; display:none; }
    .notif-dropdown { position:absolute; top:40px; right:0; width:250px; background:var(--panel); border:1px solid var(--border); border-radius:8px; display:none; z-index:100; box-shadow:0 5px 15px rgba(0,0,0,0.5); overflow:hidden; }
    .notif-item { padding:12px; border-bottom:1px solid var(--border); font-size:0.85rem; cursor:pointer; color:var(--text); }
    .notif-item:hover { background:var(--hover-overlay); }

    .menu-btn { cursor:pointer; color:var(--text); opacity:0.8; position:relative; }
    .menu-dropdown { position:absolute; top:35px; right:0; background:var(--panel); border:1px solid var(--border); border-radius:8px; display:none; z-index:200; width:160px; box-shadow:0 5px 15px rgba(0,0,0,0.5); }
    .menu-item { padding:12px; border-bottom:1px solid var(--border); font-size:0.9rem; cursor:pointer; display:block; color:var(--text); }
    .menu-item:hover { background:rgba(255,255,255,0.1); }
    .red-text { color: #ff5555; }

    .messages { flex:1; overflow-y:auto; padding:20px; display:flex; flex-direction:column; gap:5px; overscroll-behavior-y: contain; }
    .msg { max-width:65%; padding:8px 12px; border-radius:8px; font-size:0.95rem; line-height:1.4; position:relative; word-wrap:break-word; white-space: pre-wrap; word-break: break-word; overflow-wrap: anywhere; }
    .msg { contain: layout; }
    .msg.in { align-self:flex-start; background:var(--msg-in); border-top-left-radius:0; border:1px solid transparent; }
    .msg.out { align-self:flex-end; background:var(--msg-out); border-top-right-radius:0; }
    .msg img { max-width:100%; border-radius:4px; margin-top:5px; cursor:pointer; }
    /* Multi-image grid layout (Telegram-style) */
    .media-grid { display:grid; gap:2px; border-radius:8px; overflow:hidden; margin-top:4px; max-width:280px; }
    .media-grid.count-1 { grid-template-columns:1fr; }
    .media-grid.count-2 { grid-template-columns:1fr 1fr; }
    .media-grid.count-3 { grid-template-columns:1fr 1fr; }
    .media-grid.count-3 .media-grid-item:first-child { grid-column:span 2; aspect-ratio:2/1; }
    .media-grid.count-4 { grid-template-columns:1fr 1fr; }
    .media-grid.count-5up { grid-template-columns:1fr 1fr; }
    .media-grid-item { position:relative; overflow:hidden; aspect-ratio:1; }
    .media-grid-item img { width:100%; height:100%; object-fit:cover; cursor:pointer; display:block; }
    .media-grid-more { position:absolute; inset:0; background:rgba(0,0,0,0.65); display:flex; align-items:center; justify-content:center; color:#fff; font-size:1.6rem; font-weight:700; cursor:pointer; }
    /* Multi-attach preview bar */
    .multi-attach-bar { display:flex; flex-direction:column; gap:4px; padding:8px 12px; border-top:1px solid var(--border); background:var(--panel); z-index:10; }
    #multi-attach-scroll::-webkit-scrollbar { display:none; }
    .multi-attach-thumb { position:relative; flex-shrink:0; width:68px; height:68px; border-radius:8px; overflow:hidden; border:2px solid var(--border); }
    .multi-attach-thumb img { width:100%; height:100%; object-fit:cover; display:block; }
    .multi-attach-thumb .rm-btn { position:absolute; top:2px; right:2px; width:18px; height:18px; background:rgba(0,0,0,0.75); color:#fff; border:none; border-radius:50%; font-size:13px; cursor:pointer; display:flex; align-items:center; justify-content:center; padding:0; line-height:1; }
    .multi-attach-count { font-size:0.75rem; color:var(--text-muted,#aaa); white-space:nowrap; flex-shrink:0; }
    .file-att { background:rgba(0,0,0,0.2); padding:10px; border-radius:5px; display:flex; align-items:center; gap:10px; cursor:pointer; border:1px solid rgba(255,255,255,0.1); margin-top:5px; }
    .file-att:hover { background:rgba(0,0,0,0.3); }
    .msg-sender { font-size:0.75rem; font-weight:bold; color:var(--accent); margin-bottom:4px; cursor:pointer; }
    .msg-meta { font-size:0.7rem; color:rgba(255,255,255,0.5); text-align:right; margin-top:2px; }
    .msg.msg-sticker { background: transparent !important; border: none; padding: 0; box-shadow: none; }
    .msg.msg-sticker .msg-meta { position: absolute; bottom: 8px; right: 8px; background: rgba(0,0,0,0.5); padding: 2px 8px; border-radius: 12px; color: #fff; pointer-events: none; }
    .msg.msg-sticker .msg-sender { margin-left: 5px; margin-bottom: 2px; text-shadow: 0 1px 2px rgba(0,0,0,0.8); }
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
    .input-wrapper { flex:1; position:relative; min-width:0; }
    .reply-ctx { background:#2a2a2a; padding:6px 10px; border-radius:5px 5px 0 0; font-size:0.8rem; color:#aaa; display:none; justify-content:space-between; align-items:center; }
    input[type=text] { width:100%; padding:12px; border-radius:20px; border:none; background:var(--input-bg); color:var(--text); outline:none; box-sizing:border-box; }
    #txt { width:100%; padding:10px 12px; border-radius:20px; border:none; background:var(--input-bg); color:var(--text); outline:none; box-sizing:border-box; resize:none; height:40px; font-family:inherit; overflow-y:hidden; line-height:1.4; display:block; }
    
    #selection-bar { display:none; width:100%; height:100%; position:absolute; top:0; left:0; background:var(--panel); z-index:101; align-items:center; padding:0 20px; box-sizing:border-box; }
    .msg { user-select: none; -webkit-user-select: none; }
    .msg.selected { user-select: text; -webkit-user-select: text; background: rgba(168, 85, 247, 0.2) !important; border: 1px solid var(--accent); }
    .msg-menu-icon { position: absolute; top: 2px; width: 24px; height: 24px; display: flex; align-items: center; justify-content: center; cursor: pointer; color: var(--text); opacity: 0; transition: 0.2s; border-radius: 50%; font-weight: bold; font-size: 1.1rem; user-select: none; }
    .msg:hover .msg-menu-icon { opacity: 0.5; }
    .msg-menu-icon:hover { opacity: 1 !important; background: var(--hover-overlay); }
    .msg.selected .msg-menu-icon { opacity: 0 !important; pointer-events: none; }
    
    /* Position the 3-dots outside the message bubble */
    .msg.in .msg-menu-icon { right: -28px; }
    .msg.out .msg-menu-icon { left: -28px; }
    
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
    .modal-body { color:#ccc; font-size:0.9rem; margin-bottom:15px; overflow-wrap: anywhere; }
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
    .active-reaction { background: rgba(168, 85, 247, 0.3); border: 1px solid var(--accent); }
    .user-popup { position: fixed; z-index: 2000; background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 20px; box-shadow: 0 5px 20px rgba(0,0,0,0.5); min-width: 200px; display:none; flex-direction:column; gap:10px; }
    @media (max-width: 850px) {
        .user-popup { bottom: 0; left: 0; width: 100%; border-radius: 16px 16px 0 0; border: none; border-top: 1px solid var(--border); animation: slideUp 0.2s; box-sizing: border-box; }
    }
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
    .lightbox { position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.9); z-index:2000; display:none; align-items:center; justify-content:center; flex-direction:column; backdrop-filter:blur(5px); overflow:hidden; }
    .lightbox img { max-width:100%; max-height:90%; object-fit:contain; box-shadow:0 0 20px rgba(0,0,0,0.5); transition: transform 0.1s ease-out; cursor: grab; }
    .lightbox img:active { cursor: grabbing; }
    .lightbox-controls { position:absolute; top:15px; right:15px; display:flex; gap:15px; z-index:2001; }
    .lb-btn { width:40px; height:40px; background:rgba(255,255,255,0.2); border-radius:50%; display:flex; align-items:center; justify-content:center; color:#fff; cursor:pointer; backdrop-filter:blur(10px); transition:0.2s; }
    .lb-btn:hover { background:rgba(255,255,255,0.3); }
    @media (max-width: 850px) {
        .lightbox { background:#000; backdrop-filter:none; }
        .lightbox img { max-width:100%; max-height:100%; }
    }
    
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
    
    /* Emoji Drawer / Sidebar */
    .emoji-drawer { background: var(--panel); display: none; flex-direction: column; z-index: 90; flex-shrink: 0; }
    .emoji-tabs { display: flex; border-bottom: 1px solid var(--border); background: rgba(0,0,0,0.1); }
    .emoji-tab { flex: 1; padding: 12px; text-align: center; cursor: pointer; color: #888; transition: 0.2s; font-size: 0.9rem; font-weight: 500; }
    .emoji-tab:hover { background: rgba(255,255,255,0.05); }
    .emoji-tab.active { color: var(--accent); border-bottom: 2px solid var(--accent); background: rgba(255,255,255,0.05); }
    .emoji-content { flex: 1; overflow-y: auto; padding: 10px; display: grid; gap: 5px; align-content: start; }
    .emoji-grid { grid-template-columns: repeat(auto-fill, minmax(36px, 1fr)); }
    .emoji-item { font-size: 1.6rem; cursor: pointer; text-align: center; padding: 5px; border-radius: 6px; transition: transform 0.1s; user-select: none; }
    .emoji-item:hover { background: rgba(255,255,255,0.1); transform: scale(1.2); }
    .sticker-grid { grid-template-columns: repeat(auto-fill, minmax(80px, 1fr)); gap: 10px; }
    .sticker-item { width: 100%; aspect-ratio: 1; object-fit: contain; cursor: pointer; transition: transform 0.1s; }
    .sticker-item:hover { transform: scale(1.05); }
    .sticker-add-btn { display:flex; align-items:center; justify-content:center; background:rgba(255,255,255,0.1); border-radius:8px; cursor:pointer; font-size:2rem; color:#888; }
    .gif-grid { grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 8px; }
    .gif-item { width: 100%; height: 100px; object-fit: cover; border-radius: 6px; cursor: pointer; }
    .emoji-search { padding: 8px; background: var(--bg); border: 1px solid var(--border); color: var(--text); width: 100%; box-sizing: border-box; border-radius: 4px; margin-bottom: 10px; }

    @media (min-width: 851px) {
        .main-view { flex-direction: row; }
        #chat-view { width: auto !important; flex: 1; }
        .emoji-drawer { position: absolute; bottom: 80px; left: 20px; width: 320px; height: 400px; border-radius: 8px; box-shadow: 0 5px 20px rgba(0,0,0,0.5); border: 1px solid var(--border); animation: fadeUp 0.1s ease-out; z-index: 100; }
        @keyframes slideLeft { from { width: 0; opacity: 0; } to { width: 300px; opacity: 1; } }
        @keyframes fadeUp { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
    }
    @media (max-width: 850px) {
        .emoji-drawer {
            position: relative;
            width: 100%;
            height: 280px;
            border-top: 1px solid var(--border);
            animation: slideUp 0.2s ease-out;
        }
    }

    @keyframes sequentialReplace { 0%, 100% { opacity: 0; transform: translateX(-50%) scale(0.95); } 15% { opacity: 1; transform: translateX(-50%) scale(1); } 30% { opacity: 1; transform: translateX(-50%) scale(1); } 45% { opacity: 0; transform: translateX(-50%) scale(0.95); } }
    @keyframes pulse { 0%, 100% { transform: scale(1); opacity: 1; } 50% { transform: scale(1.3); opacity: 0.7; } }

    @media (max-width: 850px) {
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
        
        .back-btn { display: flex; align-items: center; justify-content: center; margin-right: 5px; font-size: 1.5rem; padding: 10px; }
        .list-item { padding: 20px 15px; }
        .avatar { width: 45px; height: 45px; }
        .btn-icon svg { width: 28px; height: 28px; }
        input, textarea { font-size: 16px !important; }
        .msg { max-width: 85%; }
        .messages { padding: 10px; }
        .desktop-only { display: none !important; }
        .mobile-only { display: block !important; }
        .msg-menu-icon { opacity: 0.6; }
    }
    @media (min-width: 851px) { .back-btn { display:none; } .mobile-only { display: none !important; } }

    /* Splash Screen Main App */
    .splash-screen { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: #000000; z-index: 9999; display: flex; justify-content: center; align-items: center; pointer-events: none; transition: opacity 0.4s cubic-bezier(0.4, 0, 0.2, 1); }
    .splash-screen .word { display: grid; grid-template-columns: 1fr 1fr; grid-template-rows: 1fr 1fr; gap: 0.15em; color: #FFFFFF; font-family: 'Poppins', sans-serif; font-weight: 100; font-size: clamp(8rem, 15vw, 10rem); line-height: 0.8; text-shadow: 0 0 30px #bf00ff; direction: ltr; opacity: 0; }
    .splash-screen .letter { display: flex; justify-content: center; align-items: center; }
    .splash-screen .m-letter { position: relative; display: inline-flex; justify-content: center; align-items: center; border-radius: 50%; }
    .splash-screen .m-letter::after { content: ''; position: absolute; top: 53%; left: 50%; width: 2.2em; height: 2.2em; border: 2px solid rgba(191, 0, 255, 0.15); border-top: 2px solid #bf00ff; border-radius: 50%; opacity: 0; pointer-events: none; box-shadow: 0 0 20px rgba(191, 0, 255, 0.4); }
    .fonts-loaded .splash-screen .word { opacity: 1; animation: focusOnM 0.7s cubic-bezier(0.76, 0, 0.24, 1) 0.2s forwards; }
    .fonts-loaded .splash-screen .letter-fade { animation: fadeOut 0.7s cubic-bezier(0.76, 0, 0.24, 1) 0.2s forwards; }
    .fonts-loaded .splash-screen .m-letter::after { animation: fadeInRing 0.7s cubic-bezier(0.76, 0, 0.24, 1) 0.2s forwards, spinRing 1.2s linear 0.2s infinite; }
    @keyframes focusOnM { 0% { transform: scale(1) translate(0, 0); } 100% { transform: scale(0.7) translate(25%, 25%); } }
    @keyframes fadeOut { 0% { opacity: 1; } 100% { opacity: 0; } }
    @keyframes fadeInRing { 0% { opacity: 0; } 100% { opacity: 1; } }
    @keyframes spinRing { 0% { transform: translate(-50%, -50%) rotate(0deg); } 100% { transform: translate(-50%, -50%) rotate(360deg); } }
    @keyframes letterAppear { from { opacity: 0; transform: scale(0.9); } to { opacity: 1; transform: scale(1); } }

    /* Connection Indicator */
    .conn-indicator { padding: 6px 0 0 0; height: 22px; display: flex; align-items: center; justify-content: center; transition: 0.3s; flex-shrink: 0; cursor: pointer; }
    .conn-more { font-family: 'Poppins', sans-serif; font-weight: 100; font-size: 1.4rem; letter-spacing: 0.1em; color: #fff; text-shadow: 0 0 15px #bf00ff; display: none; gap: 5px; line-height: 1; direction: ltr; user-select: none; }
    .conn-more span { display: inline-block; animation: letterAppear 0.5s ease-out forwards; }
    .conn-text { font-size: 0.75rem; color: #888; font-style: italic; display: block; font-family: 'Roboto', sans-serif; font-weight: 300; letter-spacing: 0.05em; }
    .conn-dots::after { content: '.'; animation: dots 1.5s infinite; display: inline-block; width: 1.5em; text-align: left; }
    .status-connected .conn-more { display: flex; }
    .status-connected .conn-text { display: none; }
    .light-mode .conn-more { color: #333; text-shadow: 0 0 10px rgba(168, 85, 247, 0.5); }
    @keyframes dots { 0% { content: '.'; } 33% { content: '..'; } 66% { content: '...'; } }

    @media (pointer: coarse) {
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        .list-item { padding: 18px 15px; }
        .msg { padding: 10px 14px; font-size: 1rem; }
        .input-area { padding: 20px 15px; padding-bottom: calc(20px + env(safe-area-inset-bottom)); }
    }

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

    /* Message search highlight */
    .msg-highlight { background: rgba(255,235,59,0.3) !important; outline: 2px solid #ffeb3b; }
    #msg-search-bar.active { display: flex !important; }

    /* Call Overlay */
    #call-overlay { position:fixed; top:0; left:0; width:100%; height:100%; background:#000; z-index:5000; display:none; flex-direction:column; align-items:center; justify-content:center; }
    #remote-video { width:100%; height:100%; object-fit:cover; }
    #local-video { position:absolute; bottom:20px; right:20px; width:100px; height:133px; background:#333; border:1px solid #fff; object-fit:cover; z-index:5001; border-radius:8px; transition:0.3s; }
    #local-video.enlarged { width:100%; height:100%; bottom:0; right:0; border:none; z-index:5000; }
    .call-controls { position:absolute; bottom:30px; left:50%; transform:translateX(-50%); display:flex; gap:20px; z-index:5002; }
    .btn-call-act { width:50px; height:50px; border-radius:50%; border:none; color:#fff; display:flex; align-items:center; justify-content:center; cursor:pointer; font-size:1.2rem; box-shadow:0 4px 10px rgba(0,0,0,0.5); transition:0.2s; }
    .btn-call-act:active { transform:scale(0.95); }
    .btn-end { background:#f44; } .btn-ans { background:#4caf50; } .btn-mic { background:rgba(255,255,255,0.2); backdrop-filter:blur(5px); }
    .call-status { position:absolute; top:40px; left:0; width:100%; text-align:center; color:#fff; text-shadow:0 2px 4px rgba(0,0,0,0.8); z-index:5002; font-size:1.2rem; }
    .call-avatar { width:100px; height:100px; border-radius:50%; background:#444; margin-bottom:20px; background-size:cover; display:flex; align-items:center; justify-content:center; font-size:2.5rem; color:#fff; box-shadow:0 5px 15px rgba(0,0,0,0.5); }
    #incoming-ui { display:none; flex-direction:column; align-items:center; z-index:5003; }
    #in-call-ui { display:none; width:100%; height:100%; }
</style>
</head>
<body>

<div id="app-splash" class="splash-screen">
    <div class="word">
        <div class="letter"><span class="m-letter">m</span></div>
        <div class="letter letter-fade">o</div>
        <div class="letter letter-fade">r</div>
        <div class="letter letter-fade">e</div>
    </div>
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
    <div class="preview-content">
        <img id="preview-img" src="" style="display:none">
        <video id="preview-vid" style="display:none;max-width:100%;max-height:100%" controls></video>
        <audio id="preview-aud" style="display:none" controls></audio>
    </div>
    <div class="preview-footer">
        <div style="color:#aaa;font-size:0.8rem" id="preview-info"></div>
        <button class="btn-primary" onclick="sendPreview()">Send</button>
    </div>
</div>

<!-- LIGHTBOX -->
<div id="lightbox" class="lightbox" onclick="closeLightbox()">
    <div class="lightbox-controls" onclick="event.stopPropagation()">
        <div class="lb-btn" onclick="shareImage()" title="Share"><svg viewBox="0 0 24 24" width="24" fill="currentColor"><path d="M18 16.08c-.76 0-1.44.3-1.96.77L8.91 12.7c.05-.23.09-.46.09-.7s-.04-.47-.09-.7l7.05-4.11c.54.5 1.25.81 2.04.81 1.66 0 3-1.34 3-3s-1.34-3-3-3-3 1.34-3 3c0 .24.04.47.09.7L8.04 9.81C7.5 9.31 6.79 9 6 9c-1.66 0-3 1.34-3 3s1.34 3 3 3c.79 0 1.5-.31 2.04-.81l7.12 4.16c-.05.21-.08.43-.08.65 0 1.61 1.31 2.92 2.92 2.92 1.61 0 2.92-1.31 2.92-2.92s-1.31-2.92-2.92-2.92z"/></svg></div>
        <div class="lb-btn" onclick="downloadImage()" title="Download"><svg viewBox="0 0 24 24" width="24" fill="currentColor"><path d="M19 9h-4V3H9v6H5l7 7 7-7zM5 18v2h14v-2H5z"/></svg></div>
        <div class="lb-btn" onclick="closeLightbox()" title="Close">&times;</div>
    </div>
    <img id="lb-img" src="" onclick="event.stopPropagation()">
</div>

<!-- CALL OVERLAY -->
<div id="call-overlay">
    <div id="incoming-ui">
        <div class="call-avatar" id="call-av"></div>
        <div style="font-size:1.5rem;font-weight:bold;margin-bottom:5px" id="call-name">User</div>
        <div style="color:#ccc;margin-bottom:40px" data-i18n="incoming_call">Incoming Video Call...</div>
        <div style="display:flex;gap:40px">
            <button class="btn-call-act btn-end" onclick="rejectCall()"><svg viewBox="0 0 24 24" width="24" fill="currentColor"><path d="M12 9c-1.6 0-3.15.25-4.6.72v3.1c0 .39-.23.74-.56.9-.98.49-1.87 1.12-2.66 1.85-.18.18-.43.28-.7.28-.28 0-.53-.11-.71-.29L.29 13.08c-.18-.17-.29-.42-.29-.7 0-.28.11-.53.29-.71C3.34 8.36 7.46 6 12 6s8.66 2.36 11.71 5.67c.18.18.29.43.29.71 0 .28-.11.53-.29.71l-2.48 2.48c-.18.18-.43.29-.71.29-.27 0-.52-.11-.7-.28-.79-.74-1.69-1.36-2.67-1.85-.33-.16-.56-.5-.56-.9v-3.1C15.15 9.25 13.6 9 12 9z"/></svg></button>
            <button class="btn-call-act btn-ans" onclick="answerCall()"><svg viewBox="0 0 24 24" width="24" fill="currentColor"><path d="M20 15.5c-1.25 0-2.45-.2-3.57-.57-.35-.11-.74-.03-1.02.24l-2.2 2.2c-2.83-1.44-5.15-3.75-6.59-6.59l2.2-2.21c.28-.26.36-.65.25-1C8.7 6.45 8.5 5.25 8.5 4c0-.55-.45-1-1-1H4c-.55 0-1 .45-1 1 0 9.39 7.61 17 17 17 .55 0 1-.45 1-1v-3.5c0-.55-.45-1-1-1zM19 12h2c0-4.97-4.03-9-9-9v2c3.87 0 7 3.13 7 7zm-4 0h2c0-2.76-2.24-5-5-5v2c1.66 0 3 1.34 3 3z"/></svg></button>
        </div>
    </div>
    <div id="in-call-ui">
        <video id="remote-video" autoplay playsinline></video>
        <video id="local-video" autoplay playsinline muted onclick="this.classList.toggle('enlarged')"></video>
        <div class="call-status" id="call-status">Connecting...</div>
        <div class="call-controls">
            <button class="btn-call-act btn-mic" onclick="toggleMic(this)"><svg viewBox="0 0 24 24" width="24" fill="currentColor"><path d="M12 14c1.66 0 3-1.34 3-3V5c0-1.66-1.34-3-3-3S9 3.34 9 5v6c0 1.66 1.34 3 3 3z"/><path d="M17 11c0 2.76-2.24 5-5 5s-5-2.24-5-5H5c0 3.53 2.61 6.43 6 6.92V21h2v-3.08c3.39-.49 6-3.39 6-6.92h-2z"/></svg></button>
            <button class="btn-call-act btn-end" onclick="endCall()"><svg viewBox="0 0 24 24" width="24" fill="currentColor"><path d="M12 9c-1.6 0-3.15.25-4.6.72v3.1c0 .39-.23.74-.56.9-.98.49-1.87 1.12-2.66 1.85-.18.18-.43.28-.7.28-.28 0-.53-.11-.71-.29L.29 13.08c-.18-.17-.29-.42-.29-.7 0-.28.11-.53.29-.71C3.34 8.36 7.46 6 12 6s8.66 2.36 11.71 5.67c.18.18.29.43.29.71 0 .28-.11.53-.29.71l-2.48 2.48c-.18.18-.43.29-.71.29-.27 0-.52-.11-.7-.28-.79-.74-1.69-1.36-2.67-1.85-.33-.16-.56-.5-.56-.9v-3.1C15.15 9.25 13.6 9 12 9z"/></svg></button>
            <button class="btn-call-act btn-mic" onclick="toggleCam(this)"><svg viewBox="0 0 24 24" width="24" fill="currentColor"><path d="M15 8v8H5V8h10m1-2H4c-.55 0-1 .45-1 1v10c0 .55.45 1 1 1h12c.55 0 1-.45 1-1v-3.5l4 4v-11l-4 4V7c0-.55-.45-1-1-1z"/></svg></button>
        </div>
    </div>
</div>

<!-- MODAL SYSTEM -->
<div id="app-modal" class="modal-overlay">
    <div class="modal-box">
        <h3 id="modal-title" class="modal-title"></h3>
        <div id="modal-body" class="modal-body"></div>
        <input id="modal-input" type="text" class="form-input" style="display:none" autocomplete="off">
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
<div id="user-popup" class="user-popup"></div>

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
        <div class="rail-btn" id="nav-observatory" onclick="switchTab('observatory')" <?php if ($lightweightMode) echo 'style="display:none"'; ?>>
            <svg viewBox="0 0 24 24"><path d="M19.9,1.622a1,1,0,0,0-1.365-.52L1.562,9.388a1,1,0,0,0-.488,1.276L2.59,14.378A1,1,0,0,0,3.516,15a1.043,1.043,0,0,0,.24-.029L11,13.179v4.407L7.293,21.293a1,1,0,1,0,1.414,1.414L11,20.414V22a1,1,0,0,0,2,0V20.414l2.293,2.293a1,1,0,0,0,1.414-1.414L13,17.586v-4.9L22.24,10.4a1,1,0,0,0,.686-1.348ZM4.115,12.821l-.836-2.047L18.447,3.368l2.191,5.367Z"/></svg>
        </div>
        
        <div style="flex:1" class="rail-spacer"></div>
        <div class="rail-btn desktop-only" id="nav-about" onclick="switchTab('about')">
            <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>
        </div>
        <div class="rail-btn" id="nav-settings" onclick="switchTab('settings')">
            <svg viewBox="0 0 24 24"><path d="M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58a.49.49 0 0 0 .12-.61l-1.92-3.32a.488.488 0 0 0-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54a.484.484 0 0 0-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L3.16 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.09.63-.09.94s.02.64.07.94l-2.03 1.58a.49.49 0 0 0-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z"/></svg>
        </div>
        <div class="rail-btn desktop-only" onclick="if(confirm('Logout?')){clearLocalStorageOnLogout();location.href='?action=logout'}" title="Logout">
            <svg viewBox="0 0 24 24"><path d="M10.09 15.59L11.5 17l5-5-5-5-1.41 1.41L12.67 11H3v2h9.67l-2.58 2.59zM19 3H5c-1.11 0-2 .9-2 2v4h2V5h14v14H5v-4H3v4c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2z"/></svg>
        </div>
    </div>

    <!-- LIST PANEL -->
    <div class="nav-panel" id="nav-panel">
        <div id="conn-indicator" class="conn-indicator" onclick="showNetworkStatus()">
            <div class="conn-more"><span>m</span><span>o</span><span>r</span><span>e</span></div>
            <div class="conn-text">Connecting<span class="conn-dots"></span></div>
        </div>
        <div id="tab-chats" class="tab-content">
            <div style="padding:10px 15px 5px 15px"><input type="text" id="chat-search" class="form-input" placeholder="Search chats..." onkeyup="renderLists()" style="margin:0;padding:10px 15px;border-radius:20px" autocomplete="off"></div>
            <div style="padding:10px 15px 5px 15px"><input type="text" id="chat-search" class="form-input" placeholder="Search chats..." oninput="debouncedRender()" style="margin:0;padding:10px 15px;border-radius:20px" autocomplete="off"></div>
            <div class="panel-header" style="padding-top:5px;padding-bottom:5px;border-bottom:none"><span data-i18n="tab_chats">Chats</span> <div class="btn-icon" onclick="promptChat()">+</div></div>
            <div class="list-area" id="list-chats">
                <div class="tab-loader">
                    <div class="rail-letters"><span>m</span><span>o</span><span>R</span><span>e</span></div>
                    <div class="rail-dot"></div>
                </div>
            </div>
        </div>
        <div id="tab-groups" class="tab-content" style="display:none">
            <div style="padding:10px 15px 5px 15px"><input type="text" id="group-search" class="form-input" placeholder="Search groups..." onkeyup="renderLists()" style="margin:0;padding:10px 15px;border-radius:20px" autocomplete="off"></div>
            <div style="padding:10px 15px 5px 15px"><input type="text" id="group-search" class="form-input" placeholder="Search groups..." oninput="debouncedRender()" style="margin:0;padding:10px 15px;border-radius:20px" autocomplete="off"></div>
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
            <div style="padding:10px 15px 5px 15px"><input type="text" id="channel-search" class="form-input" placeholder="Search channels..." onkeyup="renderLists()" style="margin:0;padding:10px 15px;border-radius:20px" autocomplete="off"></div>
            <div style="padding:10px 15px 5px 15px"><input type="text" id="channel-search" class="form-input" placeholder="Search channels..." oninput="debouncedRender()" style="margin:0;padding:10px 15px;border-radius:20px" autocomplete="off"></div>
            <div class="panel-header" style="padding-top:5px;padding-bottom:5px;border-bottom:none"><span data-i18n="tab_channels">Channels</span> <div style="display:flex;gap:5px"><div class="btn-icon" onclick="discover('channel')" title="Discover Channels">🌍</div><div class="btn-icon" onclick="createChannel()" title="Create Channel">+</div></div></div>
            <div style="padding:0 15px 10px 15px"><button class="form-input" style="cursor:pointer;border-radius:20px;text-align:center;background:var(--bg);border:1px solid var(--border)" onclick="joinGroup()">Join via Code</button></div>
            <div class="list-area" id="list-channels">
                <div class="tab-loader">
                    <div class="rail-letters"><span>m</span><span>o</span><span>R</span><span>e</span></div>
                    <div class="rail-dot"></div>
                </div>
            </div>
        </div>
        <div id="tab-observatory" class="tab-content" style="display:none" <?php if ($lightweightMode) echo 'hidden'; ?>>
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
                <div class="form-group"><label data-i18n="bio">Bio / Status</label><input class="form-input" id="set-bio" maxlength="50" autocomplete="off"></div>
                <div class="form-group"><label>Custom Status</label><input class="form-input" id="set-status" maxlength="80" placeholder="e.g. Busy, On vacation..." autocomplete="off"></div>
                <div class="form-group"><button class="btn-sec" style="width:100%;padding:10px;border:1px solid var(--border);border-radius:4px;cursor:pointer;background:var(--panel);color:var(--text)" onclick="changeUsername()">Change Username</button></div>
                <div class="form-group"><label data-i18n="avatar_url">Avatar</label>
                    <div style="display:flex;gap:5px"><input class="form-input" id="set-av" <?php if ($lightweightMode) echo 'placeholder="Local URL or Data URI only"'; ?> style="flex:1" autocomplete="off">
                    <button class="btn-sec" onclick="document.getElementById('up-av').click()">Upload</button></div>
                    <input type="file" id="up-av" hidden accept="image/*" onchange="handleAvUpload(this)">
                </div>
                <div class="form-group"><label data-i18n="new_pass">New Password</label><input class="form-input" id="set-pw" type="password" autocomplete="new-password"></div>
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
                    <p style="color:#888;">moreweb Messenger v0.0.5</p>
                    <button class="btn-sec" style="margin-bottom:20px;cursor:pointer;padding:8px 16px;border-radius:20px" onclick="checkUpdates()" data-i18n="check_updates">Check for Updates</button><br>
                    <a href="https://github.com/iWebbIO/php-messenger" target="_blank" class="about-link">GitHub Repository</a>
                    <br><br>
                    <button class="btn-sec" style="width:100%;padding:10px;border:1px solid #f55;color:#f55;border-radius:4px;cursor:pointer;background:transparent" onclick="if(confirm('Logout?')){clearLocalStorageOnLogout();location.href='?action=logout'}" data-i18n="logout">Logout</button>
                </div>
            </div>
        </div>
        <!-- ABOUT TAB -->
        <div id="tab-about" class="tab-content desktop-only" style="display:none">
            <div class="panel-header" data-i18n="tab_about">About</div>
            <div class="list-area" style="padding:20px; text-align:center; color:#ccc;">
                <h2>moreweb Messenger</h2>
                <p style="color:#888;">Version 0.0.5</p>
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
            <div id="selection-bar">
                <div class="btn-icon" onclick="clearSelection()">&times;</div>
                <div id="sel-count" style="flex:1; margin-left:15px; font-weight:bold">1 Selected</div>
                <div class="btn-icon" onclick="copySelected()" id="sel-copy-btn" style="margin-right:10px">
                    <svg viewBox="0 0 24 24" width="20" fill="currentColor"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>
                </div>
                <div class="btn-icon red-text" onclick="deleteSelected()">
                    <svg viewBox="0 0 24 24" width="20" fill="currentColor"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zm2.46-7.12l1.41-1.41L12 12.59l2.12-2.12 1.41 1.41L13.41 14l2.12 2.12-1.41 1.41L12 15.41l-2.12 2.12-1.41-1.41L10.59 14l-2.12-2.12zM15.5 4l-1-1h-5l-1 1H5v2h14V4z"/></svg>
                </div>
            </div>
            <div style="display:flex;align-items:center">
                <div class="back-btn" onclick="closeChat()" style="cursor:pointer">&larr;</div>
                <div class="avatar chat-info-clickable" id="chat-av" onclick="showProfilePopup()"></div>
                <div class="chat-info-clickable" onclick="showProfilePopup()"><div id="chat-title" style="font-weight:bold"></div><div id="chat-sub" style="font-size:0.75rem;color:#999"></div><div id="typing-ind" style="font-size:0.7rem;color:var(--accent);display:none;font-style:italic">typing...</div></div>
            </div>
            
            <div class="header-actions">
                <div class="btn-icon" id="btn-search-toggle" onclick="toggleMsgSearch()" title="Search">
                    <svg viewBox="0 0 24 24" width="24" fill="currentColor"><path d="M15.5 14h-.79l-.28-.27A6.471 6.471 0 0 0 16 9.5 6.5 6.5 0 1 0 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/></svg>
                </div>
                <div class="btn-icon" id="btn-call" onclick="startCall()" style="display:none">
                    <svg viewBox="0 0 24 24" width="24" fill="currentColor"><path d="M17 10.5V7c0-.55-.45-1-1-1H4c-.55 0-1 .45-1 1v10c0 .55.45 1 1 1h12c.55 0 1-.45 1-1v-3.5l4 4v-11l-4 4z"/></svg>
                </div>
                <div class="btn-icon notif-btn" onclick="toggleNotif()">
                    <svg viewBox="0 0 24 24" width="24" fill="currentColor"><path d="M12 22c1.1 0 2-.9 2-2h-4c0 1.1.9 2 2 2zm6-6v-5c0-3.07-1.63-5.64-4.5-6.32V4c0-.83-.67-1.5-1.5-1.5s-1.5.67-1.5 1.5v.68C7.64 5.36 6 7.92 6 11v5l-2 2v1h16v-1l-2-2zm-2 1H8v-6c0-2.48 1.51-4.5 4-4.5s4 2.02 4 4.5v6z"/></svg>
                    <div class="notif-badge" id="notif-count">0</div>
                    <div class="notif-dropdown" id="notif-list"></div>
                </div>
                <div class="btn-icon menu-btn" onclick="toggleMenu(event)">
                    <svg viewBox="0 0 24 24" width="24" fill="currentColor"><path d="M12 8c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm0 2c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zm0 6c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2z"/></svg>
                    <div class="menu-dropdown" id="chat-menu">
                        <div class="menu-item" id="menu-e2ee" onclick="toggleEncryption()" style="display:none">Enable End-to-End Encryption</div>
                        <div class="menu-item" onclick="clearChat()" data-i18n="clear_history">Clear History</div>
                        <div class="menu-item red-text" onclick="deleteChat()" data-i18n="delete_chat">Delete Chat</div>
                        <div class="menu-item" onclick="exportChat()" data-i18n="export_chat">Export Chat</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- MESSAGE SEARCH BAR -->
        <div id="msg-search-bar" style="display:none;padding:8px 15px;background:var(--panel);border-bottom:1px solid var(--border);gap:8px;align-items:center">
            <input type="text" id="msg-search-input" class="form-input" placeholder="Search messages..." style="flex:1;border-radius:20px;padding:8px 14px;margin:0" oninput="searchMessages(this.value)" autocomplete="off">
            <span id="msg-search-count" style="font-size:0.8rem;color:#888;white-space:nowrap"></span>
            <div class="btn-icon" onclick="toggleMsgSearch()">&times;</div>
        </div>

        <!-- PINNED MESSAGE BANNER -->
        <div id="pinned-banner" style="display:none;padding:8px 15px;background:rgba(168,85,247,0.1);border-bottom:1px solid var(--accent);cursor:pointer;font-size:0.85rem;align-items:center;gap:8px" onclick="scrollToPinned()">
            <svg viewBox="0 0 24 24" width="16" fill="var(--accent)"><path d="M16 12V4h1V2H7v2h1v8l-2 2v2h5.2v6h1.6v-6H18v-2l-2-2z"/></svg>
            <div style="flex:1;overflow:hidden;white-space:nowrap;text-overflow:ellipsis" id="pinned-text"></div>
            <span style="color:#888;font-size:0.75rem" id="pinned-unpin" onclick="event.stopPropagation();unpinMessage()">Unpin</span>
        </div>

        <div id="we-overlay" class="we-overlay">
            <svg viewBox="0 0 24 24" width="64" height="64" style="fill:var(--accent)"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-9-2c0-1.66 1.34-3 3-3s3 1.34 3 3v2H9V6zm9 14H6V10h12v10zm-6-3c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2z"/></svg>
            <div class="we-status" id="we-status">Generating keys...</div>
            <div style="margin-top:10px;color:#888;font-size:0.9rem">Do not leave this screen.</div>
        </div>

        <div class="messages" id="msgs"></div>

        <div id="scroll-btn" class="scroll-btn" onclick="scrollToBottom(true)">
            <svg viewBox="0 0 24 24" width="24" height="24" fill="currentColor"><path d="M7.41 8.59L12 13.17l4.59-4.58L18 10l-6 6-6-6 1.41-1.41z"/></svg>
        </div>

        <div id="multi-attach-ui" class="multi-attach-bar" style="display:none">
            <div style="display:flex; justify-content:space-between; align-items:center; width:100%">
                <span class="multi-attach-count" id="multi-attach-count"></span>
                <span onclick="cancelMultiAttach()" style="cursor:pointer; padding:0 5px; font-size:1.3rem; color:var(--text-muted,#aaa); line-height:1">&times;</span>
            </div>
            <div id="multi-attach-scroll" style="display:flex;gap:8px;align-items:center;width:100%;overflow-x:auto;scrollbar-width:none;min-width:0"></div>
        </div>

        <div class="input-area" id="input-box" style="visibility:hidden">
            <input type="file" id="file" hidden onchange="uploadFile(this)">
            <button class="btn-icon" id="btn-emoji" onclick="toggleEmojiDrawer()">
                <svg viewBox="0 0 24 24" width="24" fill="currentColor"><path d="M11.99 2C6.47 2 2 6.48 2 12s4.47 10 9.99 10C17.52 22 22 17.52 22 12S17.52 2 11.99 2zM12 20c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8zm3.5-9c.83 0 1.5-.67 1.5-1.5S16.33 8 15.5 8 14 8.67 14 9.5s.67 1.5 1.5 1.5zm-7 0c.83 0 1.5-.67 1.5-1.5S9.33 8 8.5 8 7 8.67 7 9.5 7.67 11 8.5 11zm3.5 6.5c2.33 0 4.31-1.46 5.11-3.5H6.89c.8 2.04 2.78 3.5 5.11 3.5z"/></svg>
            </button>
            <div class="input-wrapper">
                <div class="reply-ctx" id="reply-ui">
                    <div id="reply-txt" style="flex:1;overflow:hidden;margin-right:10px"></div>
                <button id="del-btn" style="display:none;font-size:0.8rem;color:#f55;margin-right:10px;background:none;border:none;cursor:pointer" onclick="deleteMsg()">Delete</button>
                    <span onclick="cancelReply()" style="cursor:pointer">&times;</span>
                </div>
                <div class="reply-ctx" id="file-preview-ui" style="display:none;border-bottom:1px solid var(--border)">
                    <div style="display:flex;align-items:center;gap:10px;overflow:hidden;flex:1">
                        <svg viewBox="0 0 24 24" width="20" fill="var(--accent)"><path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>
                        <div style="overflow:hidden">
                            <div id="file-preview-name" style="font-size:0.85rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis"></div>
                            <div id="file-preview-size" style="font-size:0.7rem;color:#888"></div>
                        </div>
                    </div>
                    <span onclick="cancelFile()" style="cursor:pointer;padding:5px;font-size:1.2rem">&times;</span>
                </div>
                <div id="rec-ui" style="display:none;align-items:center;height:40px;background:#333;border-radius:20px;padding:0 15px;color:#f55">
                    <span style="flex:1">Recording...</span>
                    <span onclick="stopRec(false)" style="cursor:pointer;margin-right:15px;color:#ccc;letter-spacing:0.2em;text-align:center">C A N C E L</span>
                    <button onclick="stopRec(true)" class="btn-icon" style="background:var(--accent);color:#fff;width:45px;height:45px;border-radius:50%"><svg viewBox="0 0 24 24"><path d="M21 7L9 19l-5.5-5.5L5 12.5 9 16.5 19 6l2 1z"/></svg></button>
                </div>
                <textarea id="txt" rows="1" placeholder="Type a message..." enterkeyhint="send" autocomplete="off"></textarea>
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
        
        <!-- Emoji Drawer -->
        <div id="emoji-drawer" class="emoji-drawer">
            <div class="emoji-tabs">
                <div class="emoji-tab active" id="tab-em-emoji" onclick="switchEmojiTab('emoji')">Emojis</div>
                <div class="emoji-tab" id="tab-em-sticker" onclick="switchEmojiTab('sticker')">Stickers</div>
                <div class="emoji-tab" id="tab-em-gif" onclick="switchEmojiTab('gif')">GIFs</div>
            </div>
            <div id="emoji-content" class="emoji-content emoji-grid"></div>
        </div>
        </div> <!-- End of chat-view -->
        
        <!-- OBSERVATORY VIEW -->
        <div id="observatory-view" style="display:none;flex-direction:column;height:100%;width:100%;overflow-y:auto;background:var(--bg)" <?php if ($lightweightMode) echo 'hidden'; ?>>
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
const ME = "<?php echo addslashes(htmlspecialchars($_SESSION['user'], ENT_QUOTES, 'UTF-8')); ?>";
const CSRF_TOKEN = "<?php echo $_SESSION['csrf_token']; ?>";
const LIGHTWEIGHT_MODE = <?php echo $lightweightMode ? 'true' : 'false'; ?>;
let lastTyping = 0;
let lastRead = 0;
let mediaRec=null, audChunks=[], recMime='';
let pendingFile = null;
let pendingImages = [];
let currentAudio=null, currentBtn=null, updateInterval=null;
let lastPollTime = null;
let emojiPinned = false;
let lastListState = "";
const RTC_CFG = LIGHTWEIGHT_MODE ? {iceServers:[]} : {iceServers:[{urls:'stun:stun.l.google.com:19302'}]};
let pc=null, localStream=null, callState='idle', callPeer=null;

const vidObserver = window.IntersectionObserver ? new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        let v = entry.target;
        if(entry.isIntersecting) {
            if(v.paused && !v.dataset.paused) v.play().catch(()=>{});
        } else {
            if(!v.paused) v.pause();
        }
    });
}, { threshold: 0.01 }) : null;

function ab2b64(buf) {
    let binary = '';
    let bytes = new Uint8Array(buf);
    let len = bytes.byteLength;
    for (let i = 0; i < len; i += 32768) {
        binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 32768));
    }
    return window.btoa(binary);
}
function b642ab(base64) {
    let str = window.atob(base64);
    let len = str.length;
    let bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = str.charCodeAt(i);
    }
    return bytes;
}

async function setSafeVideoSrc(videoEl, dataUri) {
    if(dataUri.trim().toLowerCase().startsWith('javascript:')) return;
    try {
        let blob = await (await fetch(dataUri)).blob();
        videoEl.src = URL.createObjectURL(blob);
    } catch(e) {
        videoEl.src = dataUri;
    }
    if(vidObserver) vidObserver.observe(videoEl);
}

let S = { tab:'chats', id:null, type:null, reply:null, editMsgId:null, ctx:null, dms:{}, groups:{}, online:[], profiles:{}, notifs:[], keys:{pub:null,priv:null}, e2ee:{}, weSyncReqSent:{}, scroll:{}, ackDms:[], groupCursors:{}, wsync:{peers:{}, dc:{}}, deviceId: localStorage.getItem('mw_did') || Math.random().toString(36).substr(2,9), stickers:[], gifs:[] };
localStorage.setItem('mw_did', S.deviceId);

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
        start_chat: "Start chatting", join_code: "Join via Code", incoming_call: "Incoming Video Call...",
        cancel: "CANCEL", preview: "Preview", send: "Send",
        market_usd: "USD", market_oil: "Oil", market_updated: "Updated",
        search_gifs: "Search GIFs..."
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
        start_chat: "شروع گفتگو", join_code: "عضویت با کد", incoming_call: "تماس تصویری ورودی...",
        cancel: "لغو", preview: "پیش‌نمایش", send: "ارسال",
        market_usd: "دلار", market_oil: "نفت", market_updated: "بروزرسانی",
        search_gifs: "جستجوی گیف..."
    }
};
let curLang = localStorage.getItem('mw_lang') || 'en';

function setLang(l) {
    curLang = TR[l] ? l : 'en'; localStorage.setItem('mw_lang', curLang);
    document.body.classList.toggle('rtl', curLang=='fa');
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

let debounceTimer;
function debouncedRender() {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => { renderLists(); }, 150);
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
            bd.innerHTML = placeholder;
        ip.style.display = 'none';
        cc.style.display = 'block';
        ok.innerText = 'Accept';
    } else {
        bd.style.display = 'block';
            bd.innerHTML = placeholder; // In alert mode, placeholder is body text
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

// --- LOGOUT CLEANUP ---
function clearLocalStorageOnLogout() {
    // Remove auth token and all app-specific keys
    let keysToRemove = [];
    for (let i = 0; i < localStorage.length; i++) {
        let k = localStorage.key(i);
        if (k && (k.startsWith('mw_') || k === 'mw_auth_token')) {
            keysToRemove.push(k);
        }
    }
    keysToRemove.forEach(k => localStorage.removeItem(k));
    // Clear IndexedDB
    try { indexedDB.deleteDatabase('mw_chat_db'); } catch(e) {}
}

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

async function loadSessions() {
    if(!window.crypto || !window.crypto.subtle) return;
    for (let i = 0; i < localStorage.length; i++) {
        let k = localStorage.key(i);
        if (k.startsWith('mw_grp_sess_')) {
            let gid = k.split('mw_grp_sess_')[1];
            S.e2ee[gid] = await window.crypto.subtle.importKey("jwk", JSON.parse(localStorage.getItem(k)), {name:"AES-GCM",length:256}, false, ["encrypt","decrypt"]);
        } else if (k.startsWith('mw_pub_')) {
            let u = k.split('mw_pub_')[1];
            S.e2ee[u] = await window.crypto.subtle.importKey("jwk", JSON.parse(localStorage.getItem(k)), {name:"ECDH",namedCurve:"P-256"}, true, []);
        }
    }
}

// --- BACK BUTTON HANDLER ---
function initBackButtonHandler() {
    S.openOverlays = [];
    S.ignoreNextPop = false;
    S.closeTriggeredByPop = false;

    const isPWA = () => {
        return window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone === true;
    };

    const overlayIds = [
        'main-view',
        'emoji-drawer',
        'att-menu',
        'chat-menu',
        'notif-list',
        'user-popup',
        'ctx-menu',
        'app-modal',
        'lightbox',
        'media-preview',
        'call-overlay'
    ];

    const isOverlayOpen = (id) => {
        let el = document.getElementById(id);
        if (!el) return false;
        if (id === 'main-view') return el.classList.contains('active');
        if (id === 'att-menu') return el.style.display === 'grid';
        if (id === 'chat-menu' || id === 'notif-list' || id === 'ctx-menu') return el.style.display === 'block';
        return el.style.display === 'flex';
    };

    const closeOverlay = (id) => {
        let el = document.getElementById(id);
        if (!el) return;
        if (id === 'main-view') closeChat();
        else if (id === 'emoji-drawer') el.style.display = 'none';
        else if (id === 'att-menu') el.style.display = 'none';
        else if (id === 'chat-menu') el.style.display = 'none';
        else if (id === 'notif-list') el.style.display = 'none';
        else if (id === 'user-popup') el.style.display = 'none';
        else if (id === 'ctx-menu') el.style.display = 'none';
        else if (id === 'app-modal') {
            let cancelBtn = document.getElementById('modal-cancel');
            if (cancelBtn && cancelBtn.style.display !== 'none') cancelBtn.click();
            else el.style.display = 'none';
        }
        else if (id === 'lightbox') closeLightbox();
        else if (id === 'media-preview') closePreview();
        else if (id === 'call-overlay') {
            if (typeof callState !== 'undefined' && callState === 'incoming') rejectCall();
            else endCall();
        }
    };

    const observer = new MutationObserver(() => {
        if (!isPWA() || window.innerWidth > 850) return;

        let currentVisible = [];
        overlayIds.forEach(id => {
            if (isOverlayOpen(id)) currentVisible.push(id);
        });

        let diff = currentVisible.length - S.openOverlays.length;

        if (diff > 0) {
            for (let i = 0; i < diff; i++) {
                history.pushState({ mw_overlay: true }, '');
            }
            S.openOverlays = currentVisible;
        } else if (diff < 0) {
            if (!S.closeTriggeredByPop) {
                S.ignoreNextPop = true;
                history.go(diff);
                setTimeout(() => { S.ignoreNextPop = false; }, 200);
            }
            S.openOverlays = currentVisible;
        }
    });

    const configStyle = { attributes: true, attributeFilter: ['style'] };
    const configClass = { attributes: true, attributeFilter: ['class'] };

    overlayIds.forEach(id => {
        let el = document.getElementById(id);
        if (el) {
            if (id === 'main-view') observer.observe(el, configClass);
            else observer.observe(el, configStyle);
        }
    });

    window.addEventListener('popstate', (e) => {
        if (S.ignoreNextPop) {
            S.ignoreNextPop = false;
            return;
        }
        
        if (!isPWA() || window.innerWidth > 850) return;

        if (S.openOverlays.length > 0) {
            let topmost = S.openOverlays[S.openOverlays.length - 1];
            S.closeTriggeredByPop = true;
            closeOverlay(topmost);
            Promise.resolve().then(() => {
                setTimeout(() => { S.closeTriggeredByPop = false; }, 0);
            });
        }
    });
}

async function init(){
    try {
        await loadKeys();
        await loadSessions();
        
        // Migration to clean up old AES-GCM DM keys
        let keys = Object.keys(localStorage);
        for(let k of keys){
            if(k.startsWith('mw_sess_')) localStorage.removeItem(k);
        }
        
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
        
        // Load cached metadata for offline use
        let cg = await get('meta', 'groups');
        if(cg && !Array.isArray(cg)) S.groups = cg;
        
        let cp = await get('meta', 'users');
        if(cp && !Array.isArray(cp)) S.profiles = cp;

        let cst = await get('custom', 'stickers');
        if(cst && Array.isArray(cst)) S.stickers = cst;

        let cgf = await get('custom', 'gifs');
        if(cgf && Array.isArray(cgf)) S.gifs = cgf;

        setLang(curLang);
        renderLists();
        initBackButtonHandler();
        pollLoop();

        // Handle ?join=CODE URL param for group invite links
        let urlParams = new URLSearchParams(location.search);
        let joinCode = urlParams.get('join');
        if (joinCode) {
            history.replaceState({}, '', location.pathname);
            setTimeout(async () => {
                let r = await req('join_group', {code: joinCode, password: ''});
                let d = await r.json();
                if (d.status === 'success') {
                    showToast('Joined group successfully!');
                    await poll();
                    renderLists();
                } else {
                    alertModal('Join Group', d.message || 'Invalid invite code');
                }
            }, 1000);
        }
        window.addEventListener('online', () => {
            setConn(false, false);
            if(pollTimer) clearTimeout(pollTimer);
            pollLoop();
        });
        window.addEventListener('offline', () => setConn(false, true));
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
    let silent = act=='poll' || act=='typing' || (act=='send' && data && data.type=='wsync');
    if(!silent) startProg();
    let r = await fetch('?action='+act, {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': CSRF_TOKEN},
        body: JSON.stringify(data||{})
    });
    if(!silent) endProg();
    return r;
}

function showToast(msg) {
    let t = document.getElementById('toast');
    t.innerText = msg;
    t.classList.add('show');
    setTimeout(()=>t.classList.remove('show'), 3000);
}

// --- CORE ---
let pollTimer = null;
async function pollLoop() {
    await poll();
    if(pollTimer) clearTimeout(pollTimer);
    pollTimer = setTimeout(pollLoop, navigator.onLine ? 2000 : 5000);
}

function setConn(s, isError = false){
    let el = document.getElementById('conn-indicator');
    if(s) {
        el.classList.add('status-connected');
        el.querySelector('.conn-text').innerHTML = 'Connecting<span class="conn-dots"></span>';
    } else {
        el.classList.remove('status-connected');
        if (isError || !navigator.onLine) {
            el.querySelector('.conn-text').innerHTML = 'Waiting for network<span class="conn-dots"></span>';
        } else {
            el.querySelector('.conn-text').innerHTML = 'Connecting<span class="conn-dots"></span>';
        }
    }
}

async function poll(){
    try {
        let lastPub = 0;
        let pubH = await get('public', 'global');
        if(pubH.length) lastPub = pubH[pubH.length-1].id || 0;
        
        let payload = {last_pub: lastPub};
        if(S.ackDms.length > 0) payload.ack_dms = S.ackDms;
        if(Object.keys(S.groupCursors).length > 0) payload.group_cursors = S.groupCursors;

        let r=await req('poll', payload);
        if(!r.ok) throw new Error("HTTP " + r.status);
        
        if(r.ok) { S.ackDms = []; S.groupCursors = {}; }

        lastPollTime = new Date();
        let d=await r.json();
        setConn(true);
        S.online=d.online;
        
        // Cache Profiles
        d.online.forEach(u => { S.profiles[u.username] = u; });
        await save('meta', 'users', S.profiles);

        if(d.profile){
            document.getElementById('my-av').style.backgroundImage=`url('${d.profile.avatar}')`;
            document.getElementById('my-name').innerText=d.profile.username;
            if(document.activeElement !== document.getElementById('set-bio')) document.getElementById('set-bio').value=d.profile.bio||'';
            let statusEl = document.getElementById('set-status');
            if(statusEl && document.activeElement !== statusEl) statusEl.value = d.profile.status_text||'';
            document.getElementById('my-date').innerText="Joined: "+new Date(d.profile.joined_at*1000).toLocaleDateString();
        }
        for(let m of d.dms){
            if(m.id && !S.ackDms.includes(m.id)) S.ackDms.push(m.id);
            if(m.type=='wsync'){ handleWSyncMsg(m); continue; }
            if(m.type=='delete'){ await removeMsg('dm',m.from_user,m.extra_data); continue; }
            if(m.type=='read'){ 
                let h=await get('dm',m.from_user); 
                let changed = false;
                h.forEach(x=>{if(x.from_user==ME && x.timestamp<=m.extra_data && !x.read){x.read=true; changed=true;}}); 
                if(changed) await save('dm',m.from_user,h); 
                if(S.id==m.from_user && S.type=='dm') {
                    document.querySelectorAll('.msg.out').forEach(node => {
                        let ts = parseInt(node.id.split('-')[1]);
                        let meta = node.querySelector('.msg-meta > span');
                        if(ts <= m.extra_data && meta && meta.innerText === '✓') {
                            meta.outerHTML = '<span style="color:#4fc3f7;margin-left:3px">✓✓</span>';
                        }
                    });
                }
                continue; 
            }
            if(m.type=='signal'){ onSignal(m); continue; }
            if(m.type=='enc'){ 
                try{
                    if(!S.e2ee[m.from_user]) await ensureE2EE(m.from_user);
                    let decrypted = await dec('dm', m.from_user, m.message, m.extra_data);
                    if (decrypted.startsWith('{"_mw_enc":')) {
                        let parsed = JSON.parse(decrypted);
                        m.message = parsed.msg;
                        m.type = parsed.type;
                        m.extra_data = parsed.extra;
                    } else {
                        m.message = decrypted;
                        m.type = 'text';
                    }
                }catch(e){
                    m.message="⚠️ [Encrypted] Decryption failed. Keys might be stale. Requesting new keys automatically...";
                    m.type='text';
                    if(!S.keyRefreshSent) S.keyRefreshSent = {};
                    if(!S.keyRefreshSent[m.from_user] || Date.now() - S.keyRefreshSent[m.from_user] > 60000) {
                        req('send', {to_user: m.from_user, type: 'signal', extra: 'key_refresh_req'});
                        S.keyRefreshSent[m.from_user] = Date.now();
                    }
                } 
            }
            if(m.type == 'edit') {
                let h = await get('dm', m.from_user);
                let orig = h.find(x => x.timestamp == m.extra_data);
                if(orig) {
                    orig.message = m.message; orig.edited = true;
                    await save('dm', m.from_user, h);
                    if(S.id==m.from_user && S.type=='dm') { let el = document.getElementById('msg-' + m.extra_data); if(el) el.replaceWith(createMsgNode(orig, el.querySelector('.msg-sender') !== null, h)); }
                }
                continue;
            }
            await store('dm',m.from_user,m);
            let prev = m.type==='text' ? m.message : '['+m.type+']';
            notify(m.from_user, prev, 'dm');
            if(S.type=='dm' && S.id==m.from_user && document.hasFocus()) req('send', {to_user:m.from_user, type:'read', extra:m.timestamp});
        }
        S.groups={}; 
        for(let g of d.groups){ 
            S.groups[g.id]=g; 
            let type = g.category === 'channel' ? 'channel' : 'group';
            let ex=await get(type,g.id); if(!ex.length) await save(type,g.id,[]); 
        }
        await save('meta', 'groups', S.groups);
        for(let m of d.group_msgs){ 
            if(m.id) S.groupCursors[m.group_id] = Math.max(S.groupCursors[m.group_id] || 0, m.id);
            let g = S.groups[m.group_id];
            let type = (g && g.category === 'channel') ? 'channel' : 'group';
            if(m.type=='delete'){ await removeMsg(type,m.group_id,m.extra_data); continue; }
            if(m.type=='wencrypt_key'){ handleWeKey(m); continue; }
            if(m.type=='signal') { 
                if (m.extra_data === 'group_key_req' && m.from_user !== ME) {
                    if (S.e2ee[m.group_id]) {
                        setTimeout(async () => {
                            try {
                                let r = await fetch('?action=get_profile&u=' + m.from_user);
                                let pd = await r.json();
                                if(pd.public_key) {
                                    let gkExp = await window.crypto.subtle.exportKey("jwk", S.e2ee[m.group_id]);
                                    let theirPub = await window.crypto.subtle.importKey("jwk", JSON.parse(pd.public_key), {name:"ECDH",namedCurve:"P-256"}, true, []);
                                    let ephem = await window.crypto.subtle.generateKey({name:"ECDH",namedCurve:"P-256"}, true, ["deriveKey"]);
                                    let sessKey = await window.crypto.subtle.deriveKey({name:"ECDH",public:theirPub}, ephem.privateKey, {name:"AES-GCM",length:256}, false, ["encrypt"]);
                                    
                                    let iv = window.crypto.getRandomValues(new Uint8Array(12));
                                    let buf = await window.crypto.subtle.encrypt({name:"AES-GCM",iv:iv}, sessKey, new TextEncoder().encode(JSON.stringify(gkExp)));
                                    
                                    let b=''; new Uint8Array(buf).forEach(x=>b+=String.fromCharCode(x));
                                    let i=''; iv.forEach(x=>i+=String.fromCharCode(x));
                                    let p = await window.crypto.subtle.exportKey("jwk", ephem.publicKey);
                                    
                                    let payload = {};
                                    payload[m.from_user] = JSON.stringify({ c: btoa(b), i: btoa(i), p: p });
                                    
                                    req('send', {group_id:m.group_id, type:'wencrypt_key', message:JSON.stringify(payload)});
                                }
                            } catch(e) { console.error("Failed to answer group key req", e); }
                        }, Math.random() * 5000);
                    }
                }
                continue; 
            }
            if(m.type=='enc') {
                try {
                    if(S.e2ee[m.group_id]) {
                        let decrypted = await dec('group', m.group_id, m.message, m.extra_data);
                        if (decrypted.startsWith('{"_mw_enc":')) {
                            let parsed = JSON.parse(decrypted);
                            m.message = parsed.msg;
                            m.type = parsed.type;
                            m.extra_data = parsed.extra;
                        } else {
                            m.message = decrypted;
                            m.type = 'text';
                        }
                    } else {
                        m.c_cache = m.message;
                        m.message="⚠️ [Encrypted] Missing group key. Synchronizing...";
                        m.type='text';
                        m.needs_decryption = true;
                        
                        if (!S.weSyncReqSent[m.group_id] || Date.now() - S.weSyncReqSent[m.group_id] > 10000) {
                            req('send', {group_id: m.group_id, type: 'signal', extra: 'group_key_req'});
                            S.weSyncReqSent[m.group_id] = Date.now();
                        }
                    }
                } catch(e) {
                    m.message="⚠️ [Encrypted] Decryption failed.";
                    m.type='text';
                }
            }
            if(m.type == 'edit') {
                let h = await get(type, m.group_id);
                let orig = h.find(x => x.timestamp == m.extra_data);
                if(orig) {
                    orig.message = m.message; orig.edited = true;
                    await save(type, m.group_id, h);
                    if(S.id==m.group_id && S.type==type) { let el = document.getElementById('msg-' + m.extra_data); if(el) el.replaceWith(createMsgNode(orig, el.querySelector('.msg-sender') !== null, h)); }
                }
                continue;
            }
            await store(type,m.group_id,m); 
            let prev = m.type==='text' ? m.message : '['+m.type+']';
            notify(m.group_id, prev, type); 
        }
        for(let m of d.public_msgs){
            if(m.type=='delete'){ await removeMsg('public','global',m.extra_data); continue; }
            if(m.type == 'edit') {
                let h = await get('public', 'global');
                let orig = h.find(x => x.timestamp == m.extra_data);
                if(orig) {
                    orig.message = m.message; orig.edited = true;
                    await save('public', 'global', h);
                    if(S.type=='public') { let el = document.getElementById('msg-' + m.extra_data); if(el) el.replaceWith(createMsgNode(orig, el.querySelector('.msg-sender') !== null, h)); }
                }
                continue;
            }
            await store('public','global',m);
            notify('global', m.message, 'public');
        }
        
        const stateStr = JSON.stringify({o: d.online.length, d: d.dms.length, g: d.groups.length, gm: d.group_msgs.length});
        if (stateStr !== lastListState) { lastListState = stateStr; renderLists(); }
        
        if(S.type=='public') document.getElementById('chat-sub').innerText = "Global Room (5m TTL) - " + d.online.length + " Online";
        else if(S.type=='dm' && d.typing && d.typing.includes(S.id)) document.getElementById('typing-ind').style.display='block'; else document.getElementById('typing-ind').style.display='none';

        await renderLists();
        if(S.type=='dm' && S.id){
             let ou=d.online.find(x=>x.username==S.id);
             let prof = S.profiles[S.id];
             let sub=ou?(ou.bio||'Online'):'Offline';
             document.getElementById('chat-sub').innerText=sub;
             let av = (ou && ou.avatar) ? ou.avatar : (prof ? prof.avatar : '');
             if(av) document.getElementById('chat-av').style.backgroundImage=`url('${av}')`;
        }
} catch(e){ console.error("Poll error:", e); setConn(false, true); }
}

function notify(id, text, type) {
    if(S.type === type && S.id == id && document.hasFocus()) return;
    if(S.notifs.some(n => n.id == id && n.text == text)) return;
    let title = type=='dm'?id:(type=='public'?'Public Chat':(S.groups[id]?S.groups[id].name:(type=='channel'?'Channel':'Group')));
    S.notifs.unshift({id, type, text, title: title, time:new Date()});
    if(S.notifs.length > 50) S.notifs.length = 50;
    updateNotifUI();
    let targetTab = (type=='dm' || type=='public') ? 'chats' : (type=='channel'?'channels':'groups');
    if(S.tab !== targetTab && document.getElementById('badge-' + targetTab)) {
        document.getElementById('badge-' + targetTab).style.display = 'block';
    }

    try {
        let ac = new (window.AudioContext || window.webkitAudioContext)();
        let osc = ac.createOscillator();
        let gn = ac.createGain();
        osc.connect(gn);
        gn.connect(ac.destination);
        osc.frequency.value = 600;
        gn.gain.value = 0.1;
        osc.start();
        osc.stop(ac.currentTime + 0.15);
    } catch(e) {}

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
    switchTab((n.type == 'dm' || n.type == 'public') ? 'chats' : (n.type=='channel'?'channels':'groups'));
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
    let idx = -1;
    if(m.id) idx = h.findIndex(x => x.id == m.id);
    
    if(idx === -1) {
        idx = h.findIndex(x => {
            if (x.from_user !== m.from_user) return false;
            if (x.pending && m.from_user === ME && !m.pending) {
                if ((m.type === 'file' || m.type === 'image' || m.type === 'audio') && m.extra_data && x.extra_data === m.extra_data) return true;
                if (x.message === m.message && x.type === m.type) return true;
            }
            if (x.timestamp !== m.timestamp || x.from_user !== m.from_user) return false;
            if ((m.type === 'file' || m.type === 'image' || m.type === 'audio') && m.extra_data && x.extra_data === m.extra_data) return true;
            return x.message === m.message && x.type === m.type;
        });
    }
    
    if(idx !== -1) {
        if((m.id && !h[idx].id) || (!m.pending && h[idx].pending)) {
            let old_ts = h[idx].timestamp;
            h[idx] = m;
            h.sort((a,b)=>a.timestamp-b.timestamp);
            await save(t,i,h);
            if(S.id==i && S.type==t) {
                let el = document.getElementById('msg-' + old_ts);
                if (el) {
                    el.id = 'msg-' + m.timestamp;
                    el.replaceWith(createMsgNode(m, el.querySelector('.msg-sender') !== null, h));
                }
            }
        }
        return;
    }
    if(m.type.startsWith('wencrypt_')) return; // Don't store signals
    if(m.type=='react'){
        let tg=h.find(x=>x.timestamp==m.extra_data);
        if(tg){ 
            if(!tg.reacts)tg.reacts={}; 
            if(!m.message) delete tg.reacts[m.from_user];
            else tg.reacts[m.from_user]=m.message; 
            await save(t,i,h); 
            if(S.id==i && S.type==t) {
                let el = document.getElementById('msg-' + m.extra_data);
                if (el) el.replaceWith(createMsgNode(tg, el.querySelector('.msg-sender') !== null, h));
            }
        }
      return;
    }
    h.push(m); 
    h.sort((a,b)=>a.timestamp-b.timestamp);
    await save(t,i,h);
    if(S.id==i && S.type==t) {
        if(h[h.length-1].timestamp == m.timestamp) {
            let prev = h.length>1 ? h[h.length-2] : null;
            let show = (t=='public'||t=='group'||t=='channel') && m.from_user!=ME && (!prev || prev.from_user!=m.from_user);
            let c = document.getElementById('msgs');
            if(c) c.appendChild(createMsgNode(m, show, h));
            scrollToBottom(false);
        } else renderChat();
    }
}
async function removeMsg(t,i,ts){
    let h = await get(t,i);
    let idx=h.findIndex(x=>x.timestamp==ts);
    if(idx!=-1){ 
        h.splice(idx,1); 
        await save(t,i,h); 
        if(S.id==i && S.type==t) {
            let el = document.getElementById('msg-' + ts);
            if (el) el.remove();
        }
    }
}

async function resetE2EE(u) {
    if(!confirm("Fetch the latest encryption keys for this user? Use this if they changed devices.")) return;
    delete S.e2ee[u];
    localStorage.removeItem('mw_pub_' + u);
    let success = await ensureE2EE(u);
    if(success) {
        alertModal("Security", "E2EE session updated with latest keys.");
        if (S.id === u) updateE2EEUI();
    } else {
        alertModal("Error", "Could not fetch new keys.");
    }
}

function updateE2EEUI() {
    let menuE2ee = document.getElementById('menu-e2ee');
    if(!menuE2ee) return;
    
    let isEnc = !!S.e2ee[S.id];
    let canEncrypt = false;
    
    if (S.type === 'dm') {
        canEncrypt = true;
        menuE2ee.innerText = isEnc ? "Reset E2EE Session" : "Enable End-to-End Encryption";
        menuE2ee.style.color = isEnc ? "#ff9800" : "";
    } else if (S.type === 'group' && S.groups[S.id] && S.groups[S.id].category !== 'channel') {
        let isOwner = S.groups[S.id].owner_id == <?php echo $_SESSION['uid']; ?>;
        canEncrypt = isOwner && !isEnc;
        menuE2ee.innerText = "Enable WEncrypt";
        menuE2ee.style.color = "";
    }
    
    menuE2ee.style.display = canEncrypt ? 'block' : 'none';
    
    if (S.type === 'dm' || (S.type === 'group' && S.groups[S.id] && S.groups[S.id].category !== 'channel')) {
        let title = document.getElementById('chat-title');
        let lockSvg = '<svg viewBox="0 0 24 24" width="16" style="vertical-align:text-bottom;fill:var(--accent);margin-left:5px"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1s3.1 1.39 3.1 3.1v2z"/></svg>';
        if(isEnc && !title.innerHTML.includes('<svg')) title.innerHTML += lockSvg;
        else if (!isEnc && title.innerHTML.includes('<svg')) title.innerHTML = title.innerHTML.split('<svg')[0];
        
        let txt = document.getElementById('txt');
        if(txt) {
            const langT = TR[curLang] || TR['en'];
            let canPost = !(S.type=='channel' && S.groups[S.id] && S.groups[S.id].owner_id != <?php echo $_SESSION['uid']; ?>);
            txt.placeholder = isEnc ? langT.type_enc : (canPost ? langT.type_msg : langT.only_owner);
        }
    }
}

function toggleEncryption(){
    document.getElementById('chat-menu').style.display='none';
    if(S.type=='dm') {
        if(S.e2ee[S.id]) resetE2EE(S.id);
        else startE2EE();
    }
    else if(S.type=='group') {
        if(S.e2ee[S.id]) alertModal("WEncrypt", "Group encryption is already active.");
        else startWEncrypt();
    }
}
async function startE2EE(){
    if(!window.crypto || !window.crypto.subtle) { alertModal('Error', 'Encryption requires HTTPS'); return; }
    if(S.type!='dm'||S.e2ee[S.id])return;
    startProg();
    let success = await ensureE2EE(S.id);
    endProg();
    if(success){
        alertModal("Security", "End-to-End Encryption enabled and verified.");
        updateE2EEUI();
    } else {
        alertModal("Info", "Encryption unavailable. The user may not have logged in recently to generate their keys.");
    }
}
async function ensureE2EE(u){
    if(S.e2ee[u]) return true;
    try {
        let r = await fetch('?action=get_profile&u=' + u);
        let d = await r.json();
        if(d.public_key) {
            let fk = await window.crypto.subtle.importKey("jwk", JSON.parse(d.public_key), {name:"ECDH",namedCurve:"P-256"}, true, []);
            S.e2ee[u] = fk;
            localStorage.setItem('mw_pub_' + u, d.public_key);
            return true;
        }
    } catch(e) { 
        let cached = localStorage.getItem('mw_pub_' + u);
        if(cached) {
            let fk = await window.crypto.subtle.importKey("jwk", JSON.parse(cached), {name:"ECDH",namedCurve:"P-256"}, true, []);
            S.e2ee[u] = fk;
            return true;
        }
        console.error("E2EE Setup failed", e); 
    }
    return false;
}
async function enc(t, id, txt){
    if (t === 'dm') {
        let ephem = await window.crypto.subtle.generateKey({name:"ECDH",namedCurve:"P-256"}, true, ["deriveKey"]);
        let derived = await window.crypto.subtle.deriveKey({name:"ECDH",public:S.e2ee[id]}, ephem.privateKey, {name:"AES-GCM",length:256}, false, ["encrypt"]);
        let iv=window.crypto.getRandomValues(new Uint8Array(12));
        let buf=await window.crypto.subtle.encrypt({name:"AES-GCM",iv:iv}, derived, new TextEncoder().encode(txt));
        
        let p = await window.crypto.subtle.exportKey("jwk", ephem.publicKey);
        return {c:ab2b64(buf), extra: JSON.stringify({ i: ab2b64(iv), p: p })};
    } else if (t === 'group') {
        let gk = S.e2ee[id];
        let iv=window.crypto.getRandomValues(new Uint8Array(12));
        let buf=await window.crypto.subtle.encrypt({name:"AES-GCM",iv:iv}, gk, new TextEncoder().encode(txt));
        
        return {c:ab2b64(buf), extra: ab2b64(iv)};
    }
}
async function dec(t, id, c, extra_data){
    if (t === 'dm') {
        let isLegacy = false;
        let i_b64, p_jwk;
        try {
            let ext = JSON.parse(extra_data);
            if(ext.i && ext.p) { i_b64 = ext.i; p_jwk = ext.p; } else isLegacy = true;
        } catch(e) { isLegacy = true; }

        if (isLegacy) {
            let fk = S.e2ee[id];
            let legacyKey = await window.crypto.subtle.deriveKey({name:"ECDH",public:fk}, S.keys.priv, {name:"AES-GCM",length:256}, false, ["decrypt"]);
            let d=await window.crypto.subtle.decrypt({name:"AES-GCM",iv:b642ab(extra_data)}, legacyKey, b642ab(c));
            return new TextDecoder().decode(d);
        } else {
            let ephemPub = await window.crypto.subtle.importKey("jwk", p_jwk, {name:"ECDH",namedCurve:"P-256"}, false, []);
            let derived = await window.crypto.subtle.deriveKey({name:"ECDH",public:ephemPub}, S.keys.priv, {name:"AES-GCM",length:256}, false, ["decrypt"]);
            let d=await window.crypto.subtle.decrypt({name:"AES-GCM",iv:b642ab(i_b64)}, derived, b642ab(c));
            return new TextDecoder().decode(d);
        }
    } else if (t === 'group') {
        let gk = S.e2ee[id];
        let d=await window.crypto.subtle.decrypt({name:"AES-GCM",iv:b642ab(extra_data)}, gk, b642ab(c));
        return new TextDecoder().decode(d);
    }
}

// --- WENCRYPT (GROUP E2EE) ---
async function startWEncrypt(){
    if(!confirm("Enable WEncrypt for this group? (Offline members will automatically sync the key when they come online)")) return;
    
    document.getElementById('we-overlay').style.display='flex';
    document.getElementById('we-status').innerText = "Generating keys...";
    
    fetch('?action=get_group_details&id='+S.id).then(r=>r.json()).then(async d=>{
        if(!d.is_owner) {
            document.getElementById('we-overlay').style.display='none';
            return;
        }
        
        let gk = await window.crypto.subtle.generateKey({name:"AES-GCM",length:256}, true, ["encrypt","decrypt"]);
        let gkExp = await window.crypto.subtle.exportKey("jwk", gk);
        let payload = {};
        
        for(let mem of d.members){
            if(mem.username == ME) { payload[ME] = JSON.stringify(gkExp); continue; }
            if(!mem.public_key) continue;
            
            try {
                let theirPub = await window.crypto.subtle.importKey("jwk", JSON.parse(mem.public_key), {name:"ECDH",namedCurve:"P-256"}, true, []);
                let ephem = await window.crypto.subtle.generateKey({name:"ECDH",namedCurve:"P-256"}, true, ["deriveKey"]);
                let sessKey = await window.crypto.subtle.deriveKey({name:"ECDH",public:theirPub}, ephem.privateKey, {name:"AES-GCM",length:256}, false, ["encrypt"]);
                
                let iv = window.crypto.getRandomValues(new Uint8Array(12));
                let buf = await window.crypto.subtle.encrypt({name:"AES-GCM",iv:iv}, sessKey, new TextEncoder().encode(JSON.stringify(gkExp)));
                
                let b=''; new Uint8Array(buf).forEach(x=>b+=String.fromCharCode(x));
                let i=''; iv.forEach(x=>i+=String.fromCharCode(x));
                let p = await window.crypto.subtle.exportKey("jwk", ephem.publicKey);
                
                payload[mem.username] = JSON.stringify({ c: btoa(b), i: btoa(i), p: p });
            } catch(err) {
                console.error("Failed to encrypt for user", mem.username, err);
            }
        }
        req('send', {group_id:S.id, type:'wencrypt_key', message:JSON.stringify(payload)});
        
        S.e2ee[S.id] = gk;
        localStorage.setItem('mw_grp_sess_' + S.id, JSON.stringify(gkExp));
        updateE2EEUI();
        
        document.getElementById('we-overlay').style.display='none';
        alertModal("WEncrypt", "Group is now encrypted.");
    });
}

async function handleWeKey(m){
    let payload;
    try { payload = JSON.parse(m.message); } catch(e){return;}
    if(payload[ME] && !S.e2ee[m.group_id]){
        let kStr = payload[ME];
        if(m.from_user != ME){
            try {
                let encData = JSON.parse(kStr);
                let ephemPub = await window.crypto.subtle.importKey("jwk", encData.p, {name:"ECDH",namedCurve:"P-256"}, false, []);
                let sessKey = await window.crypto.subtle.deriveKey({name:"ECDH",public:ephemPub}, S.keys.priv, {name:"AES-GCM",length:256}, false, ["decrypt"]);
                let d = await window.crypto.subtle.decrypt({name:"AES-GCM",iv:Uint8Array.from(atob(encData.i),c=>c.charCodeAt(0))}, sessKey, Uint8Array.from(atob(encData.c),c=>c.charCodeAt(0)));
                kStr = new TextDecoder().decode(d);
            } catch(e) { console.error("Failed to decrypt group key", e); return; }
        }
        try {
            let gk = await window.crypto.subtle.importKey("jwk", JSON.parse(kStr), {name:"AES-GCM",length:256}, false, ["encrypt","decrypt"]);
            S.e2ee[m.group_id] = gk;
            localStorage.setItem('mw_grp_sess_' + m.group_id, kStr);
            
            let h = await get('group', m.group_id);
            let changed = false;
            for(let i=0; i<h.length; i++) {
                if(h[i].needs_decryption || (h[i].message && h[i].message.includes("Missing group key"))) {
                    try {
                        let ciphertext = h[i].c_cache || h[i].message;
                        let decrypted = await dec('group', m.group_id, ciphertext, h[i].extra_data);
                        if (decrypted.startsWith('{"_mw_enc":')) {
                            let parsed = JSON.parse(decrypted);
                            h[i].message = parsed.msg;
                            h[i].type = parsed.type;
                            h[i].extra_data = parsed.extra;
                        } else {
                            h[i].message = decrypted;
                            h[i].type = 'text';
                        }
                        delete h[i].needs_decryption;
                        delete h[i].c_cache;
                        changed = true;
                    } catch(e) {}
                }
            }
            if(changed) {
                await save('group', m.group_id, h);
                if(S.id == m.group_id && S.type == 'group') renderChat();
                renderLists();
            }
            
            if(S.id == m.group_id) updateE2EEUI();
            showToast("WEncrypt key synced!");
        } catch(e) { console.error("Failed to import group key", e); }
    }
}

function switchTab(t){
    if(LIGHTWEIGHT_MODE && t==='observatory') return;
    S.tab=t;
    document.querySelectorAll('.rail-btn').forEach(e=>e.classList.remove('active'));
    document.getElementById('nav-'+t).classList.add('active');
    document.querySelectorAll('.tab-content').forEach(e=>e.style.display='none');
    
    document.getElementById('nav-panel').classList.remove('full-width');
    document.getElementById('main-view').style.display = '';
    
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
    if(m.usd) mh += `<div class="market-row-item"><div class="market-row-label">${t.market_usd}</div><div class="market-row-val">${obsEsc(m.usd)}</div></div>`;
    if(m.oil) mh += `<div class="market-row-item"><div class="market-row-label">${t.market_oil}</div><div class="market-row-val">${obsEsc(m.oil)}</div></div>`;
    if(m.updated) mh += `<div class="market-row-item"><div class="market-row-label">${t.market_updated}</div><div class="market-row-val" style="font-size:1rem;color:#888">${obsEsc(m.updated)}</div></div>`;
    document.getElementById('obs-market-list').innerHTML = mh;
    document.getElementById('obs-last-upd').innerText = t.market_updated + ': ' + (m.updated || '-');

    // News
    function obsEsc(t){return t?String(t).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#039;"):""}
    let newsGrid = document.getElementById('obs-news-grid');
    newsGrid.innerHTML = '';
    n.forEach((item, i) => {
        let title = obsEsc(item.title_fa || item.title_en || '');
        let summary = '';
        if(Array.isArray(item.summary)) {
            summary = '<ul class="news-summary-list">' + item.summary.map(s => `<li>${obsEsc(s)}</li>`).join('') + '</ul>';
        } else {
            summary = obsEsc(item.summary || '');
        }
        let date = new Date(item.timestamp * 1000);
        let timeStr = obsEsc(date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}));
        let sentimentColor = item.sentiment > 0 ? '#4caf50' : (item.sentiment < 0 ? '#f44336' : '#9e9e9e');
        let aiLabel = curLang == 'fa' ? 'تحلیل هوش مصنوعی' : 'AI Analysis';
        let readMore = curLang == 'fa' ? 'بیشتر بخوانید &larr;' : 'Read More &rarr;';
        let impact = item.impact ? `<div class="news-impact"><strong>${aiLabel}</strong>${obsEsc(item.impact)}</div>` : '';
        // Validate URL — only allow http/https
        let safeUrl = (item.url && /^https?:\/\//.test(item.url)) ? item.url : '#';

        let card = document.createElement('div');
        card.className = 'news-card-lg';
        card.onclick = () => window.open(safeUrl, '_blank', 'noopener,noreferrer');
        card.innerHTML = `<div class="news-card-body">
            <div class="news-card-meta"><span class="news-tag">${obsEsc(item.tag)}</span> <span style="display:flex;align-items:center"><span class="sentiment-dot" style="background:${sentimentColor}"></span> ${obsEsc(item.source)}</span></div>
            <div class="news-card-title">${title}</div>
            <div class="news-card-summary">${summary}</div>
            ${impact}
        </div>
        <div class="news-card-footer">
            <span>${timeStr}</span>
            <span>${readMore}</span>
        </div>`;
        newsGrid.appendChild(card);
    });
}

async function reqObservatory() {
    if(confirm("Request access to the Observatory?")) {
        await fetch('?action=request_observatory', {method:'POST', headers:{'X-CSRF-Token': CSRF_TOKEN}});
        loadObservatory();
    }
}

function updateListDOM(id, list, renderer) {
    let c = document.getElementById(id);
    if(!c) return;
    let loader = c.querySelector('.tab-loader');
    if(loader) loader.remove();
    
    let map = new Map();
    Array.from(c.children).forEach(el => { if(el.dataset.key) map.set(el.dataset.key, el); });
    
    list.forEach((item, i) => {
        let el = map.get(String(item.key));
        if(el) {
            renderer(el, item, true);
            map.delete(String(item.key));
        } else {
            el = document.createElement('div');
            el.className = 'list-item';
            el.dataset.key = item.key;
            renderer(el, item, false);
        }
        if(c.children[i] !== el) {
            if(i < c.children.length) c.insertBefore(el, c.children[i]);
            else c.appendChild(el);
        }
    });
    map.forEach(el => el.remove());
}

function renderDmItem(el, d, isUpdate) {
    let isActive = S.id == d.key && S.type == (d.type||'dm');
    
    el.onclick = () => openChat(d.type||'dm', d.key);
    el.oncontextmenu = (e) => onChatListContext(e, d.type||'dm', d.key);

    if(!isUpdate) {
        el.onclick = () => openChat(d.type||'dm', d.key);
        el.oncontextmenu = (e) => onChatListContext(e, 'dm', d.key);
        el.innerHTML = `<div class="avatar"></div>
                        <div style="flex:1">
                            <div style="font-weight:bold;display:flex;align-items:center" class="chat-list-title"></div>
                            <div style="font-size:0.8em;color:#888;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" class="chat-list-last"></div>
                        </div>`;
    }

    if(el.classList.contains('active') !== isActive) el.classList.toggle('active', isActive);

    let avatarEl = el.querySelector('.avatar');
    let newAv = d.av ? `url('${d.av}')` : '';
    if (avatarEl.style.backgroundImage !== newAv) avatarEl.style.backgroundImage = newAv;
    let avatarText = d.av ? '' : d.u[0].toUpperCase();
    if (avatarEl.innerText !== avatarText) avatarEl.innerText = avatarText;
    if(d.isPublic) {
        avatarEl.innerHTML = '<svg viewBox="0 0 24 24" width="24" height="24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/></svg>';
        avatarEl.style.backgroundImage = 'none';
    } else if(d.key === ME) {
        avatarEl.innerHTML = '<svg viewBox="0 0 24 24" width="24" height="24" fill="currentColor"><path d="M19.35 10.04C18.67 6.59 15.64 4 12 4 9.11 4 6.6 5.64 5.35 8.04 2.34 8.36 0 10.91 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96z"/></svg>';
        avatarEl.style.backgroundImage = 'none';
    } else {
        let newAv = d.av ? `url('${d.av}')` : '';
        if (avatarEl.style.backgroundImage !== newAv) avatarEl.style.backgroundImage = newAv;
        let avatarText = d.av ? '' : d.u[0].toUpperCase();
        if (avatarEl.innerText !== avatarText) avatarEl.innerText = avatarText;
    }

    let titleEl = el.querySelector('.chat-list-title');
    let countHtml = d.onlineCount !== undefined ? `<span style="font-size:0.75rem;background:rgba(128,128,128,0.2);color:var(--text);padding:1px 6px;border-radius:10px;margin-left:8px;border:1px solid var(--border)">${d.onlineCount}</span>` : '';
    let titleHTML = `${esc(d.u)}${countHtml} ${d.lock} ${d.ou?'<span style="color:#0f0;font-size:0.8em;margin-left:4px">●</span>':''}`;
    if (titleEl.innerHTML !== titleHTML) titleEl.innerHTML = titleHTML;

    let lastEl = el.querySelector('.chat-list-last');
    if (lastEl.innerText !== d.last) {
        if(isUpdate && lastEl.innerText) {
            lastEl.style.transition = 'opacity 0.2s';
            lastEl.style.opacity = '0';
            setTimeout(()=>{ lastEl.innerText = d.last; lastEl.style.opacity = '1'; }, 200);
        } else {
            lastEl.innerText = d.last;
        }
    }
}

function renderGroupItem(el, item, isUpdate) {
    let g = item.g;
    let isChan = g.category === 'channel';
    let isActive = S.id == g.id && S.type == (isChan ? 'channel' : 'group');
    let t = isChan ? 'channel' : 'group';
    
    el.onclick = () => openChat(t, g.id);
    el.oncontextmenu = (e) => onChatListContext(e, t, g.id);

    if(!isUpdate) {
        let t = isChan ? 'channel' : 'group';
        el.onclick = () => openChat(t, g.id);
        el.oncontextmenu = (e) => onChatListContext(e, t, g.id);
        el.innerHTML = `<div class="avatar"></div>
                        <div>
                            <div style="font-weight:bold;display:flex;align-items:center" class="chat-list-title"></div>
                            <div style="font-size:0.8em;color:#888" class="chat-list-subtitle"></div>
                        </div>`;
    }

    if(el.classList.contains('active') !== isActive) el.classList.toggle('active', isActive);

    let avatarEl = el.querySelector('.avatar');
    let avatarHTML = isChan?'📢':'#';
    if (avatarEl.innerHTML !== avatarHTML) avatarEl.innerHTML = avatarHTML;

    let titleEl = el.querySelector('.chat-list-title');
    let lock = S.e2ee[g.id] ? '<svg viewBox="0 0 24 24" width="14" style="vertical-align:middle;margin-left:4px;fill:var(--accent)"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-9-2c0-1.66 1.34-3 3-3s3 1.34 3 3v2H9V6zm9 14H6V10h12v10zm-6-3c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2z"/></svg>' : '';
    let titleHTML = `${esc(g.name)} ${lock}`;
    if (titleEl.innerHTML !== titleHTML) titleEl.innerHTML = titleHTML;

    let subtitleEl = el.querySelector('.chat-list-subtitle');
    if (subtitleEl.innerText !== g.type) subtitleEl.innerText = g.type;
}


async function renderLists(){
    try {
        const t = TR[curLang] || TR['en'];
        let chatFilter = document.getElementById('chat-search').value.toLowerCase();
        let groupFilter = document.getElementById('group-search') ? document.getElementById('group-search').value.toLowerCase() : '';
        let channelFilter = document.getElementById('channel-search') ? document.getElementById('channel-search').value.toLowerCase() : '';
        
        let keys = (await dbOp('readonly', s => s.getAllKeys())) || [];
        let dms = [];
        
        // Public Chat Injection
        let pubH = await get('public', 'global');
        let pubLast = pubH.length ? pubH[pubH.length-1] : null;
        let pubMsg = t.start_chat;
        if(pubLast && pubLast.message) {
             if(pubLast.type === 'image') pubMsg = '📷 Image';
             if(pubLast.type === 'media_group') pubMsg = '🖼️ Photos';
             else if(pubLast.type === 'audio') pubMsg = '🎤 Voice Message';
             else if(pubLast.type === 'file') pubMsg = '📁 File';
             else if(pubLast.type === 'sticker') pubMsg = '💟 Sticker';
             else if(pubLast.type === 'gif') pubMsg = '🎞️ GIF';
             else pubMsg = esc(pubLast.message || '');
        }
        dms.push({key: 'global', u: t.tab_public + ' Chat', last: pubMsg, type: 'public', isPublic: true, ts: pubLast ? pubLast.timestamp : 0, lock: '', onlineCount: S.online.length});

        for(let k of keys){
            if(k.startsWith('mw_dm_')){
                let u = k.split('mw_dm_')[1];
                let displayName = u === ME ? "Saved Messages" : u;
                if(chatFilter && !displayName.toLowerCase().includes(chatFilter)) continue;
                let h = await get('dm', u);
                let lock = S.e2ee[u] ? '<svg viewBox="0 0 24 24" width="14" style="vertical-align:middle;margin-left:4px;fill:var(--accent)"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-9-2c0-1.66 1.34-3 3-3s3 1.34 3 3v2H9V6zm9 14H6V10h12v10zm-6-3c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2z"/></svg>' : '';
                let lastMsg = h.length ? h[h.length-1] : null;
                let last = t.start_chat;
                if(lastMsg) {
                    if(lastMsg.type === 'image') last = '📷 Image';
                    if(lastMsg.type === 'media_group') last = '🖼️ Photos';
                    else if(lastMsg.type === 'video') last = '📹 Video';
                    else if(lastMsg.type === 'audio') last = '🎤 Voice Message';
                    else if(lastMsg.type === 'file') last = '📁 File';
                    else if(lastMsg.type === 'sticker') last = '💟 Sticker';
                    else if(lastMsg.type === 'gif') last = '🎞️ GIF';
                    else last = esc(lastMsg.message || '');
                }
                if(last.length>30)last=last.substring(0,30)+'...';
                let ou=S.online.find(x=>x.username==u);
                let prof = S.profiles[u];
                let av = (ou && ou.avatar) ? ou.avatar : (prof ? prof.avatar : '');
                dms.push({key: u, u: displayName, last, av, ou, lock, ts: lastMsg ? lastMsg.timestamp : 0});
            }
        }
        dms.sort((a,b) => {
            if(a.type === 'public') return -1;
            if(b.type === 'public') return 1;
            return b.ts - a.ts;
        });

        updateListDOM('list-chats', dms, renderDmItem);

        let groupsList = [];
        let channelsList = [];
        let groups = [];
        for(let g of Object.values(S.groups)) {
            let type = g.category === 'channel' ? 'channel' : 'group';
            let h = await get(type, g.id);
            let lastMsg = h.length ? h[h.length-1] : null;
            groups.push({g, ts: lastMsg ? lastMsg.timestamp : (g.created_at || 0)});
        }
        groups.sort((a,b) => b.ts - a.ts);
        
        groups.forEach(item => {
            let g = item.g;
            let isChan = g.category === 'channel';
            if(isChan && channelFilter && !g.name.toLowerCase().includes(channelFilter)) return;
            if(!isChan && groupFilter && !g.name.toLowerCase().includes(groupFilter)) return;
            
            item.key = g.id;
            if(isChan) channelsList.push(item); else groupsList.push(item);
        });
        
        updateListDOM('list-groups', groupsList, renderGroupItem);
        updateListDOM('list-channels', channelsList, renderGroupItem);
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
    cancelReply();
    cancelFile();
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
        if(i === ME) {
            tit = "Saved Messages";
            sub = "Cloud Storage";
            document.getElementById('chat-av').innerHTML = '<svg viewBox="0 0 24 24" width="24" height="24" fill="currentColor"><path d="M19.35 10.04C18.67 6.59 15.64 4 12 4 9.11 4 6.6 5.64 5.35 8.04 2.34 8.36 0 10.91 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96z"/></svg>';
            document.getElementById('chat-av').style.backgroundImage = 'none';
        } else {
            let ou=S.online.find(x=>x.username==i);
            let prof = S.profiles[i];
            sub=ou?(ou.bio||'Online'):'Offline'; av=(ou && ou.avatar) ? ou.avatar : (prof ? prof.avatar : '');
            if(av) document.getElementById('chat-av').style.backgroundImage=`url('${av}')`;
            document.getElementById('chat-av').innerText=av?'':i[0];
        }
    } else if(t=='group' || t=='channel') {
        let g = S.groups[i];
        tit=g.name; sub=t=='channel'?'Channel':'Group';
        document.getElementById('chat-av').innerText=t=='channel'?'📢':'#';
        if(t=='channel' && g.owner_id != <?php echo $_SESSION['uid']; ?>) canPost = false;
    } else if(t=='public') {
        tit="Public Chat"; sub="Global Room (5m TTL) - " + S.online.length + " Online";
        document.getElementById('chat-av').innerText='P';
        document.getElementById('chat-av').innerHTML = '<svg viewBox="0 0 24 24" width="24" height="24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/></svg>';
        document.getElementById('chat-av').style.backgroundImage = 'none';
    }
    document.getElementById('chat-title').innerText=tit;
    document.getElementById('chat-sub').innerText=sub;
    document.getElementById('btn-call').style.display = (t=='dm') ? 'flex' : 'none';
    document.getElementById('input-box').style.visibility = canPost ? 'visible' : 'hidden';
    toggleMainBtn();
    if(window.innerWidth > 850) setTimeout(()=>document.getElementById('txt').focus(), 50);
    
    updateE2EEUI();
    
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
    div.className=`msg ${m.from_user==ME?'out':'in'} ${m.pinned?'pinned':''} ${m.type=='sticker'?'msg-sticker':''}`;
    let sender='';
    if(showSender) sender=`<div class="msg-sender" onclick="if(ME!=='${esc(jsEsc(m.from_user))}'){openChat('dm','${esc(jsEsc(m.from_user))}');switchTab('chats');}">${esc(m.from_user)}</div>`;

    let safeHtmlMsg = esc(m.message);
    let txt;
    if(m.type=='image') txt=`<img src="${safeHtmlMsg}" loading="lazy" onclick="openLightbox(this.src)" onload="scrollToBottom(false)">`;
    else if(m.type=='media_group') {
        let images=[];
        try { images=JSON.parse(m.message); } catch(e){}
        let count = images.length;
        let gridCls = count<=1?'count-1':count===2?'count-2':count===3?'count-3':count===4?'count-4':'count-5up';
        let maxShow = count<=4 ? count : 4;
        let imgHtml='';
        for(let gi=0;gi<maxShow;gi++){
            let gsrc=esc(images[gi]);
            if(gi<maxShow-1 || count<=maxShow){
                imgHtml+=`<div class="media-grid-item"><img src="${gsrc}" loading="lazy" onclick="openLightbox(this.src)" onload="scrollToBottom(false)"></div>`;
            } else {
                let extra=count-maxShow;
                imgHtml+=`<div class="media-grid-item"><img src="${gsrc}" loading="lazy" style="filter:brightness(0.35)"><div class="media-grid-more">+${extra+1}</div></div>`;
            }
        }
        txt=`<div class="media-grid ${gridCls}">${imgHtml}</div>`;
    }
    else if(m.type=='video') txt=`<div class="vid-poster" id="vid-poster-${m.timestamp}" style="position:relative;max-width:100%;min-width:200px;height:150px;background:#000;border-radius:8px;display:flex;align-items:center;justify-content:center;cursor:pointer"><div class="play-btn" style="width:48px;height:48px;font-size:24px;padding-left:4px">▶</div></div>`;
    else if(m.type=='audio') {
        let isVoice = !m.extra_data;
        let extra = '';
        if(!isVoice) {
             let safeNameJs = esc(jsEsc(m.extra_data || 'audio'));
             let safeMsgJs = esc(jsEsc(m.message));
             extra = `<div style="display:flex;gap:2px;margin-left:5px"><button class="btn-icon" style="width:28px;height:28px;padding:0;color:inherit;background:none" onclick="downloadFile('${safeMsgJs}', '${safeNameJs}')" title="Download"><svg viewBox="0 0 24 24" width="18" fill="currentColor"><path d="M19 9h-4V3H9v6H5l7 7 7-7zM5 18v2h14v-2H5z"/></svg></button><button class="btn-icon" style="width:28px;height:28px;padding:0;color:inherit;background:none" onclick="shareFile('${safeMsgJs}', '${safeNameJs}')" title="Share"><svg viewBox="0 0 24 24" width="18" fill="currentColor"><path d="M18 16.08c-.76 0-1.44.3-1.96.77L8.91 12.7c.05-.23.09-.46.09-.7s-.04-.47-.09-.7l7.05-4.11c.54.5 1.25.81 2.04.81 1.66 0 3-1.34 3-3s-1.34-3-3-3-3 1.34-3 3c0 .24.04.47.09.7L8.04 9.81C7.5 9.31 6.79 9 6 9c-1.66 0-3 1.34-3 3s1.34 3 3 3c.79 0 1.5-.31 2.04-.81l7.12 4.16c-.05.21-.08.43-.08.65 0 1.61 1.31 2.92 2.92 2.92 1.61 0 2.92-1.31 2.92-2.92s-1.31-2.92-2.92-2.92z"/></svg></button></div>`;
        }
        txt=`<div class="audio-player" ${!isVoice?'style="padding:8px;background:rgba(0,0,0,0.2);border-radius:8px"':''}>
            <button class="play-btn" onclick="playAudio(this)">
                <svg viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg>
            </button>
            <div class="audio-progress" onclick="seekAudio(this, event)"><div class="audio-bar"></div></div>
            <div class="audio-time">0:00</div>
            ${extra}
            <audio src="${safeHtmlMsg}" style="display:none" onloadedmetadata="this.parentElement.querySelector('.audio-time').innerText=formatTime(this.duration)"></audio>
        </div>${!isVoice ? `<div style="font-size:0.75rem;opacity:0.8;margin-top:4px;margin-left:4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:220px">🎵 ${esc(m.extra_data)}</div>` : ''}`;
    }
    else if(m.type=='sticker') txt=`<img src="${safeHtmlMsg}" loading="lazy" style="width:128px;height:128px;object-fit:contain">`;
    else if(m.type=='gif') txt=`<video class="gif-video" autoplay loop muted playsinline style="max-width:100%;border-radius:8px;cursor:pointer"></video>`;
    else if(m.type=='file') {
        let fname = esc(m.extra_data || 'file');
        let safeNameJs = esc(jsEsc(m.extra_data || 'file'));
        let safeMsgJs = esc(jsEsc(m.message));
        txt = `<div class="file-att" onclick="downloadFile('${safeMsgJs}', '${safeNameJs}')">
            <svg viewBox="0 0 24 24" width="24" fill="currentColor"><path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>
            <span>${fname}</span></div>`;
    }
    else if(m.type=='location') {
        let coords = esc(m.message);
        txt = `<a href="https://www.google.com/maps?q=${coords}" target="_blank" style="text-decoration:none;color:var(--accent);display:flex;align-items:center;gap:5px;background:rgba(0,0,0,0.2);padding:8px;border-radius:5px;margin-top:5px">
            <svg viewBox="0 0 24 24" width="20" fill="currentColor"><path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5c-1.38 0-2.5-1.12-2.5-2.5s1.12-2.5 2.5-2.5 2.5 1.12 2.5 2.5-1.12 2.5-2.5 2.5z"/></svg>
            <span>${coords}</span>
        </a>`;
    } else {
        txt = autoLink(esc(m.message));
    }
    
    let rep='';
    if(m.reply_to_id && history){
        let p=history.find(x=>x.timestamp==m.reply_to_id);
        if(p) {

            let rTxt = p.type == 'image' ? '📷 Image' : (p.type == 'media_group' ? '🖼️ Photos' : (p.type == 'audio' ? '🎤 Audio' : (p.type == 'file' ? '📁 File' : (p.type == 'sticker' ? '💟 Sticker' : (p.type == 'gif' ? '🎞️ GIF' : esc(p.message).substring(0, 30) + '...')))));
            rep=`<div style="font-size:0.8em;border-left:2px solid var(--accent);padding-left:4px;margin-bottom:4px;opacity:0.7;cursor:pointer" onclick="scrollToMsg(${m.reply_to_id})">Reply to <b>${esc(p.from_user)}</b>: ${rTxt}</div>`;
        }
    }
    let stat='';
    if(m.from_user==ME && S.type=='dm') stat = m.read ? '<span style="color:#4fc3f7;margin-left:3px">✓✓</span>' : '<span style="margin-left:3px">✓</span>';
    if(m.pending) stat = '<span class="msg-pending-stat" style="color:#888;margin-left:3px">' + (m.progress !== undefined ? m.progress+'%' : '🕒') + '</span>';

    let reactDisplay = '';
    if (m.reacts && Object.keys(m.reacts).length > 0) {
        // Group by emoji and show counts
        let emojiCounts = {};
        for (const user in m.reacts) {
            let emoji = m.reacts[user];
            if (!emojiCounts[emoji]) emojiCounts[emoji] = { count: 0, users: [], myReact: false };
            emojiCounts[emoji].count++;
            emojiCounts[emoji].users.push(user);
            if (user === ME) emojiCounts[emoji].myReact = true;
        }
        reactDisplay = '<div class="reaction-bar" style="position:static;display:flex;flex-wrap:wrap;gap:4px;margin-top:4px;background:none;border:none;padding:0;box-shadow:none">';
        for (const emoji in emojiCounts) {
            let data = emojiCounts[emoji];
            let myClass = data.myReact ? 'active-reaction' : '';
            let title = data.users.slice(0,5).join(', ') + (data.users.length > 5 ? '...' : '');
            reactDisplay += `<span class="reaction ${myClass}" title="${esc(title)}" onclick="sendReact(${m.timestamp}, '${emoji}')" style="cursor:pointer;background:rgba(255,255,255,0.1);border:1px solid rgba(255,255,255,0.1);border-radius:12px;padding:2px 6px;font-size:0.9rem;display:inline-flex;align-items:center;gap:3px">${emoji}<span style="font-size:0.75rem;opacity:0.8">${data.count}</span></span>`;
        }
        reactDisplay += '</div>';
    }

    let editedHtml = m.edited ? '<span style="font-size:0.65rem;font-style:italic;margin-right:4px">edited</span>' : '';
    let menuIcon = `<div class="msg-menu-icon" onclick="openMsgMenu(event, ${m.timestamp})">⋮</div>`;
    div.innerHTML=`${sender}${rep}${txt}<div class="msg-meta">${editedHtml}${new Date(+m.timestamp > 9999999999 ? +m.timestamp : +m.timestamp*1000).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})} ${stat}</div>${reactDisplay}${menuIcon}`;
    
    let touchTimer;
    div.addEventListener('touchstart', (e) => {
        if(e.target.closest('.msg-menu-icon')) return;
        if(e.target.tagName === 'A') return; // allow link taps
        touchTimer = setTimeout(() => {
            if(navigator.vibrate) navigator.vibrate(30);
            toggleSelection(m.timestamp);
        }, 500);
    }, {passive: true});
    div.addEventListener('touchend', () => clearTimeout(touchTimer));
    div.addEventListener('touchcancel', () => clearTimeout(touchTimer));
    div.addEventListener('touchmove', () => clearTimeout(touchTimer));

    div.oncontextmenu=(e)=>{
        e.preventDefault();
        clearTimeout(touchTimer);
        if(selectedMsgs.size > 0) return;
        showContextMenu(e, 'message', m);
    };

    div.onclick=(e)=>{
        if (window.justFinishedDrag) return;
        if(selectedMsgs.size > 0) {
            if(!e.target.closest('.msg-menu-icon')) {
                toggleSelection(m.timestamp);
            }
        }
    };
    div.ondblclick=()=>{ 
        if(m.reacts && m.reacts[ME] === '❤️') sendReact(m.timestamp, null);
        else sendReact(m.timestamp, '❤️'); 
    };

    if(m.type=='video') {
        let ph = div.querySelector(`#vid-poster-${m.timestamp}`);
        if(ph) {
            ph.onclick = async (e) => {
                if(selectedMsgs.size > 0) return;
                e.stopPropagation();
                ph.innerHTML = '<div class="rail-dot" style="background:#fff"></div>';
                let v = document.createElement('video');
                v.controls = true;
                v.style.maxWidth = '100%';
                v.style.borderRadius = '8px';
                v.autoplay = true;
                await setSafeVideoSrc(v, m.message);
                ph.replaceWith(v);
            };
        }
    }
    if(m.type=='gif') {
        let v = div.querySelector('.gif-video');
        if(v) {
            v.onclick = function() {
                if(this.paused) { this.play(); delete this.dataset.paused; }
                else { this.pause(); this.dataset.paused = "true"; }
            };
            setSafeVideoSrc(v, m.message);
        }
    }
    return div;
}

async function renderChat(){
    clearSelection();
    let h = await get(S.type,S.id);
    let c = document.getElementById('msgs');
    if(!c) return;
    updatePinnedBanner();
    
    c.querySelectorAll('video').forEach(v => {
        if(v.src && v.src.startsWith('blob:')) URL.revokeObjectURL(v.src);
    });
    
    c.innerHTML='';
    let last=null, lastDate=null;
    h.forEach(m=>{
        let d = new Date(+m.timestamp > 9999999999 ? +m.timestamp : +m.timestamp*1000);
        let dateStr = d.toLocaleDateString();
        if(dateStr !== lastDate) {
            let sep = document.createElement('div');
            sep.style.cssText = "text-align:center;font-size:0.8rem;color:#666;margin:10px 0;position:sticky;top:0;z-index:5;";
            sep.innerHTML = `<span style="background:var(--panel);padding:4px 10px;border-radius:10px;border:1px solid var(--border)">${dateStr}</span>`;
            c.appendChild(sep);
            lastDate = dateStr;
            last = null;
        }
        let show=(S.type=='public'||S.type=='group'||S.type=='channel') && m.from_user!=ME && m.from_user!=last;
        c.appendChild(createMsgNode(m, show, h));
        last=m.from_user;
    });
}

function closeChat() {
    clearSelection();
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
    let inputEl = document.getElementById('txt');
    let txt=inputEl.value.trim();
    if(pendingImages.length > 0 && document.getElementById('multi-attach-ui').style.display !== 'none') {
        sendMediaGroup();
    } else if(pendingFile && document.getElementById('file-preview-ui').style.display !== 'none') {
        sendFile(pendingFile);
        cancelFile();
    }
    if(!txt)return;
    addToRecentEmojis(txt);
    
    // Optimistic UI
    inputEl.value=''; 
    document.getElementById('txt').style.height='40px'; toggleMainBtn();
    if(navigator.vibrate) navigator.vibrate(20);
    
    if(S.editMsgId) {
        let editId = S.editMsgId;
        S.editMsgId = null;
        cancelReply();
        
        let h = await get(S.type, S.id);
        let m = h.find(x => x.timestamp == editId);
        if(m) {
            m.message = txt;
            m.edited = true;
            await save(S.type, S.id, h);
            let el = document.getElementById('msg-' + editId);
            if(el) el.replaceWith(createMsgNode(m, el.querySelector('.msg-sender') !== null, h));
        }
        
        let load = { message: txt, type: 'edit', extra: editId, timestamp: Date.now() };
        if(S.type=='dm') load.to_user=S.id; else if(S.type=='group'||S.type=='channel') load.group_id=S.id; else if(S.type=='public') load.group_id=-1;
        
        if(S.e2ee[S.id] && (S.type=='dm'||S.type=='group')) {
            try {
                let innerPayload = JSON.stringify({ _mw_enc: true, type: 'edit', msg: txt, extra: editId });
                let e = await enc(S.type, S.id, innerPayload);
                load.message=e.c; load.extra=e.extra; load.type='enc';
            } catch(e) { console.error('Encryption failed for edit', e); }
        }
        req('send', load);
        return;
    }
    
    let replyId = S.reply;
    cancelReply();
    
    let ts = Date.now();
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

    if(S.e2ee[S.id] && (S.type == 'dm' || S.type == 'group')){
        try {
            let innerPayload = JSON.stringify({ _mw_enc: true, type: 'text', msg: txt, extra: null });
            let e=await enc(S.type, S.id, innerPayload);
            load.message=e.c; load.extra=e.extra; load.type='enc';
        } catch(e){ console.error("Encryption failed, sending plain", e); }
    }

    try {
        let r = await req('send', load);
        let d = await r.json();
        if(d.status === 'success') {
            let h = await get(S.type, S.id);
            let m = h.find(x => x.timestamp == ts && x.message == txt);
            if(m) { 
                delete m.pending; 
                let old_ts = m.timestamp;
                if (d.timestamp) m.timestamp = d.timestamp;
                h.sort((a,b)=>a.timestamp-b.timestamp);
                await save(S.type, S.id, h); 
                let el = document.getElementById('msg-' + old_ts);
                if (el) {
                    el.id = 'msg-' + m.timestamp;
                    el.replaceWith(createMsgNode(m, el.querySelector('.msg-sender') !== null, h));
                }
            }
        }
    } catch(e) { console.error(e); }
}

// --- SELECTION LOGIC ---
let selectedMsgs = new Set();
function toggleSelection(ts) {
    if (selectedMsgs.has(ts)) {
        selectedMsgs.delete(ts);
        let el = document.getElementById('msg-'+ts);
        if(el) el.classList.remove('selected');
    } else {
        selectedMsgs.add(ts);
        let el = document.getElementById('msg-'+ts);
        if(el) el.classList.add('selected');
    }
    updateSelectionBar();
}
function clearSelection() {
    selectedMsgs.forEach(ts => {
        let el = document.getElementById('msg-'+ts);
        if(el) el.classList.remove('selected');
    });
    selectedMsgs.clear();
    updateSelectionBar();
}
function updateSelectionBar() {
    let bar = document.getElementById('selection-bar');
    if (selectedMsgs.size > 0) {
        bar.style.display = 'flex';
        document.getElementById('sel-count').innerText = selectedMsgs.size + ' Selected';
        let copyBtn = document.getElementById('sel-copy-btn');
        if(copyBtn) copyBtn.style.display = selectedMsgs.size === 1 ? 'flex' : 'none';
    } else {
        bar.style.display = 'none';
    }
}
async function copySelected() {
    if(selectedMsgs.size === 1) {
        let ts = Array.from(selectedMsgs)[0];
        let h = await get(S.type, S.id);
        let m = h.find(x => x.timestamp == ts);
        if(m && m.type == 'text') {
            navigator.clipboard.writeText(m.message);
            showToast('Copied to clipboard');
        } else {
            showToast('Only text can be copied');
        }
    }
    clearSelection();
}
function deleteSelected() {
    let cbHtml = `<label style="display:flex;align-items:center;gap:10px;cursor:pointer;margin-top:15px"><input type="checkbox" id="del-everyone" checked> Delete for everyone</label>`;
    confirmModal("Delete Messages", `Are you sure you want to delete ${selectedMsgs.size} message(s)?${cbHtml}`, async (confirmed) => {
        if(!confirmed) return;
        let delEveryone = document.getElementById('del-everyone') ? document.getElementById('del-everyone').checked : false;
        let h = await get(S.type, S.id);
        for(let ts of selectedMsgs) {
            let m = h.find(x => x.timestamp == ts);
            if(m) {
                if(delEveryone && m.from_user == ME) {
                    let ld={message:'DEL', type:'delete', extra:ts};
                    if(S.type=='dm')ld.to_user=S.id; else if(S.type=='group'||S.type=='channel') ld.group_id=S.id; else if(S.type=='public') ld.group_id=-1;
                    req('send', ld);
                }
                await removeMsg(S.type, S.id, ts);
            }
        }
        clearSelection();
    });
}

window.openMsgMenu = async function(e, ts) {
    e.stopPropagation();
    let h = await get(S.type, S.id);
    let m = h.find(x => x.timestamp == ts);
    if(m) showContextMenu(e, 'message', m);
}

// --- CONTEXT MENU ---
function showContextMenu(e, type, data) {
    const t = TR[curLang];
    e.preventDefault();
    S.ctx = {type, data};
    let menu = document.getElementById('ctx-menu');
    let html = '';
    
    if(type == 'message') {
        let myReact = (data.reacts && data.reacts[ME]) ? data.reacts[ME] : null;
        let isMine = data.from_user === ME;
        let isText = data.type === 'text';
        html = `<div class="ctx-reactions">
        <span class="ctx-reaction ${myReact=='❤️'?'active-reaction':''}" onclick="ctxAction('react','❤️')">❤️</span>
        <span class="ctx-reaction ${myReact=='😂'?'active-reaction':''}" onclick="ctxAction('react','😂')">😂</span>
        <span class="ctx-reaction ${myReact=='😮'?'active-reaction':''}" onclick="ctxAction('react','😮')">😮</span>
        <span class="ctx-reaction ${myReact=='😢'?'active-reaction':''}" onclick="ctxAction('react','😢')">😢</span>
        <span class="ctx-reaction ${myReact=='👍'?'active-reaction':''}" onclick="ctxAction('react','👍')">👍</span>
        </div>
        <div class="ctx-item" onclick="ctxAction('reply')">Reply</div>
        ${isMine && isText ? `<div class="ctx-item" onclick="ctxAction('edit')">Edit</div>` : ''}
        <div class="ctx-item" onclick="ctxAction('select')">Select</div>
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
    
    let x = e.clientX !== undefined ? e.clientX : (e.touches && e.touches[0] ? e.touches[0].clientX : window.innerWidth / 2);
    let y = e.clientY !== undefined ? e.clientY : (e.touches && e.touches[0] ? e.touches[0].clientY : window.innerHeight / 2);
    if(e.type === 'click' && e.target.classList.contains('msg-menu-icon')) {
        let rect = e.target.getBoundingClientRect();
        x = rect.left; y = rect.bottom;
    }
    menu.style.visibility = 'hidden';
    menu.style.display = 'block';
    
    let mw = menu.offsetWidth, mh = menu.offsetHeight;
    if (x + mw > window.innerWidth) x = Math.max(0, x - mw);
    if (y + mh > window.innerHeight) y = Math.max(0, y - mh);
    
    menu.style.left = x + 'px';
    menu.style.top = y + 'px';
    menu.style.visibility = 'visible';
    if(navigator.vibrate) navigator.vibrate(30);
}

function onChatListContext(e, type, id) { showContextMenu(e, 'chat_list', {type, id}); }

async function ctxAction(act, arg) {
    document.getElementById('ctx-menu').style.display='none';
    let c = S.ctx;
    if(!c) return;
    
    if(c.type == 'message') {
        let m = c.data;
        if(act=='react') {
            let myReact = (m.reacts && m.reacts[ME]) ? m.reacts[ME] : null;
            if(myReact === arg) await sendReact(m.timestamp, null);
            else await sendReact(m.timestamp, arg);
        }
        else if(act=='reply') { S.reply=m.timestamp; document.getElementById('reply-ui').style.display='flex'; let snip=m.type=='text'?esc(m.message).substring(0,30):'['+m.type+']'; document.getElementById('reply-txt').innerHTML=`<div style="font-size:0.75rem;color:var(--accent);margin-bottom:2px">Replying to ${esc(m.from_user)}</div><div style="color:var(--text);opacity:0.9;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${snip}</div>`; document.getElementById('del-btn').style.display='none'; document.getElementById('txt').focus(); }
        else if(act=='edit') {
            S.editMsgId = m.timestamp;
            document.getElementById('reply-ui').style.display='flex';
            document.getElementById('reply-txt').innerHTML=`<div style="font-size:0.75rem;color:var(--accent);margin-bottom:2px">Editing message</div><div style="color:var(--text);opacity:0.9;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(m.message).substring(0,30)}</div>`;
            document.getElementById('del-btn').style.display='none';
            document.getElementById('txt').value = m.message;
            document.getElementById('txt').focus();
            toggleMainBtn();
        }
        else if(act=='select') { toggleSelection(m.timestamp); }
        else if(act=='forward') promptModal("Forward", "Username:", u=>{ if(u) req('send',{message:m.message,type:m.type,extra:m.extra_data,to_user:u}); });
        else if(act=='copy') { if(m.type=='text') { navigator.clipboard.writeText(m.message); showToast('Copied to clipboard'); } }
        else if(act=='pin') {
            let h=await get(S.type,S.id);
            let t=h.find(x=>x.timestamp==m.timestamp);
            if(t){
                t.pinned=!t.pinned; await save(S.type,S.id,h);
                let el = document.getElementById('msg-' + m.timestamp);
                if (el) el.replaceWith(createMsgNode(t, el.querySelector('.msg-sender') !== null, h));
                updatePinnedBanner();
            }
        }
      else if(act=='details') alertModal("Details", `From: ${m.from_user}<br>Sent: ${new Date(+m.timestamp > 9999999999 ? +m.timestamp : +m.timestamp*1000).toLocaleString()}`);
        else if(act=='delete') { if(m.from_user!=ME)return; S.reply=m.timestamp; await deleteMsg(); }
    } else if(c.type == 'chat_list') {
        let d = c.data;
        if(act=='open') { openChat(d.type, d.id); switchTab((d.type=='dm'||d.type=='public')?'chats':(d.type=='channel'?'channels':'groups')); }
        else if(act=='clear') { if(confirm("Clear history?")) { await save(d.type, d.id, []); if(S.id==d.id) renderChat(); renderLists(); } }
        else if(act=='del_chat') { if(confirm("Delete chat?")) { await dbOp('readwrite', s=>s.delete(`mw_${d.type}_${d.id}`)); if(S.id==d.id) closeChat(); renderLists(); } }
    } else {
        if(act=='theme') toggleTheme();
        else if(act=='settings') switchTab('settings');
        else if(act=='about') switchTab('about');
    }
}

async function viewReactionUser(e, user) {
    e.stopPropagation();
    let p = S.profiles[user];
    if(!p) {
        let r = await fetch('?action=get_profile&u='+user);
        p = await r.json();
        if(p.status!='error') S.profiles[user] = p;
    }
    if(!p || !p.username) return;
    
    let html = `<div style="display:flex;align-items:center;gap:15px">
        <div class="avatar" style="width:50px;height:50px;font-size:1.5rem;background-image:url('${esc(p.avatar||'')}')">${p.avatar?'':esc(p.username[0])}</div>
        <div>
            <div style="font-weight:bold;font-size:1.1rem">${esc(p.username)}</div>
            <div style="color:#888;font-size:0.9rem">${esc(p.bio||'No bio')}</div>
        </div>
    </div>
    <div style="font-size:0.8rem;color:#666;margin-top:5px">
        Joined: ${new Date(p.joined_at*1000).toLocaleDateString()}<br>
        Last Seen: ${new Date(p.last_seen*1000).toLocaleString()}
    </div>`;
    
    let pop = document.getElementById('user-popup');
    pop.innerHTML = html;
    pop.style.display = 'flex';
    
    if(window.innerWidth > 850) {
        let rect = e.target.getBoundingClientRect();
        let popH = pop.offsetHeight;
        let popW = pop.offsetWidth;
        
        let top = rect.top - popH - 10;
        if(top < 10) top = rect.bottom + 10;
        
        let left = rect.left;
        if(left + popW > window.innerWidth - 20) left = window.innerWidth - popW - 20;
        
        pop.style.top = top + 'px';
        pop.style.left = left + 'px';
    } else {
        pop.style.top = ''; pop.style.left = '';
    }
}

async function sendReact(ts,e){
    let ld={message:(e||''),type:'react',extra:ts};
    if(S.type=='dm')ld.to_user=S.id; else if(S.type=='group'||S.type=='channel') ld.group_id=S.id; else if(S.type=='public') ld.group_id=-1;
    req('send', ld);
    let h = await get(S.type,S.id);
    let m=h.find(x=>x.timestamp==ts);
    if(m){ 
        if(!m.reacts)m.reacts={}; 
        if(e===null) delete m.reacts[ME];
        else m.reacts[ME]=e; 
        await save(S.type,S.id,h); 
        let el = document.getElementById('msg-' + ts);
        if (el) el.replaceWith(createMsgNode(m, el.querySelector('.msg-sender') !== null, h));
    }
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
    let lines = h.map(m => {
        let d = new Date(+m.timestamp > 9999999999 ? +m.timestamp : +m.timestamp*1000);
        let timeStr = d.toLocaleString();
        let content = m.type === 'text' ? m.message : '[' + m.type + ']';
        return `[${timeStr}] ${m.from_user}: ${content}`;
    });
    let blob = new Blob([lines.join('\n')], {type : 'text/plain'});
    let a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `chat_${S.id}_${Date.now()}.txt`;
    a.click(); toggleMenu();
}

// --- MESSAGE SEARCH ---
function toggleMsgSearch() {
    let bar = document.getElementById('msg-search-bar');
    if (bar.classList.contains('active')) {
        bar.classList.remove('active');
        bar.style.display = 'none';
        document.getElementById('msg-search-input').value = '';
        clearSearchHighlights();
    } else {
        bar.classList.add('active');
        bar.style.display = 'flex';
        setTimeout(() => document.getElementById('msg-search-input').focus(), 50);
    }
}
function clearSearchHighlights() {
    document.querySelectorAll('.msg.msg-highlight').forEach(el => el.classList.remove('msg-highlight'));
    document.getElementById('msg-search-count').innerText = '';
}
function searchMessages(q) {
    clearSearchHighlights();
    if (!q.trim()) return;
    let ql = q.toLowerCase();
    let matches = [];
    document.querySelectorAll('.msg').forEach(el => {
        // Check text content (excluding metadata)
        let meta = el.querySelector('.msg-meta');
        let text = el.innerText;
        if (meta) text = text.replace(meta.innerText, '');
        if (text.toLowerCase().includes(ql)) {
            el.classList.add('msg-highlight');
            matches.push(el);
        }
    });
    document.getElementById('msg-search-count').innerText = matches.length + ' result' + (matches.length !== 1 ? 's' : '');
    if (matches.length > 0) matches[0].scrollIntoView({behavior: 'smooth', block: 'center'});
}

// --- PINNED MESSAGE BANNER ---
let pinnedMsgTs = null;
async function updatePinnedBanner() {
    let h = await get(S.type, S.id);
    let pinned = h.filter(m => m.pinned);
    let banner = document.getElementById('pinned-banner');
    if (pinned.length > 0) {
        let last = pinned[pinned.length - 1];
        pinnedMsgTs = last.timestamp;
        let txt = last.type === 'text' ? last.message : '[' + last.type + ']';
        document.getElementById('pinned-text').innerText = '📌 ' + txt.substring(0, 60);
        banner.style.display = 'flex';
    } else {
        pinnedMsgTs = null;
        banner.style.display = 'none';
    }
}
function scrollToPinned() {
    if (pinnedMsgTs) scrollToMsg(pinnedMsgTs);
}
async function unpinMessage() {
    if (!pinnedMsgTs) return;
    let h = await get(S.type, S.id);
    let m = h.find(x => x.timestamp == pinnedMsgTs);
    if (m) { m.pinned = false; await save(S.type, S.id, h); }
    updatePinnedBanner();
    let el = document.getElementById('msg-' + pinnedMsgTs);
    if (el) el.classList.remove('pinned');
}

// --- BLOCK USER ---
async function blockUser(username, unblock) {
    let r = await req('block_user', {username, unblock: unblock || false});
    let d = await r.json();
    if (d.status === 'success') showToast(unblock ? 'User unblocked' : 'User blocked');
    else showToast(d.message || 'Error');
}

// --- USERNAME CHANGE ---
async function changeUsername() {
    promptModal("Change Username", "New username:", async (newName) => {
        if (!newName) return;
        let r = await req('change_username', {username: newName});
        let d = await r.json();
        if (d.status === 'success') {
            alertModal('Success', 'Username changed to ' + d.username + '. Please re-login.');
            setTimeout(() => { clearLocalStorageOnLogout(); location.href = '?action=logout'; }, 2000);
        } else alertModal('Error', d.message || 'Failed to change username');
    });
}

// --- GROUP INVITE LINK ---
async function copyInviteLink(gid) {
    let r = await req('get_invite_link', {group_id: gid});
    let d = await r.json();
    if (d.status === 'success' && d.join_code) {
        let url = location.origin + location.pathname + '?join=' + d.join_code;
        try {
            await navigator.clipboard.writeText(url);
            showToast('Invite link copied!');
        } catch(e) {
            alertModal('Invite Link', url);
        }
    }
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
    if(window.innerWidth > 850) {
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
    f.value = ''; f.removeAttribute('capture'); f.removeAttribute('accept'); f.removeAttribute('multiple');
    if(type === 'camera') { f.accept = 'image/*'; f.setAttribute('capture', 'environment'); }
    else if(type === 'gallery') { f.accept = 'image/*'; f.multiple = true; }
    f.click();
    document.getElementById('att-menu').style.display='none';
}
function sendLocation() {
    if(!navigator.geolocation) return alertModal('Error', 'Geolocation not supported');
    startProg();
    navigator.geolocation.getCurrentPosition(pos => {
        endProg();
        let coords = `${pos.coords.latitude.toFixed(6)},${pos.coords.longitude.toFixed(6)}`;
        let ts = Date.now();
        let ld = {message: coords, type: 'location', timestamp: ts};
        if(S.type=='dm') ld.to_user=S.id; else if(S.type=='group'||S.type=='channel') ld.group_id=S.id; else ld.group_id=-1;
        
        let handleLocResponse = async (r) => {
            let d = await r.json();
            if(d.status === 'success') {
                let h = await get(S.type, S.id);
                let m = h.find(x => x.timestamp == ts && x.message == coords);
                if(m) {
                    delete m.pending;
                    let old_ts = m.timestamp;
                    if (d.timestamp) m.timestamp = d.timestamp;
                    h.sort((a,b)=>a.timestamp-b.timestamp);
                    await save(S.type, S.id, h);
                    let el = document.getElementById('msg-' + old_ts);
                    if(el) {
                        el.id = 'msg-' + m.timestamp;
                        el.replaceWith(createMsgNode(m, el.querySelector('.msg-sender') !== null, h));
                    }
                }
            }
        };

        if (S.e2ee[S.id] && (S.type == 'dm' || S.type == 'group')) {
            try {
                let innerPayload = JSON.stringify({ _mw_enc: true, type: 'location', msg: coords, extra: null });
                enc(S.type, S.id, innerPayload).then(e => {
                    ld.message = e.c; ld.extra = e.extra; ld.type = 'enc';
                    req('send', ld).then(handleLocResponse);
                }).catch(err => req('send', ld).then(handleLocResponse)); 
            } catch(e) {}
        } else {
            req('send', ld).then(handleLocResponse);
        }
        
        store(S.type,S.id,{from_user:ME,message:coords,type:'location',timestamp:ts, pending:true});
        scrollToBottom(true);
        document.getElementById('att-menu').style.display='none';
    }, err => { endProg(); alertModal('Error', 'Location access denied'); });
}

async function uploadFile(inp){
    let files = Array.from(inp.files);
    if(!files.length) return;
    inp.value = '';
    let imageFiles = files.filter(f => f.type.startsWith('image/') && f.type !== 'image/gif');
    if(files.length > 1 && imageFiles.length > 1) {
        processMultipleImages(imageFiles);
    } else {
        processFile(files[0]);
    }
}

async function processFile(f) {
    document.getElementById('preview-img').style.display = 'none';
    document.getElementById('preview-vid').style.display = 'none';
    document.getElementById('preview-aud').style.display = 'none';
    document.getElementById('file-preview-ui').style.display = 'none';

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
            
            let name = f.name;
            if(!name || name === 'image.png') name = "image_" + Date.now() + ".jpg";
            else if(name.toLowerCase().endsWith('.png')) name = name.replace(/\.png$/i, '.jpg');
            
            pendingFile = new File([blob], name, {type:'image/jpeg'});
            
            // Show Preview
            let pvImg = document.getElementById('preview-img');
            pvImg.src = URL.createObjectURL(pendingFile);
            pvImg.style.display = 'block';
            document.getElementById('preview-info').innerText = `${(pendingFile.size/1024).toFixed(1)} KB`;
            document.getElementById('media-preview').style.display = 'flex';
        } catch(e){ console.log("Compression failed", e); alertModal('Error', 'Image processing failed'); }
        endProg();
    } else if (f.type.startsWith('video/')) {
        pendingFile = f;
        let pvVid = document.getElementById('preview-vid');
        pvVid.src = URL.createObjectURL(f);
        pvVid.style.display = 'block';
        document.getElementById('preview-info').innerText = `${(f.size/1024/1024).toFixed(1)} MB`;
        document.getElementById('media-preview').style.display = 'flex';
    } else if (f.type.startsWith('audio/')) {
        pendingFile = f;
        let pvAud = document.getElementById('preview-aud');
        pvAud.src = URL.createObjectURL(f);
        pvAud.style.display = 'block';
        document.getElementById('preview-info').innerText = `${(f.size/1024).toFixed(1)} KB`;
        document.getElementById('media-preview').style.display = 'flex';
    } else {
        pendingFile = f;
        document.getElementById('file-preview-ui').style.display = 'flex';
        document.getElementById('file-preview-name').innerText = f.name;
        document.getElementById('file-preview-size').innerText = (f.size/1024).toFixed(1) + ' KB';
        toggleMainBtn();
    }
}

document.addEventListener('paste', e => {
    if(!S.id || document.getElementById('app-modal').style.display === 'flex' || document.getElementById('lightbox').style.display === 'flex') return;
    let items = (e.clipboardData || e.originalEvent.clipboardData).items;
    for (let i = 0; i < items.length; i++) {
        if (items[i].kind === 'file') {
            e.preventDefault();
            let blob = items[i].getAsFile();
            if(blob) processFile(blob);
        }
    }
});

let dz = document.getElementById('input-box');
let dzC = 0;
dz.addEventListener('dragenter', e=>{ e.preventDefault(); dzC++; dz.style.boxShadow='inset 0 0 0 2px var(--accent)'; });
dz.addEventListener('dragover', e=>{ e.preventDefault(); });
dz.addEventListener('dragleave', e=>{ e.preventDefault(); dzC--; if(dzC===0)dz.style.boxShadow='none'; });
dz.addEventListener('drop', e=>{ 
    e.preventDefault(); dzC=0; dz.style.boxShadow='none';
    if(e.dataTransfer.files.length) processFile(e.dataTransfer.files[0]);
});

function sendPreview() {
    if(pendingFile) sendFile(pendingFile);
    closePreview();
}

function closePreview() {
    document.getElementById('media-preview').style.display = 'none';
    let img = document.getElementById('preview-img'), vid = document.getElementById('preview-vid'), aud = document.getElementById('preview-aud');
    if(img.src) URL.revokeObjectURL(img.src);
    if(vid.src) URL.revokeObjectURL(vid.src);
    if(aud.src) URL.revokeObjectURL(aud.src);
    img.src = ''; vid.src = ''; aud.src = '';
    vid.pause(); aud.pause();
    pendingFile = null;
}

async function processMultipleImages(files) {
    startProg();
    pendingImages = [];
    for(let f of files) {
        try {
            let img = await new Promise((res,rej)=>{let i=new Image();i.onload=()=>res(i);i.onerror=rej;i.src=URL.createObjectURL(f);});
            let cvs = document.createElement('canvas');
            let w=img.width, h=img.height, max=1600;
            if(w>max||h>max){ if(w>h){h=Math.round(h*max/w);w=max;}else{w=Math.round(w*max/h);h=max;} }
            cvs.width=w; cvs.height=h;
            cvs.getContext('2d').drawImage(img,0,0,w,h);
            let blob = await new Promise(r=>cvs.toBlob(r,'image/jpeg',0.8));
            let name = f.name;
            if(!name||name==='image.png') name='image_'+Date.now()+'.jpg';
            else if(name.toLowerCase().endsWith('.png')) name=name.replace(/\.png$/i,'.jpg');
            let file = new File([blob], name, {type:'image/jpeg'});
            let src = URL.createObjectURL(file);
            pendingImages.push({file, src, name});
        } catch(e){ console.warn('processMultipleImages: failed for file', e); }
    }
    endProg();
    if(pendingImages.length === 0) return;
    if(pendingImages.length === 1) {
        let item = pendingImages[0];
        pendingImages = [];
        let pvImg = document.getElementById('preview-img');
        pvImg.src = item.src;
        pvImg.style.display = 'block';
        pendingFile = item.file;
        document.getElementById('preview-info').innerText = (item.file.size/1024).toFixed(1)+' KB';
        document.getElementById('media-preview').style.display = 'flex';
        return;
    }
    renderMultiAttachPreview();
}

function renderMultiAttachPreview() {
    let container = document.getElementById('multi-attach-scroll');
    container.innerHTML = '';
    pendingImages.forEach((item, i) => {
        let thumb = document.createElement('div');
        thumb.className = 'multi-attach-thumb';
        let img = document.createElement('img');
        img.src = item.src;
        img.style.cursor = 'pointer';
        img.onclick = () => openLightbox(item.src);
        let btn = document.createElement('button');
        btn.className = 'rm-btn';
        btn.innerHTML = '&times;';
        btn.onclick = () => removeMultiAttachImage(i);
        thumb.appendChild(img);
        thumb.appendChild(btn);
        container.appendChild(thumb);
    });
    let countEl = document.getElementById('multi-attach-count');
    countEl.innerText = pendingImages.length + ' photo' + (pendingImages.length > 1 ? 's' : '');
    document.getElementById('multi-attach-ui').style.display = 'flex';
    toggleMainBtn();
}

function removeMultiAttachImage(i) {
    URL.revokeObjectURL(pendingImages[i].src);
    pendingImages.splice(i, 1);
    if(pendingImages.length === 0) {
        cancelMultiAttach();
    } else {
        renderMultiAttachPreview();
    }
}

function cancelMultiAttach() {
    pendingImages.forEach(item => URL.revokeObjectURL(item.src));
    pendingImages = [];
    document.getElementById('multi-attach-ui').style.display = 'none';
    document.getElementById('multi-attach-scroll').innerHTML = '';
    toggleMainBtn();
}

async function sendMediaGroup() {
    if(pendingImages.length === 0) return;
    let images = [...pendingImages];
    cancelMultiAttach();
    startProg();
    let ts = Date.now();
    let replyId = S.reply;
    cancelReply();

    let dataUrls = [];
    let names = [];
    for(let item of images) {
        let dataUrl = await new Promise(r => { let rd = new FileReader(); rd.onload = () => r(rd.result); rd.readAsDataURL(item.file); });
        dataUrls.push(dataUrl);
        names.push(item.name);
    }

    let msgData = JSON.stringify(dataUrls);
    let extraData = JSON.stringify(names);

    let msgObj = {from_user:ME, message:msgData, type:'media_group', timestamp:ts, reply_to_id:replyId, extra_data:extraData, pending:true, progress:0};
    await store(S.type, S.id, msgObj);
    scrollToBottom(true);

    let load = {message:msgData, type:'media_group', extra:extraData, reply_to:replyId, timestamp:ts};
    if(S.type=='dm') load.to_user=S.id;
    else if(S.type=='group'||S.type=='channel') load.group_id=S.id;
    else load.group_id=-1;

    if(S.e2ee[S.id] && (S.type=='dm'||S.type=='group')) {
        try {
            let innerPayload = JSON.stringify({_mw_enc:true, type:'media_group', msg:msgData, extra:extraData});
            let e = await enc(S.type, S.id, innerPayload);
            load.message=e.c; load.extra=e.extra; load.type='enc';
        } catch(e){ console.error('Encryption failed', e); }
    }

    try {
        let r = await req('send', load);
        let d = await r.json();
        if(d.status==='success') {
            let h = await get(S.type, S.id);
            let m = h.find(x => x.timestamp==ts && x.type=='media_group');
            if(m && m.pending) {
                delete m.pending; delete m.progress; 
                let old_ts = m.timestamp;
                if (d.timestamp) m.timestamp = d.timestamp;
                h.sort((a,b)=>a.timestamp-b.timestamp);
                await save(S.type, S.id, h);
                let el = document.getElementById('msg-'+old_ts);
                if(el) {
                    el.id = 'msg-' + m.timestamp;
                    el.replaceWith(createMsgNode(m, el.querySelector('.msg-sender')!==null, h));
                }
            }
        }
    } catch(e){ console.error('sendMediaGroup failed', e); }
    endProg();
}

async function sendFile(fileToSend) {
    startProg();
    let ts = Date.now();
    let replyId = S.reply;
    cancelReply();
    
    // Optimistic Render
    await new Promise((resolve) => {
        let r = new FileReader();
        r.onload = async () => {
            let type = 'file';
            if (fileToSend.type.startsWith('image/')) type = 'image';
            else if (fileToSend.type.startsWith('video/')) type = 'video';
            else if (fileToSend.type.startsWith('audio/')) type = 'audio';
            let dataUrl = r.result;
            await store(S.type,S.id,{from_user:ME,message:dataUrl,type:type,timestamp:ts,extra_data:fileToSend.name, reply_to_id:replyId, pending:true, progress: 0});
            scrollToBottom(true);
            
            if (S.e2ee[S.id] && (S.type == 'dm' || S.type == 'group')) {
                try {
                    let innerPayload = JSON.stringify({ _mw_enc: true, type: type, msg: dataUrl, extra: fileToSend.name });
                    let e = await enc(S.type, S.id, innerPayload);
                    let load = { message: e.c, extra: e.extra, type: 'enc', timestamp: ts };
                    if(replyId) load.reply_to = replyId;
                    if(S.type=='dm') load.to_user=S.id; else if(S.type=='group'||S.type=='channel') load.group_id=S.id; else load.group_id=-1;
                    
                    let xhr = new XMLHttpRequest();
                    xhr.open('POST', '?action=send');
                    xhr.setRequestHeader('Content-Type', 'application/json');
                    xhr.setRequestHeader('X-CSRF-Token', CSRF_TOKEN);
                    
                    xhr.upload.onprogress = (e) => {
                        if (e.lengthComputable) {
                            let pct = Math.round((e.loaded / e.total) * 100);
                            let msgNode = document.getElementById('msg-' + ts);
                            if(msgNode) {
                                let statNode = msgNode.querySelector('.msg-pending-stat');
                                if(statNode) statNode.innerText = pct === 100 ? 'Processing...' : pct + '%';
                                msgNode.dataset.progress = pct;
                            }
                        }
                    };
                    
                    xhr.onload = async () => {
                        endProg();
                        let h = await get(S.type, S.id);
                        let m = h.find(x => x.timestamp == ts && x.extra_data == fileToSend.name);
                        if(xhr.status === 200) {
                            let d;
                            try { d = JSON.parse(xhr.responseText); } catch(err) { d = {status:'error'}; }
                            if(d.status === 'success') {
                                if(m && m.pending) { 
                                    delete m.pending; delete m.progress; 
                                    let old_ts = m.timestamp;
                                    if (d.timestamp) m.timestamp = d.timestamp;
                                    h.sort((a,b)=>a.timestamp-b.timestamp);
                                    await save(S.type, S.id, h); 
                                    let el = document.getElementById('msg-' + old_ts);
                                    if (el) {
                                        el.id = 'msg-' + m.timestamp;
                                        el.replaceWith(createMsgNode(m, el.querySelector('.msg-sender') !== null, h));
                                    }
                                }
                            } else {
                                if(m && m.pending) { alertModal('Error', d.message||'Encrypted upload failed'); let idx = h.indexOf(m); if(idx!=-1) { h.splice(idx, 1); await save(S.type, S.id, h); let el = document.getElementById('msg-' + ts); if(el) el.remove(); } }
                            }
                        } else {
                            if(m && m.pending) { alertModal('Error', 'HTTP '+xhr.status); let idx = h.indexOf(m); if(idx!=-1) { h.splice(idx, 1); await save(S.type, S.id, h); let el = document.getElementById('msg-' + ts); if(el) el.remove(); } }
                        }
                    };
                    xhr.onerror = async () => {
                        endProg();
                        let h = await get(S.type, S.id);
                        let m = h.find(x => x.timestamp == ts && x.extra_data == fileToSend.name);
                        if(m && m.pending) { alertModal('Error', 'Network error during upload'); let idx = h.indexOf(m); if(idx!=-1) { h.splice(idx, 1); await save(S.type, S.id, h); let el = document.getElementById('msg-' + ts); if(el) el.remove(); } }
                    };
                    xhr.send(JSON.stringify(load));
                } catch(err) {
                    endProg();
                    console.error("Encryption failed", err);
                    alertModal('Error', 'File encryption failed. It might be too large for local memory.');
                    let h = await get(S.type, S.id);
                    let m = h.find(x => x.timestamp == ts && x.extra_data == fileToSend.name);
                    if(m && m.pending) { let idx = h.indexOf(m); if(idx!=-1) { h.splice(idx, 1); await save(S.type, S.id, h); let el = document.getElementById('msg-' + ts); if(el) el.remove(); } }
                }
            } else {
                resolve();
            }
        };
        r.readAsDataURL(fileToSend);
    });

            let fd = new FormData();
            fd.append('file', fileToSend);
            fd.append('timestamp', ts);
            if(replyId) fd.append('reply_to', replyId);
            if(S.type=='dm') fd.append('to_user', S.id);
            else if(S.type=='group'||S.type=='channel') fd.append('group_id', S.id);
            else fd.append('group_id', -1);

            try {
                let d = await new Promise((resolve, reject) => {
                    let xhr = new XMLHttpRequest();
                    xhr.open('POST', '?action=upload_msg');
                    xhr.setRequestHeader('X-CSRF-Token', CSRF_TOKEN);
                    
                    xhr.upload.onprogress = (e) => {
                        if (e.lengthComputable) {
                            let pct = Math.round((e.loaded / e.total) * 100);
                            let msgNode = document.getElementById('msg-' + ts);
                            if(msgNode) {
                                let statNode = msgNode.querySelector('.msg-pending-stat');
                                if(statNode) statNode.innerText = pct === 100 ? 'Processing...' : pct + '%';
                                msgNode.dataset.progress = pct;
                            }
                        }
                    };
                    
                    xhr.onload = () => {
                        if(xhr.status === 200) {
                            try { 
                                let text = xhr.responseText;
                                let match = text.match(/\{[\s\S]*\}/);
                                resolve(JSON.parse(match ? match[0] : text)); 
                            } catch(err) { reject(err); }
                        } else reject(new Error('HTTP ' + xhr.status));
                    };
                    xhr.onerror = () => reject(new Error('Network Error'));
                    xhr.send(fd);
                });
                endProg();
                let h = await get(S.type, S.id);
                let m = h.find(x => x.timestamp == ts && x.extra_data == fileToSend.name);
                if(d.status!='success') {
                    if(m && m.pending) {
                        alertModal('Error', d.message||'Upload failed');
                        let idx = h.indexOf(m);
                        if(idx!=-1) { 
                            h.splice(idx, 1); await save(S.type, S.id, h); 
                            let el = document.getElementById('msg-' + ts);
                            if (el) el.remove();
                        }
                    }
                } else {
                    if(m && m.pending) { 
                        delete m.pending; delete m.progress; 
                        let old_ts = m.timestamp;
                        if (d.timestamp) m.timestamp = d.timestamp;
                        h.sort((a,b)=>a.timestamp-b.timestamp);
                        await save(S.type, S.id, h); 
                        let el = document.getElementById('msg-' + old_ts);
                        if (el) {
                            el.id = 'msg-' + m.timestamp;
                            el.replaceWith(createMsgNode(m, el.querySelector('.msg-sender') !== null, h));
                        }
                    }
                }
            } catch(e) {
                endProg();
                console.error(e);
                let h = await get(S.type, S.id);
                let m = h.find(x => x.timestamp == ts && x.extra_data == fileToSend.name);
                if(m && m.pending) {
                    alertModal('Error', 'Upload failed or timed out.');
                    let idx = h.indexOf(m);
                    if(idx!=-1) { 
                        h.splice(idx, 1); await save(S.type, S.id, h); 
                        let el = document.getElementById('msg-' + ts);
                        if (el) el.remove();
                    }
                }
            }
}

async function handleAvUpload(inp) {
    let f = inp.files[0]; if(!f) return;
    startProg();
    try {
        let img = await new Promise((res,rej)=>{let i=new Image();i.onload=()=>res(i);i.onerror=rej;i.src=URL.createObjectURL(f);});
        let cvs = document.createElement('canvas');
        let size = 200; 
        let w=img.width, h=img.height;
        let scale = Math.min(size/w, size/h);
        if(scale < 1) { w*=scale; h*=scale; }
        cvs.width=w; cvs.height=h;
        cvs.getContext('2d').drawImage(img,0,0,w,h);
        let b64 = cvs.toDataURL('image/webp', 0.8);
        document.getElementById('set-av').value = b64;
        document.getElementById('my-av').style.backgroundImage = `url('${b64}')`;
    } catch(e) { console.error(e); alertModal('Error', 'Image processing failed'); }
    endProg();
}

function downloadFile(data, name){
    if(data.trim().toLowerCase().startsWith('javascript:')) { showToast('Invalid file data'); return; }
    let a = document.createElement('a'); a.href = data; a.download = name; a.click();
}

function cancelReply(){ S.reply=null; S.editMsgId=null; document.getElementById('reply-ui').style.display='none'; document.getElementById('del-btn').style.display='none'; }
function cancelFile() {
    pendingFile = null;
    document.getElementById('file-preview-ui').style.display = 'none';
    document.getElementById('file').value = '';
    toggleMainBtn();
}
function promptChat(){ promptModal("New Chat", "Username:", async (u)=>{ 
    if(!u) return;
    if(u.toLowerCase() === 'me') u = ME;
    if(!/^[a-zA-Z0-9_-]+$/.test(u)){ alertModal('Error','Invalid username format'); return; }
    startProg();
    let r = await fetch('?action=get_profile&u='+u);
    endProg();
    let d = await r.json();
    if(d.status=='error'){ alertModal('Error','User not found'); return; }
    let realU = d.username;
    let ex=await get('dm',realU); 
    if(!ex.length) await save('dm',realU,[]); 
    openChat('dm',realU); 
    switchTab('chats'); 
}); }

function createGroup(){ createEntity('group'); }
function createChannel(){ createEntity('channel'); }

function createEntity(type){ 
    let label = type=='channel'?'Channel':'Group';
    alertModal("Create "+label, "");
    document.getElementById('modal-ok').style.display='none';
    document.getElementById('modal-cancel').style.display='block';
    document.getElementById('modal-body').innerHTML = `
        <input id="ng-name" class="form-input" placeholder="${label} Name" autocomplete="off">
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
        <input id="jg-code" class="form-input" placeholder="Invite Code" autocomplete="off">
        <input id="jg-pass" class="form-input" type="password" placeholder="Password (Optional)" autocomplete="new-password">
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

function saveSettings(){
    req('update_profile',{bio:document.getElementById('set-bio').value,avatar:document.getElementById('set-av').value,new_password:document.getElementById('set-pw').value});
    let statusEl = document.getElementById('set-status');
    if (statusEl) req('update_status', {status: statusEl.value});
    alertModal("Settings", "Profile updated.");
}

async function discover(cat){ startProg(); alertModal("Discover "+(cat=='channel'?'Channels':'Groups'), '<div class="tab-loader" style="min-height:150px"><div class="rail-letters"><span>m</span><span>o</span><span>R</span><span>e</span></div><div class="rail-dot"></div></div>'); let r=await fetch('?action=get_discoverable_groups&cat='+encodeURIComponent(cat)); endProg(); let d=await r.json(); let container=document.createElement('div'); container.style.cssText='max-height:300px;overflow-y:auto'; d.items.forEach(g=>{ let row=document.createElement('div'); row.style.cssText='padding:10px;border-bottom:1px solid #333;display:flex;justify-content:space-between;align-items:center'; let info=document.createElement('div'); let nameEl=document.createElement('b'); nameEl.textContent=g.name; let codeEl=document.createElement('span'); codeEl.style.cssText='color:#888;font-size:0.8rem'; codeEl.textContent='Code: '+g.join_code; info.appendChild(nameEl); info.appendChild(document.createElement('br')); info.appendChild(codeEl); let btn=document.createElement('button'); btn.className='btn-sec'; btn.textContent='Join'; let code=g.join_code; btn.onclick=()=>req('join_group',{code:code}).then(r=>r.json()).then(()=>{document.getElementById('app-modal').style.display='none';renderLists()}); row.appendChild(info); row.appendChild(btn); container.appendChild(row); }); let body=document.getElementById('modal-body'); body.innerHTML=''; body.appendChild(container); }

async function showProfilePopup() {
    if(S.type === 'dm') {
        startProg();
        let r = await fetch('?action=get_profile&u='+S.id);
        endProg();
        let p = await r.json();
        if(p.status === 'error') return;
        
        let html = `<div style="text-align:center;margin-bottom:15px">
            <div class="avatar" style="width:80px;height:80px;margin:0 auto 10px auto;font-size:2rem;background-image:url('${esc(p.avatar||'')}')">${p.avatar?'':esc(p.username[0])}</div>
            <b>${esc(p.username)}</b><br>
            <span style="color:#888;font-size:0.8rem">${esc(p.bio||'-')}</span><br>
            ${p.status_text ? `<span style="color:var(--accent);font-size:0.8rem;display:inline-block;margin-top:3px">● ${esc(p.status_text)}</span><br>` : ''}
            <div style="font-size:0.8rem;color:#666;margin-top:5px">
                Joined: ${new Date(p.joined_at*1000).toLocaleDateString()}<br>
                Last Seen: ${new Date(p.last_seen*1000).toLocaleString()}
            </div>
            ${!S.e2ee[S.id] ? `<button class="btn-sec" style="margin-top:15px;width:100%" onclick="startE2EE();document.getElementById('app-modal').style.display='none'">Enable End-to-End Encryption</button>` : `<button class="btn-sec" style="margin-top:15px;width:100%;color:#ff9800;border-color:#ff9800" id="reset-e2ee-btn-popup">Reset E2EE Session</button>`}
            <button class="btn-sec" style="margin-top:10px;width:100%;color:#f55;border-color:#f55" id="block-user-btn-popup">Block User</button>
        </div>`;
        alertModal("Profile", ""); document.getElementById('modal-body').innerHTML = html;
        let blkBtn = document.getElementById('block-user-btn-popup');
        if(blkBtn) { let uid = S.id; blkBtn.onclick = () => { blockUser(uid); document.getElementById('app-modal').style.display='none'; }; }
        let rstE2EEBtn = document.getElementById('reset-e2ee-btn-popup');
        if(rstE2EEBtn) { let uid = S.id; rstE2EEBtn.onclick = () => { resetE2EE(uid); document.getElementById('app-modal').style.display='none'; }; }
    } else if (S.type === 'group' || S.type === 'channel') {
        startProg();
        let r = await fetch('?action=get_group_details&id='+S.id);
        endProg();
        let d = await r.json();
        if(d.status === 'error') return;
        
        let html = `<div style="text-align:center;margin-bottom:15px">
            <b>${esc(d.group.name)}</b><br>
            <span style="color:#888;font-size:0.8rem">${d.group.category=='channel'?'Channel':'Group'} - ${esc(d.group.type)} ${d.group.join_code ? '| Code: '+esc(d.group.join_code) : ''}</span><br>
            ${d.is_owner && d.group.type=='private' ? `<button class="btn-sec" style="font-size:0.7rem;margin-top:5px" onclick="groupSettings(${S.id})">Manage Invite</button>` : ''}
            ${!S.e2ee[S.id] && d.group.category!='channel' ? `<button class="btn-sec" style="margin-top:10px;width:100%" onclick="startWEncrypt();document.getElementById('app-modal').style.display='none'">Enable WEncrypt</button>` : ``}
        </div>
        <div style="max-height:200px;overflow-y:auto;text-align:left;margin-bottom:15px;background:#222;padding:10px;border-radius:8px">
            <div style="font-size:0.8rem;color:#aaa;margin-bottom:5px">Members (${d.members.length})</div>
            ${d.members.map(m=>`<div style="padding:5px;border-bottom:1px solid var(--border);display:flex;align-items:center">
                <div class="avatar" style="width:24px;height:24px;font-size:0.8rem;margin-right:8px;background-image:url('${esc(m.avatar||'')}')">${m.avatar?'':esc(m.username[0])}</div>
                <span>${esc(m.username)}</span> ${m.public_key?'<span title="Key Available" style="color:#0f0;font-size:0.6rem;margin-left:5px">🔑</span>':''}
            </div>`).join('')}
        </div>
        <div style="display:flex;gap:10px;justify-content:center">
            <button class="btn-modal btn-sec" style="color:#f55;border-color:#f55" onclick="leaveGroup(${S.id})">Leave Group</button>
            ${d.is_owner ? `<button class="btn-modal btn-sec" style="color:#f55;border-color:#f55" onclick="nukeGroup(${S.id})">Delete Group</button>` : ''}
            ${d.group.join_code ? `<button class="btn-modal btn-sec" onclick="copyInviteLink(${S.id});document.getElementById('app-modal').style.display='none'">Copy Invite Link</button>` : ''}
        </div>`;

        alertModal("Group Info", "");
        document.getElementById('modal-body').innerHTML = html;
    }
}

function groupSettings(gid){
    alertModal("Group Settings", "");
    document.getElementById('modal-body').innerHTML = `
        <div class="form-group"><label>Enable Joining</label> <input type="checkbox" id="gs-join"></div>
        <div class="form-group"><label>Code Suffix (Letter)</label><input id="gs-suff" class="form-input" maxlength="1" placeholder="A-Z" autocomplete="off"></div>
        <div class="form-group"><label>Password (Optional)</label><input id="gs-pass" class="form-input" type="password" autocomplete="new-password"></div>
        <div class="form-group"><label>Expiry (Minutes)</label><input id="gs-exp" class="form-input" type="number" placeholder="60" autocomplete="off"></div>
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
    let c = document.getElementById('msgs');
    if(!c) return;
    if(force) { c.scrollTop=c.scrollHeight; return; }
    if(c.scrollHeight - c.scrollTop - c.clientHeight < 150) c.scrollTo({ top: c.scrollHeight, behavior: 'smooth' });
}
function esc(t){ return t?String(t).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#039;"):"" }
function jsEsc(t){ return t?String(t).replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r'):"" }
function autoLink(html) {
    // html is already escaped; replace http(s) URLs with clickable links
    return html.replace(/(https?:\/\/[^\s<>"']+)/g, function(url) {
        return '<a href="' + url + '" target="_blank" rel="noopener noreferrer" style="color:var(--accent);word-break:break-all" onclick="event.stopPropagation()">' + url + '</a>';
    });
}

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
                let ts=Date.now();
                let msgObj = {from_user:ME,message:r.result,type:'audio',timestamp:ts, pending: true};
                await store(S.type,S.id,msgObj); 
                scrollToBottom(true);
                
                let load = {message:r.result,type:'audio',timestamp:ts}; 
                if(S.type=='dm')load.to_user=S.id; else if(S.type=='group'||S.type=='channel') load.group_id=S.id; else if(S.type=='public') load.group_id=-1; 

                if (S.e2ee[S.id] && (S.type == 'dm' || S.type == 'group')) {
                    try {
                        let innerPayload = JSON.stringify({ _mw_enc: true, type: 'audio', msg: r.result, extra: null });
                        let e = await enc(S.type, S.id, innerPayload);
                        load.message = e.c; load.extra = e.extra; load.type = 'enc';
                    } catch(err) { console.error("Encryption failed", err); }
                }

                try {
                    let res = await req('send', load);
                    let d = await res.json();
                    if(d.status === 'success') {
                        let h = await get(S.type, S.id);
                        let m = h.find(x => x.timestamp == ts && x.message == r.result);
                        if(m) { 
                            delete m.pending; 
                            let old_ts = m.timestamp;
                            if (d.timestamp) m.timestamp = d.timestamp;
                            h.sort((a,b)=>a.timestamp-b.timestamp);
                            await save(S.type, S.id, h); 
                            let el = document.getElementById('msg-' + old_ts);
                            if (el) {
                                el.id = 'msg-' + m.timestamp;
                                el.replaceWith(createMsgNode(m, el.querySelector('.msg-sender') !== null, h));
                            }
                        }
                    }
                } catch(e) {}
            };
            r.readAsDataURL(b);
        }
    };
    mediaRec.stop();
}

function playAudio(btn) {
    if (selectedMsgs.size > 0) return;
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
    let hasMulti = pendingImages.length > 0 && document.getElementById('multi-attach-ui').style.display !== 'none';
    if (txt || hasMulti || (pendingFile && document.getElementById('file-preview-ui').style.display !== 'none')) send();
    else startRec();
}

function toggleMainBtn() {
    let hasText = document.getElementById('txt').value.trim().length > 0;
    let hasFile = pendingFile !== null && document.getElementById('file-preview-ui').style.display !== 'none';
    let hasMulti = pendingImages.length > 0 && document.getElementById('multi-attach-ui').style.display !== 'none';
    document.getElementById('icon-mic').style.display = (hasText || hasFile || hasMulti) ? 'none' : 'block';
    document.getElementById('icon-send').style.display = (hasText || hasFile || hasMulti) ? 'block' : 'none';
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
    if(!e.target.closest('.user-popup') && !e.target.closest('.reaction')) document.getElementById('user-popup').style.display='none';
    if(!e.target.closest('#att-menu') && !e.target.closest('#btn-att') && document.getElementById('att-menu')) document.getElementById('att-menu').style.display='none';
    if(!e.target.closest('#emoji-drawer') && !e.target.closest('#btn-emoji') && document.getElementById('emoji-drawer')) document.getElementById('emoji-drawer').style.display='none';
};
window.oncontextmenu = (e) => {
    if(e.defaultPrevented) return;
    if(e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.isContentEditable) return;
    showContextMenu(e, 'app', null);
};
window.onkeydown = (e) => {
    if(e.key === 'Escape') {
        let ctx = document.getElementById('ctx-menu');
        if(ctx && ctx.style.display === 'block') { ctx.style.display = 'none'; return; }
        if(selectedMsgs.size > 0) { clearSelection(); return; }
        if(document.getElementById('app-modal').style.display === 'flex') document.getElementById('modal-cancel').click();
        else if(document.getElementById('lightbox').style.display === 'flex') closeLightbox();
        else if(document.getElementById('media-preview').style.display === 'flex') closePreview();
        else if(document.getElementById('main-view').classList.contains('active')) closeChat();
    }
};

let isDraggingToSelect = false;
let dragStartTs = null;
let lastHoveredTs = null;
let hasDragged = false;
let dragStartX = 0, dragStartY = 0;
let dragInitialSelection = new Set();
let currentMouseX = 0, currentMouseY = 0;

document.addEventListener('DOMContentLoaded', () => {
    const msgsContainer = document.getElementById('msgs');
    if (!msgsContainer) return;
    
    msgsContainer.addEventListener('mousedown', (e) => {
        if (e.button !== 0) return; 
        if (e.target.closest('.msg-menu-icon')) return;
        
        let msgEl = e.target.closest('.msg');
        if (msgEl && msgEl.classList.contains('selected')) return;
        
        if (!msgEl) {
            let msgs = Array.from(document.querySelectorAll('.msg'));
            let closest = null;
            let minDist = Infinity;
            msgs.forEach(m => {
                let rect = m.getBoundingClientRect();
                let dist = Math.abs(e.clientY - (rect.top + rect.height/2));
                if (dist < minDist) {
                    minDist = dist;
                    closest = m;
                }
            });
            msgEl = closest;
        }
        
        if (msgEl) {
            isDraggingToSelect = true;
            hasDragged = false;
            dragStartTs = parseInt(msgEl.id.split('-')[1]);
            lastHoveredTs = dragStartTs;
            dragStartX = e.clientX;
            dragStartY = e.clientY;
            dragInitialSelection = new Set(selectedMsgs);
        }
    });

    document.addEventListener('mousemove', (e) => {
        currentMouseX = e.clientX;
        currentMouseY = e.clientY;
        
        if (!isDraggingToSelect) return;
        
        if (!hasDragged) {
            if (Math.abs(e.clientX - dragStartX) > 5 || Math.abs(e.clientY - dragStartY) > 5) {
                hasDragged = true;
                updateDragSelection(dragStartTs, dragStartTs);
            } else {
                return;
            }
        }
        
        let el = document.elementFromPoint(e.clientX, e.clientY);
        let msgEl = el ? el.closest('.msg') : null;
        
        if (!msgEl) {
            let msgs = Array.from(document.querySelectorAll('.msg'));
            let closest = null;
            let minDist = Infinity;
            msgs.forEach(m => {
                let rect = m.getBoundingClientRect();
                let dist = Math.abs(currentMouseY - (rect.top + rect.height/2));
                if (dist < minDist) {
                    minDist = dist;
                    closest = m;
                }
            });
            msgEl = closest;
        }

        if (msgEl) {
            let ts = parseInt(msgEl.id.split('-')[1]);
            if (ts !== lastHoveredTs) {
                updateDragSelection(dragStartTs, ts);
                lastHoveredTs = ts;
            }
        }
    });

    document.addEventListener('mouseup', () => {
        if (isDraggingToSelect) {
            isDraggingToSelect = false;
            if (hasDragged) {
                window.justFinishedDrag = true;
                setTimeout(() => window.justFinishedDrag = false, 50);
            }
        }
    });

    setInterval(() => {
        if (!isDraggingToSelect || !hasDragged) return;
        let c = document.getElementById('msgs');
        if (!c) return;
        let rect = c.getBoundingClientRect();
        let scrollSpeed = 0;
        if (currentMouseY < rect.top + 50) scrollSpeed = -15;
        else if (currentMouseY > rect.bottom - 50) scrollSpeed = 15;
        
        if (scrollSpeed !== 0) {
            c.scrollTop += scrollSpeed;
            
            let el = document.elementFromPoint(currentMouseX, currentMouseY);
            let msgEl = el ? el.closest('.msg') : null;
            if (!msgEl) {
                let msgs = Array.from(document.querySelectorAll('.msg'));
                let closest = null;
                let minDist = Infinity;
                msgs.forEach(m => {
                    let mrect = m.getBoundingClientRect();
                    let dist = Math.abs(currentMouseY - (mrect.top + mrect.height/2));
                    if (dist < minDist) {
                        minDist = dist;
                        closest = m;
                    }
                });
                msgEl = closest;
            }

            if (msgEl) {
                let ts = parseInt(msgEl.id.split('-')[1]);
                if (ts !== lastHoveredTs) {
                    updateDragSelection(dragStartTs, ts);
                    lastHoveredTs = ts;
                }
            }
        }
    }, 30);
});

function updateDragSelection(startTs, endTs) {
    let msgs = Array.from(document.querySelectorAll('.msg'));
    let startIdx = msgs.findIndex(m => m.id === 'msg-' + startTs);
    let endIdx = msgs.findIndex(m => m.id === 'msg-' + endTs);
    if (startIdx === -1 || endIdx === -1) return;
    
    let min = Math.min(startIdx, endIdx);
    let max = Math.max(startIdx, endIdx);
    
    let newSelection = new Set(dragInitialSelection);
    for (let i = min; i <= max; i++) {
        let ts = parseInt(msgs[i].id.split('-')[1]);
        newSelection.add(ts);
    }
    
    document.querySelectorAll('.msg').forEach(el => {
        let ts = parseInt(el.id.split('-')[1]);
        if (newSelection.has(ts)) {
            if (!selectedMsgs.has(ts)) el.classList.add('selected');
        } else {
            if (selectedMsgs.has(ts)) el.classList.remove('selected');
        }
    });
    
    selectedMsgs = newSelection;
    updateSelectionBar();
}

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

// --- WEBRTC CALLING ---
async function startCall() {
    if(callState!='idle') return;
    if(S.type!='dm') return alertModal('Error', 'Calls only available in DMs');
    if(!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) return alertModal('Error', 'Calling not supported (HTTPS required)');
    callPeer = S.id;
    callState = 'outgoing';
    showCallUI('calling');
    await initRTC();
    try {
        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
        sendSignal('offer', JSON.stringify(offer));
    } catch(e) { endCall(); alertModal('Error', 'Call failed to start'); }
}
async function initRTC() {
    try {
        localStream = await navigator.mediaDevices.getUserMedia({video:true, audio:true});
        document.getElementById('local-video').srcObject = localStream;
    } catch(e) { console.error(e); alertModal('Error', 'Camera/Mic access denied'); throw e; }
    
    pc = new RTCPeerConnection(RTC_CFG);
    localStream.getTracks().forEach(track => pc.addTrack(track, localStream));
    pc.ontrack = e => { document.getElementById('remote-video').srcObject = e.streams[0]; };
    pc.onicecandidate = e => { if(e.candidate) sendSignal('candidate', JSON.stringify(e.candidate)); };
    pc.onconnectionstatechange = () => {
        if(pc.connectionState === 'connected') {
            document.getElementById('call-status').innerText = '';
            callState = 'connected';
        } else if(pc.connectionState === 'disconnected' || pc.connectionState === 'failed') endCall(false);
    };
}
async function onSignal(m) {
    let data = {};
    try { if(m.message) data = JSON.parse(m.message); } catch(e) {}
    const type = m.extra_data;
    if(type === 'key_refresh_req') {
        delete S.e2ee[m.from_user];
        localStorage.removeItem('mw_pub_' + m.from_user);
        let success = await ensureE2EE(m.from_user);
        if (success) {
            req('send', {to_user: m.from_user, type: 'signal', extra: 'key_refreshed'});
        }
        if(S.id === m.from_user) updateE2EEUI();
        return;
    } else if (type === 'key_refreshed') {
        showToast(`E2EE keys refreshed automatically.`);
        return;
    }
    if(type === 'offer') {
        if(callState != 'idle') return sendSignal('busy', '', m.from_user);
        callPeer = m.from_user;
        callState = 'incoming';
        S.pendingOffer = data;
        showCallUI('incoming', m.from_user);
        // Ringtone could go here
    } else if (type === 'answer') {
        if(callState == 'outgoing' || callState == 'connecting') {
            await pc.setRemoteDescription(data);
            callState = 'connected';
        }
    } else if (type === 'candidate') {
        if(pc && callState != 'idle') try { await pc.addIceCandidate(data); } catch(e){}
    } else if (type === 'bye') {
        endCall(false);
    } else if (type === 'busy') {
        alertModal('Info', 'User is busy'); endCall(false);
    }
}
async function answerCall() {
    document.getElementById('incoming-ui').style.display='none';
    document.getElementById('in-call-ui').style.display='block';
    await initRTC();
    await pc.setRemoteDescription(S.pendingOffer);
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    sendSignal('answer', JSON.stringify(answer));
    callState = 'connected';
}
function rejectCall() { sendSignal('bye', ''); endCall(false); }
function endCall(notify=true) {
    if(notify && callPeer) sendSignal('bye', '');
    if(pc) { pc.close(); pc = null; }
    if(localStream) { localStream.getTracks().forEach(t=>t.stop()); localStream = null; }
    document.getElementById('call-overlay').style.display='none';
    callState = 'idle'; callPeer = null;
}

async function showNetworkStatus() {
    let online = navigator.onLine ? 'Online' : 'Offline';
    let color = navigator.onLine ? '#4caf50' : '#f44';
    
    let wsyncCount = Object.keys(S.wsync.dc).length;
    let wsyncText = wsyncCount > 0 ? wsyncCount + ' Peer(s)' : 'Idle';
    let wsyncColor = wsyncCount > 0 ? '#4caf50' : '#888';

    let last = lastPollTime ? lastPollTime.toLocaleTimeString() : 'Never';
    
    let html = `
    <div style="padding:10px">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:15px;margin-bottom:20px">
            <div>Internet<br><b style="color:${color};font-size:1.1rem">${online}</b></div>
            <div>WSync<br><b style="color:${wsyncColor};font-size:1.1rem">${wsyncText}</b></div>
        </div>
        <div style="background:rgba(255,255,255,0.05);padding:10px;border-radius:8px;margin-bottom:20px">
            <div style="display:flex;justify-content:space-between;margin-bottom:5px">
                <span style="color:#888">Last Poll:</span>
                <span>${last}</span>
            </div>
            <div style="display:flex;justify-content:space-between">
                <span style="color:#888">Latency:</span>
                <span id="net-latency">-</span>
            </div>
        </div>
        <button class="btn-primary" style="width:100%;padding:12px" onclick="pingServer()">Ping Server</button>
    </div>`;
    alertModal("Network Status", "");
    document.getElementById('modal-body').innerHTML = html;
    document.getElementById('modal-ok').innerText = 'Close';
}
async function pingServer() { let btn = document.querySelector('#modal-body button'); if(btn) { btn.disabled = true; btn.innerText = 'Pinging...'; } let start = Date.now(); try { await fetch('?action=ping'); let lat = Date.now() - start; if(document.getElementById('net-latency')) { let el=document.getElementById('net-latency'); el.innerText = lat + ' ms'; el.style.color = lat < 200 ? '#4caf50' : (lat < 500 ? '#ff9800' : '#f44'); } } catch(e) { if(document.getElementById('net-latency')) document.getElementById('net-latency').innerText = 'Error'; } if(btn) { btn.disabled = false; btn.innerText = 'Ping Server'; } }

function sendSignal(type, data, to) {
    req('send', {to_user: to||callPeer, message: data, type: 'signal', extra: type});
}
function showCallUI(mode, name) {
    document.getElementById('call-overlay').style.display='flex';
    document.getElementById('incoming-ui').style.display = mode=='incoming'?'flex':'none';
    document.getElementById('in-call-ui').style.display = mode=='incoming'?'none':'block';
    if(mode=='incoming') { document.getElementById('call-name').innerText=name; let u=S.online.find(x=>x.username==name); document.getElementById('call-av').style.backgroundImage=u?`url('${u.avatar}')`:''; }
}
function toggleMic(btn) { let t=localStream.getAudioTracks()[0]; t.enabled=!t.enabled; btn.style.background=t.enabled?'rgba(255,255,255,0.2)':'#f44'; }
function toggleCam(btn) { let t=localStream.getVideoTracks()[0]; t.enabled=!t.enabled; btn.style.background=t.enabled?'rgba(255,255,255,0.2)':'#f44'; }

// --- WSYNC (Local Sync) ---
async function sendWSyncSignal(type, data, targetId) {
    let payload = { s: S.deviceId, t: type, d: data };
    if(targetId) payload.tg = targetId;
    req('send', { to_user: ME, type: 'wsync', message: JSON.stringify(payload) });
}

async function handleWSyncMsg(m) {
    if(m.from_user !== ME) return;
    let p; try { p = JSON.parse(m.message); } catch(e){ return; }
    if(p.s === S.deviceId) return;
    if(p.tg && p.tg !== S.deviceId) return;

    let peerId = p.s;
    if(p.t === 'hello') {
        initWSyncPeer(peerId, true);
    } else if(p.t === 'offer') {
        await initWSyncPeer(peerId, false);
        let pc = S.wsync.peers[peerId];
        await pc.setRemoteDescription(p.d);
        let ans = await pc.createAnswer();
        await pc.setLocalDescription(ans);
        sendWSyncSignal('answer', ans, peerId);
    } else if(p.t === 'answer') {
        let pc = S.wsync.peers[peerId];
        if(pc) await pc.setRemoteDescription(p.d);
    } else if(p.t === 'ice') {
        let pc = S.wsync.peers[peerId];
        if(pc) await pc.addIceCandidate(p.d);
    }
}

async function initWSyncPeer(peerId, initiator) {
    if(S.wsync.peers[peerId]) return;
    let pc = new RTCPeerConnection(RTC_CFG);
    S.wsync.peers[peerId] = pc;
    
    pc.onicecandidate = e => { if(e.candidate) sendWSyncSignal('ice', e.candidate, peerId); };
    pc.onconnectionstatechange = () => {
        if(pc.connectionState === 'disconnected' || pc.connectionState === 'failed') {
            delete S.wsync.peers[peerId]; delete S.wsync.dc[peerId];
        }
    };

    if(initiator) {
        let dc = pc.createDataChannel("wsync");
        setupDC(dc, peerId);
        let off = await pc.createOffer();
        await pc.setLocalDescription(off);
        sendWSyncSignal('offer', off, peerId);
    } else {
        pc.ondatachannel = e => setupDC(e.channel, peerId);
    }
}

function setupDC(dc, peerId) {
    S.wsync.dc[peerId] = dc;
    dc.onopen = () => { startSync(peerId); showToast("WSync: Connected"); };
    dc.onmessage = e => handleSyncData(peerId, JSON.parse(e.data));
}

async function startSync(peerId) {
    let summary = { dm: {}, group: {}, channel: {}, public: [] };
    let keys = await dbOp('readonly', s => s.getAllKeys());
    for(let k of keys) {
        if(k.startsWith('mw_dm_')) {
            let u = k.split('mw_dm_')[1];
            let h = await get('dm', u);
            summary.dm[u] = h.slice(-20).map(x => x.timestamp);
        } else if(k.startsWith('mw_group_')) {
            let gid = k.split('mw_group_')[1];
            let h = await get('group', gid);
            summary.group[gid] = h.slice(-20).map(x => x.timestamp);
        } else if(k.startsWith('mw_channel_')) {
            let gid = k.split('mw_channel_')[1];
            let h = await get('channel', gid);
            summary.channel[gid] = h.slice(-20).map(x => x.timestamp);
        } else if(k === 'mw_public_global') {
            let h = await get('public', 'global');
            summary.public = h.slice(-20).map(x => x.timestamp);
        }
    }
    let dc = S.wsync.dc[peerId];
    if(dc && dc.readyState === 'open') dc.send(JSON.stringify({ t: 'summary', d: summary }));
}

async function handleSyncData(peerId, data) {
    if(data.t === 'summary') {
        let missing = { dm: {}, group: {}, channel: {}, public: [] }, reqCount = 0;
        for(let u in data.d.dm) {
            let h = await get('dm', u), myTs = h.map(x => x.timestamp);
            let diff = data.d.dm[u].filter(ts => !myTs.includes(ts));
            if(diff.length) { missing.dm[u] = diff; reqCount += diff.length; }
        }
        for(let gid in data.d.group) {
            let h = await get('group', gid), myTs = h.map(x => x.timestamp);
            let diff = data.d.group[gid].filter(ts => !myTs.includes(ts));
            if(diff.length) { missing.group[gid] = diff; reqCount += diff.length; }
        }
        if(data.d.channel) {
            for(let gid in data.d.channel) {
                let h = await get('channel', gid), myTs = h.map(x => x.timestamp);
                let diff = data.d.channel[gid].filter(ts => !myTs.includes(ts));
                if(diff.length) { missing.channel[gid] = diff; reqCount += diff.length; }
            }
        }
        if(data.d.public) {
            let h = await get('public', 'global'), myTs = h.map(x => x.timestamp);
            let diff = data.d.public.filter(ts => !myTs.includes(ts));
            if(diff.length) { missing.public = diff; reqCount += diff.length; }
        }
        if(reqCount > 0) S.wsync.dc[peerId].send(JSON.stringify({ t: 'req', d: missing }));
    } else if(data.t === 'req') {
        let payload = [];
        for(let u in data.d.dm) { let h = await get('dm', u); h.filter(x => data.d.dm[u].includes(x.timestamp)).forEach(m => payload.push({ cat: 'dm', id: u, m: m })); }
        for(let gid in data.d.group) { let h = await get('group', gid); h.filter(x => data.d.group[gid].includes(x.timestamp)).forEach(m => payload.push({ cat: 'group', id: gid, m: m })); }
        if(data.d.channel) { for(let gid in data.d.channel) { let h = await get('channel', gid); h.filter(x => data.d.channel[gid].includes(x.timestamp)).forEach(m => payload.push({ cat: 'channel', id: gid, m: m })); } }
        if(data.d.public) { let h = await get('public', 'global'); h.filter(x => data.d.public.includes(x.timestamp)).forEach(m => payload.push({ cat: 'public', id: 'global', m: m })); }
        S.wsync.dc[peerId].send(JSON.stringify({ t: 'push', d: payload }));
    } else if(data.t === 'push') {
        for(let item of data.d) await store(item.cat, item.id, item.m);
        if(data.d.length) { showToast(`WSync: Synced ${data.d.length} msgs`); renderLists(); }
    }
}

// --- EMOJI DRAWER ---
const EMOJIS = "😀 😃 😄 😁 😆 😅 😂 🤣 🥲 🥹 ☺️ 😊 😇 🙂 🙃 😉 😌 😍 🥰 😘 😗 😙 😚 😋 😛 😝 😜 🤪 🤨 🧐 🤓 😎 🥸 🤩 🥳 😏 😒 😞 😔 😟 😕 🙁 ☹️ 😣 😖 😫 😩 🥺 😢 😭 😤 😠 😡 🤬 🤯 😳 🥵 🥶 😱 😨 😰 😥 😓 🤗 🤔 🫣 🤭 🫢 🫡 🤫 🫠 🤥 😶 🫥 😐 😑 😬 🙄 😯 😦 😧 😮 😲 🥱 😴 🤤 😪 😵 😵‍💫 🫨 🤐 🥴 🤢 🤮 🤧 😷 🤒 🤕 🤑 🤠 😈 👿 👹 👺 🤡 💩 👻 💀 ☠️ 👽 👾 🤖 🎃 😺 😸 😹 😻 😼 😽 🙀 😿 😾 🫶 👋 🤚 🖐️ ✋ 🖖 👌 🤌 🤏 ✌️ 🤞 🫰 🤟 🤘 🤙 👈 👉 👆 🖕 👇 ☝️ 👍 👎 ✊ 👊 🤛 🤜 👏 🫶 👐 🙌 🫶 🤝 🙏 ✍️ 💅 🤳 💪 🦵 🦶 👂 🦻 👃 🧠 🫀 🫁 🦷 🦴 👀 👁️ 👅 👄 🫦 💋 🩸";
const EMOJI_ARR = EMOJIS.split(' ');
let currentEmojiTab = 'emoji';

let btnEm = document.getElementById('btn-emoji');
let drw = document.getElementById('emoji-drawer');

btnEm.onmouseenter = () => {
    if(window.innerWidth > 850 && !emojiPinned) {
        drw.style.display = 'flex';
        drw.classList.add('popover');
        switchEmojiTab(currentEmojiTab);
    }
};
btnEm.onmouseleave = () => {
    if(window.innerWidth > 850 && !emojiPinned) {
        setTimeout(()=>{ if(!drw.matches(':hover')) { drw.style.display = 'none'; drw.classList.remove('popover'); } }, 100);
    }
};
drw.onmouseleave = () => {
    if(window.innerWidth > 850 && !emojiPinned) {
        drw.style.display = 'none';
        drw.classList.remove('popover');
    }
};

function toggleEmojiDrawer() {
    let d = document.getElementById('emoji-drawer');
    let wasVisible = d.style.display === 'flex';
    document.getElementById('att-menu').style.display = 'none';
    d.style.display = wasVisible ? 'none' : 'flex';
    if(!wasVisible) switchEmojiTab(currentEmojiTab);
    
    if(window.innerWidth > 850) emojiPinned = !wasVisible;
}

function switchEmojiTab(tab) {
    currentEmojiTab = tab;
    document.querySelectorAll('.emoji-tab').forEach(e => e.classList.remove('active'));
    document.getElementById('tab-em-'+tab).classList.add('active');
    let c = document.getElementById('emoji-content');
    
    c.querySelectorAll('video').forEach(v => {
        if(v.src && v.src.startsWith('blob:')) URL.revokeObjectURL(v.src);
    });
    
    c.innerHTML = '';
    c.className = 'emoji-content';
    
    let frag = document.createDocumentFragment();
    
    if(tab === 'emoji') {
        c.classList.add('emoji-grid');
        
        let recent = JSON.parse(localStorage.getItem('mw_recent_emojis') || '[]');
        if(recent.length) {
            let lbl = document.createElement('div');
            lbl.innerText = 'Recent';
            lbl.style.gridColumn = '1 / -1';
            lbl.style.fontSize = '0.75rem';
            lbl.style.color = '#888';
            lbl.style.padding = '4px 0';
            frag.appendChild(lbl);
            recent.forEach(e => {
                let el = document.createElement('div');
                el.className = 'emoji-item';
                el.innerText = e;
                el.onclick = () => insertEmoji(e);
                frag.appendChild(el);
            });
            let sep = document.createElement('div');
            sep.style.gridColumn = '1 / -1';
            sep.style.height = '1px';
            sep.style.background = 'var(--border)';
            sep.style.margin = '8px 0';
            frag.appendChild(sep);
        }

        EMOJI_ARR.forEach(e => {
            if(!e) return;
            let el = document.createElement('div');
            el.className = 'emoji-item';
            el.innerText = e;
            el.onclick = () => insertEmoji(e);
            frag.appendChild(el);
        });
    } else if(tab === 'sticker') {
        c.classList.add('sticker-grid');
        
        let addBtn = document.createElement('div');
        addBtn.className = 'sticker-item sticker-add-btn';
        addBtn.innerHTML = '+';
        addBtn.onclick = () => createSticker();
        frag.appendChild(addBtn);

        S.stickers.forEach(s => {
            let el = document.createElement('img');
            el.className = 'sticker-item';
            el.src = s;
            el.onclick = () => { sendSticker(s, 'sticker'); };
            frag.appendChild(el);
        });
    } else if(tab === 'gif') {
        c.classList.add('gif-grid');
        
        let addBtn = document.createElement('div');
        addBtn.className = 'gif-item sticker-add-btn';
        addBtn.innerHTML = '+';
        addBtn.onclick = () => createGif();
        frag.appendChild(addBtn);

        S.gifs.forEach(url => {
            let el = document.createElement('video');
            el.className = 'gif-item';
            el.autoplay = true;
            el.loop = true;
            el.muted = true;
            el.playsInline = true;
            el.onclick = () => { sendSticker(url, 'gif'); };
            setSafeVideoSrc(el, url);
            frag.appendChild(el);
        });
    }
    c.appendChild(frag);
}

function insertEmoji(char) {
    addToRecentEmojis(char);
    let txt = document.getElementById('txt');
    let start = txt.selectionStart;
    let end = txt.selectionEnd;
    let before = txt.value.substring(0, start);
    let after = txt.value.substring(end);
    txt.value = before + char + after;
    let newPos = start + char.length;
    txt.setSelectionRange(newPos, newPos);
    txt.focus();
    // Trigger resize
    txt.style.height = 'auto';
    txt.style.height = Math.min(txt.scrollHeight, 150) + 'px';
    toggleMainBtn();
}

function addToRecentEmojis(str) {
    if(!str) return;
    try {
        let recent = JSON.parse(localStorage.getItem('mw_recent_emojis') || '[]');
        let matches = str.match(/\p{Emoji_Presentation}/gu);
        if(matches) {
            matches.forEach(e => {
                recent = recent.filter(x => x !== e);
                recent.unshift(e);
            });
            recent = recent.slice(0, 24);
            localStorage.setItem('mw_recent_emojis', JSON.stringify(recent));
        }
    } catch(e) {}
}

function createSticker() {
    let inp = document.createElement('input');
    inp.type = 'file';
    inp.accept = 'image/*';
    inp.onchange = async e => {
        let f = e.target.files[0];
        if(!f) return;
        startProg();
        try {
            let img = await new Promise((res,rej)=>{let i=new Image();i.onload=()=>res(i);i.onerror=rej;i.src=URL.createObjectURL(f);});
            let cvs = document.createElement('canvas');
            cvs.width = 512; cvs.height = 512;
            let ctx = cvs.getContext('2d');
            
            // Center Crop
            let s = Math.min(img.width, img.height);
            let sx = (img.width - s) / 2;
            let sy = (img.height - s) / 2;
            
            ctx.drawImage(img, sx, sy, s, s, 0, 0, 512, 512);
            let b64 = cvs.toDataURL('image/png');
            S.stickers.push(b64);
            await save('custom', 'stickers', S.stickers);
            switchEmojiTab('sticker');
        } catch(e) { alertModal('Error', 'Failed to process image'); }
        endProg();
    };
    inp.click();
}

function createGif() {
    let inp = document.createElement('input');
    inp.type = 'file';
    inp.accept = 'video/*,image/gif';
    inp.onchange = async e => {
        let f = e.target.files[0];
        if(!f) return;
        startProg();
        if(f.type.startsWith('video/')) {
            let v = document.createElement('video');
            v.preload = 'metadata';
            v.onloadedmetadata = async () => {
                if(v.duration > 15) { alertModal('Error', 'Video must be 15 seconds or less'); endProg(); return; }
                let r = new FileReader();
                r.onload = async () => {
                    S.gifs.push(r.result);
                    await save('custom', 'gifs', S.gifs);
                    switchEmojiTab('gif');
                    endProg();
                };
                r.readAsDataURL(f);
            };
            v.src = URL.createObjectURL(f);
        } else {
            // GIF Image
            let r = new FileReader();
            r.onload = async () => {
                S.gifs.push(r.result);
                await save('custom', 'gifs', S.gifs);
                switchEmojiTab('gif');
                endProg();
            };
            r.readAsDataURL(f);
        }
    };
    inp.click();
}

async function sendSticker(content, type='text') {
    let ts = Date.now();
    let msgObj = { from_user: ME, message: content, type: type, timestamp: ts, pending: true };
    await store(S.type, S.id, msgObj);
    scrollToBottom(true);
    
    let load = { message: content, type: type, timestamp: ts };
    if(S.type=='dm') load.to_user=S.id; else if(S.type=='group'||S.type=='channel') load.group_id=S.id; else if(S.type=='public') load.group_id=-1;
    
    if (S.e2ee[S.id] && (S.type == 'dm' || S.type == 'group')) {
        try {
            let innerPayload = JSON.stringify({ _mw_enc: true, type: type, msg: content, extra: null });
            let e = await enc(S.type, S.id, innerPayload);
            load.message = e.c; load.extra = e.extra; load.type = 'enc';
        } catch(err) { console.error("Encryption failed", err); }
    }
    
    try {
        let r = await req('send', load);
        let d = await r.json();
        if(d.status === 'success') {
            let h = await get(S.type, S.id);
            let m = h.find(x => x.timestamp == ts && x.message == content);
            if(m) { 
                delete m.pending; 
                let old_ts = m.timestamp;
                if (d.timestamp) m.timestamp = d.timestamp;
                h.sort((a,b)=>a.timestamp-b.timestamp);
                await save(S.type, S.id, h); 
                let el = document.getElementById('msg-' + old_ts);
                if (el) {
                    el.id = 'msg-' + m.timestamp;
                    el.replaceWith(createMsgNode(m, el.querySelector('.msg-sender') !== null, h));
                }
            }
        }
    } catch(e) {}
}

// Mobile Swipe Back
let tSX=0, tSY=0, isDragging=false;
const mv = document.getElementById('main-view');
mv.addEventListener('touchstart', e => {
    if(window.innerWidth > 850) return;
        if(e.target.closest('#multi-attach-scroll')) return;
    tSX = e.touches[0].clientX; tSY = e.touches[0].clientY;
    isDragging = false; mv.style.transition = 'none';
}, {passive:true});
mv.addEventListener('touchmove', e => {
    if(window.innerWidth > 850 || !mv.classList.contains('active')) return;
        if(e.target.closest('#multi-attach-scroll')) return;
    let dx = e.touches[0].clientX - tSX, dy = e.touches[0].clientY - tSY;
    if(!isDragging && dx > 10 && Math.abs(dy) < Math.abs(dx) * 0.8) isDragging = true;
    if(isDragging) { if(e.cancelable) e.preventDefault(); mv.style.transform = `translateX(${Math.max(0, dx)}px)`; }
}, {passive:false});
mv.addEventListener('touchend', e => {
    if(window.innerWidth > 850) return;
        if(e.target.closest('#multi-attach-scroll')) return;
    mv.style.transition = '';
    if(isDragging) {
        if(e.changedTouches[0].clientX - tSX > 100) { closeChat(); mv.style.transform = ''; }
        else mv.style.transform = '';
        isDragging = false;
    } else mv.style.transform = '';
}, {passive:true});

// Mobile Tab Swipe
const np = document.getElementById('nav-panel');
let tabSwipe = { startX:0, startY:0, current:null, target:null, active:false, width:0 };
const TABS_ORDER = ['chats', 'groups', 'channels', 'observatory', 'settings'];

np.addEventListener('touchstart', e => {
    if(window.innerWidth > 850) return;
    tabSwipe.startX = e.touches[0].clientX;
    tabSwipe.startY = e.touches[0].clientY;
    tabSwipe.active = false;
    tabSwipe.width = np.offsetWidth;
    tabSwipe.current = document.getElementById('tab-'+S.tab);
    tabSwipe.target = null;
    if(tabSwipe.current) tabSwipe.current.style.transition = 'none';
}, {passive:true});

np.addEventListener('touchmove', e => {
    if(window.innerWidth > 850 || !tabSwipe.current) return;
    let dx = e.touches[0].clientX - tabSwipe.startX;
    let dy = e.touches[0].clientY - tabSwipe.startY;
    
    if(!tabSwipe.active) {
        if(Math.abs(dx) > 10 && Math.abs(dx) > Math.abs(dy) * 1.5) {
            tabSwipe.active = true;
            let tabs = TABS_ORDER.filter(t => !LIGHTWEIGHT_MODE || t !== 'observatory');
            let idx = tabs.indexOf(S.tab);
            
            if(dx < 0 && idx < tabs.length - 1) tabSwipe.target = document.getElementById('tab-'+tabs[idx+1]);
            else if(dx > 0 && idx > 0) tabSwipe.target = document.getElementById('tab-'+tabs[idx-1]);
            
            if(tabSwipe.target) {
                tabSwipe.target.style.display = 'flex';
                tabSwipe.target.style.position = 'absolute';
                tabSwipe.target.style.top = '28px';
                tabSwipe.target.style.width = '100%';
                tabSwipe.target.style.height = 'calc(100% - 28px)';
                tabSwipe.target.style.zIndex = '20';
                tabSwipe.target.style.background = 'var(--panel)';
                tabSwipe.target.style.transition = 'none';
                tabSwipe.target.style.transform = `translateX(${dx < 0 ? '100%' : '-100%'})`;
            }
        }
    }
    
    if(tabSwipe.active) {
        if(e.cancelable) e.preventDefault();
        tabSwipe.current.style.transform = `translateX(${dx}px)`;
        if(tabSwipe.target) {
            let start = dx < 0 ? tabSwipe.width : -tabSwipe.width;
            tabSwipe.target.style.transform = `translateX(${start + dx}px)`;
        }
    }
}, {passive:false});

np.addEventListener('touchend', e => {
    if(window.innerWidth > 850 || !tabSwipe.current) return;
    if(tabSwipe.active) {
        let dx = e.changedTouches[0].clientX - tabSwipe.startX;
        let threshold = tabSwipe.width * 0.25;
        let switchAction = tabSwipe.target && Math.abs(dx) > threshold;
        
        requestAnimationFrame(() => {
            tabSwipe.current.style.transition = 'transform 0.2s ease-out';
            if(tabSwipe.target) tabSwipe.target.style.transition = 'transform 0.2s ease-out';
            
            if(switchAction) {
                tabSwipe.current.style.transform = `translateX(${dx < 0 ? '-100%' : '100%'})`;
                tabSwipe.target.style.transform = 'translateX(0)';
                setTimeout(() => {
                    resetTabStyles(tabSwipe.current);
                    resetTabStyles(tabSwipe.target);
                    switchTab(tabSwipe.target.id.replace('tab-', ''));
                }, 200);
            } else {
                tabSwipe.current.style.transform = 'translateX(0)';
                if(tabSwipe.target) {
                    tabSwipe.target.style.transform = `translateX(${dx < 0 ? '100%' : '-100%'})`;
                    setTimeout(() => {
                        tabSwipe.target.style.display = 'none';
                        resetTabStyles(tabSwipe.target);
                    }, 200);
                }
            }
        });
    }
    tabSwipe.active = false;
});

function resetTabStyles(el) {
    if(!el) return;
    el.style.position = ''; el.style.top = ''; el.style.width = ''; el.style.height = '';
    el.style.zIndex = ''; el.style.background = ''; el.style.transform = ''; el.style.transition = '';
}

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

// --- LIGHTBOX LOGIC ---
let lbScale=1, lbX=0, lbY=0, lbIsDragging=false, lbStartX=0, lbStartY=0, lbPinchStartDist=0, lbStartScale=1;
const lbImg = document.getElementById('lb-img');

function openLightbox(src) {
    if (selectedMsgs.size > 0) return;
    document.getElementById('lightbox').style.display = 'flex';
    lbImg.src = src;
    lbScale=1; lbX=0; lbY=0; updateLbTransform();
}
function closeLightbox() {
    document.getElementById('lightbox').style.display = 'none';
    lbImg.src = '';
}
function updateLbTransform() { lbImg.style.transform = `translate(${lbX}px, ${lbY}px) scale(${lbScale})`; }

async function shareImage() {
    if(!lbImg.src) return;
    if(lbImg.src.trim().toLowerCase().startsWith('javascript:')) return;
    if(navigator.share) {
        try {
            let blob = await (await fetch(lbImg.src)).blob();
            let file = new File([blob], "image.png", {type: blob.type});
            if(navigator.canShare && navigator.canShare({files:[file]})) await navigator.share({files:[file]});
            else await navigator.share({url: lbImg.src});
        } catch(e) { showToast("Share failed"); }
    } else showToast("Sharing not supported");
}
function downloadImage() {
    if(lbImg.src.trim().toLowerCase().startsWith('javascript:')) return;
    let a = document.createElement('a');
    a.href = lbImg.src;
    a.download = 'image_' + Date.now();
    a.click();
}

async function shareFile(data, name) {
    if(data.trim().toLowerCase().startsWith('javascript:')) return;
    if(navigator.share) {
        try {
            let blob = await (await fetch(data)).blob();
            let file = new File([blob], name, {type: blob.type});
            if(navigator.canShare && navigator.canShare({files:[file]})) await navigator.share({files:[file]});
            else await navigator.share({url: data});
        } catch(e) { showToast("Share failed"); }
    } else showToast("Sharing not supported");
}

// Zoom & Pan
lbImg.addEventListener('wheel', e => {
    e.preventDefault();
    lbScale *= (e.deltaY > 0 ? 0.9 : 1.1);
    if(lbScale < 1) lbScale = 1;
    updateLbTransform();
});
lbImg.addEventListener('mousedown', e => { lbIsDragging=true; lbStartX=e.clientX-lbX; lbStartY=e.clientY-lbY; });
window.addEventListener('mousemove', e => { if(lbIsDragging){ e.preventDefault(); lbX=e.clientX-lbStartX; lbY=e.clientY-lbStartY; updateLbTransform(); } });
window.addEventListener('mouseup', () => { lbIsDragging=false; });

lbImg.addEventListener('touchstart', e => {
    if(e.touches.length===2) {
        lbPinchStartDist = Math.hypot(e.touches[0].pageX-e.touches[1].pageX, e.touches[0].pageY-e.touches[1].pageY);
        lbStartScale = lbScale;
    } else if(e.touches.length===1) {
        lbIsDragging=true; lbStartX=e.touches[0].pageX-lbX; lbStartY=e.touches[0].pageY-lbY;
    }
});
lbImg.addEventListener('touchmove', e => {
    e.preventDefault();
    if(e.touches.length===2) {
        let dist = Math.hypot(e.touches[0].pageX-e.touches[1].pageX, e.touches[0].pageY-e.touches[1].pageY);
        lbScale = lbStartScale * (dist/lbPinchStartDist);
        if(lbScale < 1) lbScale = 1;
        updateLbTransform();
    } else if(e.touches.length===1 && lbIsDragging) {
        lbX=e.touches[0].pageX-lbStartX; lbY=e.touches[0].pageY-lbStartY; updateLbTransform();
    }
});
lbImg.addEventListener('touchend', () => { lbIsDragging=false; });

if('serviceWorker' in navigator)navigator.serviceWorker.register('?action=sw');
init().catch(e=>console.error(e));

setTimeout(() => sendWSyncSignal('hello'), 2000);

Promise.all([
    new Promise(resolve => document.addEventListener('DOMContentLoaded', resolve)),
    document.fonts.ready
]).then(() => {
    document.body.classList.add('fonts-loaded');
    const splash = document.getElementById('app-splash');
    if (splash) {
        const word = splash.querySelector('.word');
        word.addEventListener('animationend', (e) => {
            if (e.animationName === 'focusOnM') {
                setTimeout(() => {
                    splash.style.opacity = '0';
                    setTimeout(() => { splash.remove(); }, 400);
                }, 250); 
            }
        });
    }
});

</script>
</body>
</html>
