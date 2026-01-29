<?php
session_start();
ini_set('upload_max_filesize', '10M');
ini_set('post_max_size', '10M');

// -------------------------------------------------------------------------
// 1. CONFIGURATION & DATABASE
// -------------------------------------------------------------------------
$dbFile = __DIR__ . '/chat_mw.db';

try {
    $db = new PDO("sqlite:$dbFile");
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

    // Tables
    $db->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        avatar TEXT, 
        joined_at INTEGER,
        last_seen INTEGER
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

} catch (PDOException $e) { die("DB Error: " . $e->getMessage()); }

// -------------------------------------------------------------------------
// 2. BACKEND API
// -------------------------------------------------------------------------
$action = $_GET['action'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    $input = json_decode(file_get_contents('php://input'), true);

    // AUTH
    if ($action === 'register') {
        $user = trim(htmlspecialchars($input['username']));
        $pass = password_hash($input['password'], PASSWORD_DEFAULT);
        try {
            $stmt = $db->prepare("INSERT INTO users (username, password, joined_at, last_seen) VALUES (?, ?, ?, ?)");
            $stmt->execute([$user, $pass, time(), time()]);
            $_SESSION['user'] = $user;
            $_SESSION['uid'] = $db->lastInsertId();
            echo json_encode(['status' => 'success']);
        } catch (PDOException $e) { echo json_encode(['status' => 'error', 'message' => 'Username taken']); }
        exit;
    }
    if ($action === 'login') {
        $stmt = $db->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$input['username']]);
        $row = $stmt->fetch();
        if ($row && password_verify($input['password'], $row['password'])) {
            $_SESSION['user'] = $row['username'];
            $_SESSION['uid'] = $row['id'];
            echo json_encode(['status' => 'success']);
        } else { echo json_encode(['status' => 'error', 'message' => 'Invalid credentials']); }
        exit;
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
        echo json_encode(['status' => 'success']);
        exit;
    }

    // MESSAGING
    if ($action === 'send') {
        $ts = time();
        $reply = $input['reply_to'] ?? null;
        $extra = $input['extra'] ?? null;
        $type = $input['type'] ?? 'text';
        $msg = $input['message'];

        if (isset($input['to_user'])) {
            $stmt = $db->prepare("INSERT INTO messages (from_user, to_user, message, type, reply_to_id, extra_data, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([$me, $input['to_user'], $msg, $type, $reply, $extra, $ts]);
        } else if (isset($input['group_id'])) {
            $stmt = $db->prepare("INSERT INTO messages (group_id, from_user, message, type, reply_to_id, extra_data, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([$input['group_id'], $me, $msg, $type, $reply, $extra, $ts]);
        }
        echo json_encode(['status' => 'success']);
        exit;
    }

    // GROUPS
    if ($action === 'create_group') {
        $code = ($input['type'] === 'public') ? rand(100000, 999999) : null;
        $db->prepare("INSERT INTO groups (name, type, owner_id, join_code, created_at) VALUES (?, ?, ?, ?, ?)")
           ->execute([htmlspecialchars($input['name']), $input['type'], $myId, $code, time()]);
        $gid = $db->lastInsertId();
        $db->prepare("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)")->execute([$gid, $myId]);
        echo json_encode(['status' => 'success']);
        exit;
    }
    if ($action === 'join_group') {
        $row = $db->prepare("SELECT id FROM groups WHERE join_code = ?");
        $row->execute([$input['code']]);
        $grp = $row->fetch();
        if ($grp) {
            try { $db->prepare("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)")->execute([$grp['id'], $myId]); 
            echo json_encode(['status' => 'success']); } catch(Exception $e) { echo json_encode(['status' => 'error', 'message'=>'Joined already']); }
        } else echo json_encode(['status' => 'error', 'message' => 'Invalid code']);
        exit;
    }
}

// POLLING
if ($_SERVER['REQUEST_METHOD'] === 'GET' && $action === 'poll') {
    if (!isset($_SESSION['user'])) { http_response_code(403); exit; }
    $me = $_SESSION['user'];
    $myId = $_SESSION['uid'];

    $db->prepare("UPDATE users SET last_seen = ? WHERE id = ?")->execute([time(), $myId]);

    // Self Profile
    $myProfile = $db->prepare("SELECT username, avatar, joined_at FROM users WHERE id = ?");
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
    $groups = $db->prepare("SELECT g.id, g.name, g.type, g.join_code, gm.last_received_id FROM groups g JOIN group_members gm ON g.id=gm.group_id WHERE gm.user_id=?");
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
    $online = $db->prepare("SELECT username, avatar, last_seen FROM users WHERE last_seen > ?");
    $online->execute([time()-300]);

    echo json_encode(['profile' => $myProfile->fetch(), 'dms' => $dms, 'groups' => $myGroups, 'group_msgs' => $grpMsgs, 'online' => $online->fetchAll()]);
    exit;
}

if ($action === 'logout') { session_destroy(); header("Location: index.php"); exit; }

// -------------------------------------------------------------------------
// FRONTEND
// -------------------------------------------------------------------------
if (!isset($_SESSION['user'])) {
?>
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>moreweb Messenger - Login</title>
<style>
body{background:#121212;color:#eee;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.box{background:#1e1e1e;padding:2rem;border-radius:12px;width:300px;text-align:center;box-shadow:0 10px 30px rgba(0,0,0,0.5)}
input{width:100%;padding:12px;margin:10px 0;background:#2c2c2c;border:1px solid #333;color:#fff;border-radius:6px;box-sizing:border-box}
button{width:100%;padding:12px;background:#00a884;color:#fff;border:none;border-radius:6px;font-weight:bold;cursor:pointer}
</style>
</head>
<body>
<div class="box">
    <h2 id="ttl">moreweb Messenger</h2><div id="err" style="color:#f55;display:none;margin-bottom:10px"></div>
    <input id="u" placeholder="Username"><input type="password" id="p" placeholder="Password">
    <button onclick="sub()">Login</button>
    <p style="color:#888;cursor:pointer;font-size:0.9rem" onclick="reg=!reg;document.getElementById('ttl').innerText=reg?'Register':'Login'">Toggle Login/Register</p>
</div>
<script>
let reg=false;
async function sub(){
    let u=document.getElementById('u').value,p=document.getElementById('p').value;
    let r=await fetch('?action='+(reg?'register':'login'),{method:'POST',body:JSON.stringify({username:u,password:p})});
    let d=await r.json();
    if(d.status=='success')location.reload();else{let e=document.getElementById('err');e.innerText=d.message;e.style.display='block'}
}
</script></body></html>
<?php exit; } ?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>moreweb Messenger</title>
<style>
    :root { --bg:#121212; --rail:#0b0b0b; --panel:#1e1e1e; --border:#2a2a2a; --accent:#00a884; --text:#e0e0e0; --msg-in:#2c2c2c; --msg-out:#005c4b; }
    body { margin:0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; background:var(--bg); color:var(--text); height:100vh; display:flex; overflow:hidden; }
    
    /* Layout */
    .app-container { display:flex; width:100%; height:100%; }
    .nav-rail { width:60px; background:var(--rail); border-right:1px solid var(--border); display:flex; flex-direction:column; align-items:center; padding-top:20px; z-index:10; }
    .rail-btn { width:40px; height:40px; border-radius:10px; display:flex; align-items:center; justify-content:center; margin-bottom:15px; cursor:pointer; color:#888; transition:0.2s; position:relative; }
    .rail-btn:hover { background:rgba(255,255,255,0.1); color:#fff; }
    .rail-btn.active { background:var(--accent); color:#fff; }
    .rail-btn svg { width:24px; height:24px; fill:currentColor; }
    .rail-badge { position:absolute; top:-2px; right:-2px; background:red; border-radius:50%; width:10px; height:10px; display:none; border:2px solid var(--rail); }

    .nav-panel { width:280px; background:var(--panel); border-right:1px solid var(--border); display:flex; flex-direction:column; }
    .panel-header { padding:20px; font-weight:bold; font-size:1.2rem; border-bottom:1px solid var(--border); display:flex; justify-content:space-between; align-items:center; }
    .list-area { flex:1; overflow-y:auto; }
    .list-item { padding:15px; border-bottom:1px solid #252525; display:flex; align-items:center; cursor:pointer; transition:0.2s; }
    .list-item:hover { background:rgba(255,255,255,0.05); }
    .list-item.active { background:#333; }
    .avatar { width:40px; height:40px; border-radius:50%; background:#444; margin-right:12px; display:flex; align-items:center; justify-content:center; font-weight:bold; background-size:cover; flex-shrink:0; }
    
    .main-view { flex:1; display:flex; flex-direction:column; background:#0a0a0a; background-image:radial-gradient(#222 1px, transparent 1px); background-size:20px 20px; position:relative; }
    .chat-header { height:60px; background:var(--panel); border-bottom:1px solid var(--border); display:flex; align-items:center; justify-content:space-between; padding:0 20px; }
    .header-actions { display:flex; gap:15px; position:relative; }
    
    .notif-btn { position:relative; cursor:pointer; color:#bbb; }
    .notif-badge { position:absolute; top:-5px; right:-5px; background:#f44; color:#fff; font-size:0.6rem; padding:1px 4px; border-radius:8px; display:none; }
    .notif-dropdown { position:absolute; top:40px; right:0; width:250px; background:#252525; border:1px solid #444; border-radius:8px; display:none; z-index:100; box-shadow:0 5px 15px rgba(0,0,0,0.5); overflow:hidden; }
    .notif-item { padding:12px; border-bottom:1px solid #333; font-size:0.85rem; cursor:pointer; }
    .notif-item:hover { background:#333; }

    .messages { flex:1; overflow-y:auto; padding:20px; display:flex; flex-direction:column; gap:5px; }
    .msg { max-width:65%; padding:8px 12px; border-radius:8px; font-size:0.95rem; line-height:1.4; position:relative; word-wrap:break-word; }
    .msg.in { align-self:flex-start; background:var(--msg-in); border-top-left-radius:0; }
    .msg.out { align-self:flex-end; background:var(--msg-out); border-top-right-radius:0; }
    .msg img { max-width:100%; border-radius:4px; margin-top:5px; cursor:pointer; }
    .msg-meta { font-size:0.7rem; color:rgba(255,255,255,0.5); text-align:right; margin-top:2px; }
    .reaction-bar { position:absolute; bottom:-12px; right:0; background:#222; border-radius:10px; padding:2px 6px; font-size:0.8rem; box-shadow:0 2px 5px rgba(0,0,0,0.5); cursor:pointer; }
    
    .input-area { padding:15px; background:var(--panel); display:flex; gap:10px; align-items:center; border-top:1px solid var(--border); }
    .input-wrapper { flex:1; position:relative; }
    .reply-ctx { background:#2a2a2a; padding:6px 10px; border-radius:5px 5px 0 0; font-size:0.8rem; color:#aaa; display:none; justify-content:space-between; }
    input[type=text] { width:100%; padding:12px; border-radius:20px; border:none; background:#333; color:#fff; outline:none; box-sizing:border-box; }
    
    .btn-icon { background:none; border:none; color:#888; cursor:pointer; display:flex; align-items:center; justify-content:center; }
    .btn-icon:hover { color:#fff; }
    .btn-primary { background:var(--accent); color:#fff; border:none; padding:8px 16px; border-radius:20px; cursor:pointer; font-weight:bold; }
    
    .settings-panel { padding:20px; text-align:center; }
    .form-group { margin-top:15px; text-align:left; }
    .form-input { width:100%; padding:10px; background:#333; border:1px solid #444; color:#fff; border-radius:4px; margin-top:5px; outline:none; box-sizing:border-box; }
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

    @media (max-width: 768px) {
        .nav-panel { width:calc(100% - 60px); position:absolute; left:60px; height:100%; z-index:5; transition:transform 0.3s; }
        .nav-panel.hidden { display:none; }
        .main-view { width:100%; position:absolute; left:0; height:100%; z-index:8; transform:translateX(100%); transition:transform 0.3s; }
        .main-view.active { transform:translateX(0); }
        .back-btn { display:inline-block; margin-right:10px; font-size:1.5rem; cursor:pointer; }
    }
    @media (min-width: 769px) { .back-btn { display:none; } }
</style>
</head>
<body>

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
        <div class="rail-btn" id="nav-settings" onclick="switchTab('settings')">
            <svg viewBox="0 0 24 24"><path d="M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58a.49.49 0 0 0 .12-.61l-1.92-3.32a.488.488 0 0 0-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54a.484.484 0 0 0-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L3.16 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.09.63-.09.94s.02.64.07.94l-2.03 1.58a.49.49 0 0 0-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z"/></svg>
        </div>
        <div class="rail-btn" id="nav-about" onclick="switchTab('about')">
            <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>
        </div>
        
        <div style="flex:1"></div>
        <div class="rail-btn" onclick="location.href='?action=logout'" title="Logout">
            <svg viewBox="0 0 24 24"><path d="M10.09 15.59L11.5 17l5-5-5-5-1.41 1.41L12.67 11H3v2h9.67l-2.58 2.59zM19 3H5c-1.11 0-2 .9-2 2v4h2V5h14v14H5v-4H3v4c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2z"/></svg>
        </div>
    </div>

    <!-- LIST PANEL -->
    <div class="nav-panel" id="nav-panel">
        <div id="tab-chats" class="tab-content">
            <div class="panel-header">Chats <div class="btn-icon" onclick="promptChat()">+</div></div>
            <div class="list-area" id="list-chats"></div>
        </div>
        <div id="tab-groups" class="tab-content" style="display:none">
            <div class="panel-header">Groups <div class="btn-icon" onclick="createGroup()">+</div></div>
            <div style="padding:10px"><button class="form-input" style="cursor:pointer" onclick="joinGroup()">Join via Code</button></div>
            <div class="list-area" id="list-groups"></div>
        </div>
        <div id="tab-settings" class="tab-content" style="display:none">
            <div class="panel-header">Settings</div>
            <div class="settings-panel">
                <div class="avatar" id="my-av" style="width:80px;height:80px;margin:0 auto;font-size:2rem"></div>
                <h3 id="my-name"></h3>
                <p id="my-date" style="color:#777;font-size:0.8rem"></p>
                <div class="form-group"><label>Avatar URL</label><input class="form-input" id="set-av"></div>
                <div class="form-group"><label>New Password</label><input class="form-input" id="set-pw" type="password"></div>
                <br><button class="btn-primary" onclick="saveSettings()">Save</button>
            </div>
        </div>
        <!-- ABOUT TAB -->
        <div id="tab-about" class="tab-content" style="display:none">
            <div class="panel-header">About</div>
            <div style="padding:20px; text-align:center; color:#ccc;">
                <h2>moreweb Messenger</h2>
                <p style="color:#888;">Version 0.0.1</p>
                <p>A secure, self-contained messenger with ephemeral server storage and local history persistence.</p>
                <br>
                <a href="https://github.com/iWebbIO/php-messenger" target="_blank" class="about-link">
                    <svg viewBox="0 0 24 24" width="24" height="24" fill="currentColor" style="vertical-align:middle"><path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/></svg>
                    GitHub Repository
                </a>
            </div>
        </div>
    </div>

    <!-- MAIN CHAT -->
    <div class="main-view" id="main-view">
        <div class="chat-header">
            <div style="display:flex;align-items:center">
                <div class="back-btn" onclick="closeChat()">&larr;</div>
                <div class="avatar" id="chat-av"></div>
                <div><div id="chat-title" style="font-weight:bold"></div><div id="chat-sub" style="font-size:0.75rem;color:#999"></div></div>
            </div>
            
            <div class="header-actions">
                <button class="btn-icon" id="btn-e2ee" onclick="startE2EE()" title="E2EE" style="display:none">
                    <svg viewBox="0 0 24 24" width="20"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-9-2c0-1.66 1.34-3 3-3s3 1.34 3 3v2H9V6zm9 14H6V10h12v10zm-6-3c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2z"/></svg>
                </button>
                <div class="notif-btn" onclick="toggleNotif()">
                    <svg viewBox="0 0 24 24" width="24" fill="currentColor"><path d="M12 22c1.1 0 2-.9 2-2h-4c0 1.1.9 2 2 2zm6-6v-5c0-3.07-1.63-5.64-4.5-6.32V4c0-.83-.67-1.5-1.5-1.5s-1.5.67-1.5 1.5v.68C7.64 5.36 6 7.92 6 11v5l-2 2v1h16v-1l-2-2zm-2 1H8v-6c0-2.48 1.51-4.5 4-4.5s4 2.02 4 4.5v6z"/></svg>
                    <div class="notif-badge" id="notif-count">0</div>
                    <div class="notif-dropdown" id="notif-list"></div>
                </div>
            </div>
        </div>

        <div class="messages" id="msgs"></div>

        <div class="input-area" id="input-box" style="visibility:hidden">
            <button class="btn-icon" onclick="document.getElementById('file').click()">
                <svg viewBox="0 0 24 24" width="24" fill="currentColor"><path d="M21 19V5c0-1.1-.9-2-2-2H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2zM8.5 13.5l2.5 3.01L14.5 12l4.5 6H5l3.5-4.5z"/></svg>
            </button>
            <input type="file" id="file" hidden accept="image/*" onchange="uploadImg(this)">
            <div class="input-wrapper">
                <div class="reply-ctx" id="reply-ui"><span id="reply-txt"></span><span onclick="cancelReply()" style="cursor:pointer">&times;</span></div>
                <input type="text" id="txt" placeholder="Type a message..." autocomplete="off">
            </div>
            <button class="btn-icon" style="color:var(--accent)" onclick="send()">
                <svg viewBox="0 0 24 24" width="24" fill="currentColor"><path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"/></svg>
            </button>
        </div>
    </div>
</div>

<script>
const ME = "<?php echo $_SESSION['user']; ?>";
let S = { tab:'chats', id:null, type:null, reply:null, dms:{}, groups:{}, online:[], notifs:[], keys:{pub:null,priv:null}, e2ee:{} };

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
    } else {
        bd.style.display = 'block';
        bd.innerText = placeholder; // In alert mode, placeholder is body text
        ip.style.display = 'none';
        cc.style.display = 'none';
    }

    ok.onclick = () => {
        const val = ip.value;
        ov.style.display = 'none';
        if(callback) callback(val);
    };
    cc.onclick = () => { ov.style.display = 'none'; };
    ip.onkeydown = (e) => {
        if(e.key === 'Enter') ok.click();
        if(e.key === 'Escape') cc.click();
    };
}
function promptModal(t, p, cb) { showModal(t, 'prompt', p, cb); }
function alertModal(t, m) { showModal(t, 'alert', m, null); }

// --- INIT ---
async function init(){
    let k=await window.crypto.subtle.generateKey({name:"ECDH",namedCurve:"P-256"},true,["deriveKey"]);
    S.keys.pub=k.publicKey; S.keys.priv=k.privateKey;
    poll(); setInterval(poll,2000);
}

// --- CORE ---
async function poll(){
    try {
        let r=await fetch('?action=poll');
        let d=await r.json();
        S.online=d.online;
        if(d.profile){
            document.getElementById('my-av').style.backgroundImage=`url('${d.profile.avatar}')`;
            document.getElementById('my-name').innerText=d.profile.username;
            document.getElementById('my-date').innerText="Joined: "+new Date(d.profile.joined_at*1000).toLocaleDateString();
        }
        d.dms.forEach(async m=>{
            if(m.type=='signal'){ handleSignal(m); return; }
            if(m.type=='enc'){ try{m.message=await dec(m.from_user,m.message,m.extra_data)}catch(e){m.message="[Encrypted]"} }
            store('dm',m.from_user,m);
            notify(m.from_user, m.message, 'dm');
        });
        S.groups={}; d.groups.forEach(g=>{ S.groups[g.id]=g; if(!get('group',g.id)) save('group',g.id,[]); });
        d.group_msgs.forEach(m=>{ store('group',m.group_id,m); notify(m.group_id, m.message, 'group'); });

        renderLists();
        if(S.id) renderChat();
    } catch(e){}
}

function notify(id, text, type) {
    if(S.type === type && S.id == id) return;
    if(S.notifs.some(n => n.id == id && n.text == text)) return;
    S.notifs.unshift({id, type, text, title: type=='dm'?id:(S.groups[id]?S.groups[id].name:'Group'), time:new Date()});
    updateNotifUI();
    document.getElementById(type=='dm'?'badge-chats':'badge-groups').style.display = 'block';
}

function updateNotifUI() {
    let c = document.getElementById('notif-count');
    c.innerText = S.notifs.length;
    c.style.display = S.notifs.length > 0 ? 'block' : 'none';
    let l = document.getElementById('notif-list');
    let h = S.notifs.length===0 ? '<div style="padding:10px;text-align:center;color:#666">No notifications</div>' : '';
    S.notifs.slice(0,5).forEach((n,i) => {
        h += `<div class="notif-item" onclick="openFromNotif(${i})">
            <b>${n.title}</b><span style="font-size:0.7rem;color:#888;float:right">${n.time.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}</span><br>
            ${n.text.substring(0,30)}...
        </div>`;
    });
    l.innerHTML = h;
}

function openFromNotif(idx) {
    let n = S.notifs[idx];
    S.notifs.splice(idx, 1);
    updateNotifUI();
    toggleNotif(false);
    switchTab(n.type == 'dm' ? 'chats' : 'groups');
    openChat(n.type, n.id);
}

function toggleNotif(force) {
    let el = document.getElementById('notif-list');
    if(force === false) el.style.display='none'; else el.style.display = (el.style.display=='block'?'none':'block');
}

function get(t,i){ let k=`mw_${t}_${i}`; return JSON.parse(localStorage.getItem(k))||[]; }
function save(t,i,d){ localStorage.setItem(`mw_${t}_${i}`,JSON.stringify(d)); }
function store(t,i,m){
    let h=get(t,i);
    if(h.find(x=>x.timestamp==m.timestamp && x.message==m.message)) return;
    if(m.type=='react'){
        let tg=h.find(x=>x.timestamp==m.extra_data);
        if(tg){ if(!tg.reacts)tg.reacts={}; tg.reacts[m.from_user]=m.message; save(t,i,h); }
        return;
    }
    h.push(m); save(t,i,h);
    if(S.id==i && S.type==t) scrollToBottom();
}

async function startE2EE(){
    if(S.type!='dm'||S.e2ee[S.id])return;
    let exp=await window.crypto.subtle.exportKey("jwk",S.keys.pub);
    fetch('?action=send',{method:'POST',body:JSON.stringify({to_user:S.id,message:JSON.stringify(exp),type:'signal'})});
    alertModal("Security", "Key exchange requested.");
}
async function handleSignal(m){
    let fk=await window.crypto.subtle.importKey("jwk",JSON.parse(m.message),{name:"ECDH",namedCurve:"P-256"},true,[]);
    S.e2ee[m.from_user]=await window.crypto.subtle.deriveKey({name:"ECDH",public:fk},S.keys.priv,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
    alertModal("Security", "Secure channel ready with "+m.from_user);
}
async function enc(u,txt){
    let iv=window.crypto.getRandomValues(new Uint8Array(12));
    let buf=await window.crypto.subtle.encrypt({name:"AES-GCM",iv:iv},S.e2ee[u],new TextEncoder().encode(txt));
    return {c:btoa(String.fromCharCode(...new Uint8Array(buf))),i:btoa(String.fromCharCode(...new Uint8Array(iv)))};
}
async function dec(u,c,i){
    let d=await window.crypto.subtle.decrypt({name:"AES-GCM",iv:Uint8Array.from(atob(i),c=>c.charCodeAt(0))},S.e2ee[u],Uint8Array.from(atob(c),c=>c.charCodeAt(0)));
    return new TextDecoder().decode(d);
}

function switchTab(t){
    S.tab=t;
    document.querySelectorAll('.rail-btn').forEach(e=>e.classList.remove('active'));
    document.getElementById('nav-'+t).classList.add('active');
    document.querySelectorAll('.tab-content').forEach(e=>e.style.display='none');
    document.getElementById('tab-'+t).style.display='block';
    if(t=='chats') document.getElementById('badge-chats').style.display='none';
    if(t=='groups') document.getElementById('badge-groups').style.display='none';
    document.getElementById('nav-panel').classList.remove('hidden');
    document.getElementById('main-view').classList.remove('active');
}

function renderLists(){
    let dh='';
    Object.keys(localStorage).forEach(k=>{
        if(k.startsWith('mw_dm_')){
            let u=k.split('mw_dm_')[1];
            let h=JSON.parse(localStorage.getItem(k));
            let last=h.length?h[h.length-1].message:'Start chatting';
            if(last.length>30)last=last.substring(0,30)+'...';
            let ou=S.online.find(x=>x.username==u);
            let av=ou?ou.avatar:'';
            dh+=`<div class="list-item ${S.id==u?'active':''}" onclick="openChat('dm','${u}')">
                <div class="avatar" style="background-image:url('${av}')">${av?'':u[0].toUpperCase()}</div>
                <div style="flex:1"><div style="font-weight:bold">${u} ${ou?'<span style="color:#0f0;font-size:0.8em">●</span>':''}</div><div style="font-size:0.8em;color:#888">${last}</div></div>
            </div>`;
        }
    });
    document.getElementById('list-chats').innerHTML=dh;
    let gh='';
    Object.values(S.groups).forEach(g=>{
        gh+=`<div class="list-item ${S.id==g.id?'active':''}" onclick="openChat('group',${g.id})">
            <div class="avatar">#</div>
            <div><div style="font-weight:bold">${g.name}</div><div style="font-size:0.8em;color:#888">${g.type}</div></div>
        </div>`;
    });
    document.getElementById('list-groups').innerHTML=gh;
}

function openChat(t,i){
    S.type=t; S.id=i;
    renderChat(); scrollToBottom();
    document.getElementById('input-box').style.visibility='visible';
    document.getElementById('main-view').classList.add('active');
    document.getElementById('nav-panel').classList.add('hidden');
    let tit=i, sub='', av='';
    document.getElementById('btn-e2ee').style.display=(t=='dm'?'block':'none');
    if(t=='dm'){
        let ou=S.online.find(x=>x.username==i);
        sub=ou?'Online':'Offline'; av=ou?ou.avatar:'';
        if(av) document.getElementById('chat-av').style.backgroundImage=`url('${av}')`;
        document.getElementById('chat-av').innerText=av?'':i[0];
    } else {
        tit=S.groups[i].name; sub='Group';
        document.getElementById('chat-av').innerText='#';
    }
    document.getElementById('chat-title').innerText=tit;
    document.getElementById('chat-sub').innerText=sub;
}

function renderChat(){
    let c=document.getElementById('msgs'); c.innerHTML='';
    let h=get(S.type,S.id);
    h.forEach(m=>{
        let div=document.createElement('div');
        div.className=`msg ${m.from_user==ME?'out':'in'}`;
        let txt=m.type=='image'?`<img src="${m.message}" onclick="window.open(this.src)">`:esc(m.message);
        let rep='';
        if(m.reply_to_id){
            let p=h.find(x=>x.timestamp==m.reply_to_id);
            if(p) rep=`<div style="font-size:0.8em;border-left:2px solid var(--accent);padding-left:4px;margin-bottom:4px;opacity:0.7">Reply: ${p.type=='image'?'Image':p.message.substring(0,20)}</div>`;
        }
        let reacts='';
        if(m.reacts) reacts=`<div class="reaction-bar">${Object.values(m.reacts).join('')}</div>`;
        div.innerHTML=`${rep}${txt}<div class="msg-meta">${new Date(m.timestamp*1000).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}</div>${reacts}`;
        div.oncontextmenu=(e)=>{e.preventDefault(); S.reply=m.timestamp; document.getElementById('reply-ui').style.display='flex'; document.getElementById('reply-txt').innerText="Replying...";};
        div.ondblclick=()=>{ promptModal('Reaction', 'Enter emoji:', (e) => { if(e) sendReact(m.timestamp,e); }); };
        c.appendChild(div);
    });
}

function closeChat() {
    document.getElementById('main-view').classList.remove('active');
    document.getElementById('nav-panel').classList.remove('hidden');
    S.id=null;
}

async function send(){
    let txt=document.getElementById('txt').value.trim();
    if(!txt)return;
    let load={message:txt, type:'text', reply_to:S.reply};
    if(S.type=='dm' && S.e2ee[S.id]){
        let e=await enc(S.id,txt);
        load.message=e.c; load.extra=e.i; load.type='enc';
    }
    if(S.type=='dm') load.to_user=S.id; else load.group_id=S.id;
    await fetch('?action=send',{method:'POST',body:JSON.stringify(load)});
    store(S.type,S.id,{from_user:ME, message:txt, type:load.type=='enc'?'text':load.type, timestamp:Math.floor(Date.now()/1000), reply_to_id:S.reply});
    document.getElementById('txt').value=''; cancelReply();
}

function sendReact(ts,e){
    let ld={message:e,type:'react',extra:ts};
    if(S.type=='dm')ld.to_user=S.id; else ld.group_id=S.id;
    fetch('?action=send',{method:'POST',body:JSON.stringify(ld)});
    let h=get(S.type,S.id);
    let m=h.find(x=>x.timestamp==ts);
    if(m){ if(!m.reacts)m.reacts={}; m.reacts[ME]=e; save(S.type,S.id,h); renderChat(); }
}

function uploadImg(inp){
    let f=inp.files[0]; let r=new FileReader();
    r.onload=()=>{
        let ld={message:r.result,type:'image'};
        if(S.type=='dm')ld.to_user=S.id; else ld.group_id=S.id;
        fetch('?action=send',{method:'POST',body:JSON.stringify(ld)});
        store(S.type,S.id,{from_user:ME,message:r.result,type:'image',timestamp:Date.now()/1000});
    };
    r.readAsDataURL(f);
}

function cancelReply(){ S.reply=null; document.getElementById('reply-ui').style.display='none'; }
function promptChat(){ promptModal("New Chat", "Username:", (u)=>{ if(u){ if(!get('dm',u).length)save('dm',u,[]); openChat('dm',u); switchTab('chats'); }}); }
function createGroup(){ promptModal("New Group", "Group Name:", (n)=>{ if(n)fetch('?action=create_group',{method:'POST',body:JSON.stringify({name:n,type:'public'})}); }); }
function joinGroup(){ promptModal("Join Group", "6-Digit Code:", (c)=>{ if(c)fetch('?action=join_group',{method:'POST',body:JSON.stringify({code:c})}); }); }
function saveSettings(){ fetch('?action=update_profile',{method:'POST',body:JSON.stringify({avatar:document.getElementById('set-av').value,new_password:document.getElementById('set-pw').value})}); alertModal("Settings", "Profile updated."); }
function scrollToBottom(){ let c=document.getElementById('msgs'); c.scrollTop=c.scrollHeight; }
function esc(t){ return t?t.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"):"" }

document.getElementById('txt').onkeypress=e=>{if(e.key=='Enter')send()};
window.onclick=(e)=>{if(!e.target.closest('.notif-btn'))toggleNotif(false);};

init();
</script>
</body>
</html>