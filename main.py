import os
import json
import time
import sqlite3
import secrets
from flask import Flask, render_template_string, request, session, jsonify, redirect, url_for
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash

# -------------------------------------------------------------------------
# 1. CONFIGURATION
# -------------------------------------------------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change_this_to_something_random')
app.config['DATABASE'] = 'chat_mw.db'
# 10MB limit for websocket messages (for file uploads)
socketio = SocketIO(app, cors_allowed_origins="*", max_http_buffer_size=10 * 1024 * 1024) 

def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute("PRAGMA journal_mode=WAL;")
        db.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            avatar TEXT, 
            joined_at INTEGER,
            last_seen INTEGER,
            typing_to TEXT,
            typing_at INTEGER,
            bio TEXT
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            type TEXT,
            owner_id INTEGER,
            join_code TEXT,
            created_at INTEGER
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS group_members (
            group_id INTEGER,
            user_id INTEGER,
            last_received_id INTEGER DEFAULT 0,
            PRIMARY KEY (group_id, user_id)
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER DEFAULT NULL, 
            from_user TEXT,
            to_user TEXT,
            message TEXT,
            type TEXT DEFAULT 'text',
            reply_to_id INTEGER,
            extra_data TEXT,
            timestamp INTEGER
        )""")
        
        # Indexes
        db.execute("CREATE INDEX IF NOT EXISTS idx_msg_to ON messages(to_user)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_msg_group ON messages(group_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_msg_ts ON messages(timestamp)")
        db.commit()

init_db()

# -------------------------------------------------------------------------
# 2. BACKEND ROUTES (AUTH & STATIC)
# -------------------------------------------------------------------------

@app.route('/')
def index():
    if 'user' not in session:
        return render_template_string(LOGIN_HTML)
    return render_template_string(APP_HTML, username=session['user'], csrf_token=session.get('csrf_token'))

@app.route('/api/auth', methods=['POST'])
def auth():
    data = request.json
    action = request.args.get('action')
    db = get_db()
    
    if action == 'register':
        user = data.get('username', '').strip().lower()
        pwd = data.get('password', '')
        if len(user) > 30 or not user or not pwd:
            return jsonify({'status': 'error', 'message': 'Invalid input'})
        
        hashed = generate_password_hash(pwd)
        try:
            cur = db.cursor()
            cur.execute("INSERT INTO users (username, password, joined_at, last_seen) VALUES (?, ?, ?, ?)", 
                        (user, hashed, int(time.time()), int(time.time())))
            db.commit()
            session['user'] = user
            session['uid'] = cur.lastrowid
            session['csrf_token'] = secrets.token_hex(16)
            return jsonify({'status': 'success'})
        except sqlite3.IntegrityError:
            return jsonify({'status': 'error', 'message': 'Username taken'})

    elif action == 'login':
        user = data.get('username', '').lower()
        cur = db.execute("SELECT * FROM users WHERE lower(username) = ?", (user,))
        row = cur.fetchone()
        if row and check_password_hash(row['password'], data.get('password', '')):
            session['user'] = row['username']
            session['uid'] = row['id']
            session['csrf_token'] = secrets.token_hex(16)
            return jsonify({'status': 'success'})
        return jsonify({'status': 'error', 'message': 'Invalid credentials'})
    
    return jsonify({'status': 'error'})

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# -------------------------------------------------------------------------
# 3. WEBSOCKET EVENTS
# -------------------------------------------------------------------------

@socketio.on('connect')
def handle_connect():
    if 'user' not in session:
        return False # Reject connection
    
    uid = session['uid']
    username = session['user']
    
    # User joins their own room (for DMs) and 'global' (for online status/public chat)
    join_room(f"user_{uid}")
    join_room("public_chat")
    
    # Update status
    with get_db() as db:
        db.execute("UPDATE users SET last_seen = ? WHERE id = ?", (int(time.time()), uid))
        db.commit()
        
        # Load Groups and Join Rooms
        groups = db.execute("SELECT group_id FROM group_members WHERE user_id = ?", (uid,)).fetchall()
        for g in groups:
            join_room(f"group_{g['group_id']}")
    
    # Broadcast online status
    socketio.emit('presence', {'username': username, 'status': 'online'}, include_self=False)
    send_initial_data()

@socketio.on('disconnect')
def handle_disconnect():
    if 'user' in session:
         # In a real app we might want to delay this slightly to handle page refreshes gracefully
         socketio.emit('presence', {'username': session['user'], 'status': 'offline'}, include_self=False)

@socketio.on('get_data')
def send_initial_data():
    if 'user' not in session: return
    uid = session['uid']
    me = session['user']
    db = get_db()
    
    # Profile
    profile = db.execute("SELECT username, avatar, joined_at, bio FROM users WHERE id = ?", (uid,)).fetchone()
    
    # Groups
    groups = db.execute("""
        SELECT g.id, g.name, g.type, g.join_code 
        FROM groups g 
        JOIN group_members gm ON g.id = gm.group_id 
        WHERE gm.user_id = ?
    """, (uid,)).fetchall()
    
    # Fetch Messages logic
    # 1. DMs (simplified: fetch last 50 for active conversations or sync)
    # Note: In a real SocketIO app, we usually fetch history per chat on demand. 
    # To mimic the PHP single-poll behavior, we'll send recent history.
    
    dms = db.execute("SELECT * FROM messages WHERE (to_user = ? OR from_user = ?) AND group_id IS NULL ORDER BY timestamp ASC LIMIT 500", (me, me)).fetchall()
    
    # 2. Group Messages
    grp_msgs = []
    for g in groups:
        msgs = db.execute("SELECT * FROM messages WHERE group_id = ? ORDER BY timestamp DESC LIMIT 50", (g['id'],)).fetchall()
        grp_msgs.extend(msgs[::-1]) # Reverse to chronological
        
    # 3. Public Messages
    pub_msgs = db.execute("SELECT * FROM messages WHERE group_id = -1 ORDER BY timestamp DESC LIMIT 50").fetchall()
    
    # Online Users
    online = db.execute("SELECT username, avatar, last_seen, bio FROM users WHERE last_seen > ?", (int(time.time()) - 300,)).fetchall()

    emit('init_data', {
        'profile': dict(profile),
        'groups': [dict(g) for g in groups],
        'dms': [dict(m) for m in dms],
        'group_msgs': [dict(m) for m in grp_msgs],
        'public_msgs': [dict(m) for m in pub_msgs[::-1]],
        'online': [dict(u) for u in online]
    })

@socketio.on('send_msg')
def handle_message(data):
    if 'user' not in session: return
    
    me = session['user']
    ts = int(time.time())
    msg = data.get('message')
    mtype = data.get('type', 'text')
    reply_to = data.get('reply_to')
    extra = data.get('extra')
    
    if len(msg) > 15000000: return # Limit size
    
    db = get_db()
    
    # Construct payload for broadcast
    payload = {
        'id': None, # Will fill after insert
        'from_user': me,
        'message': msg,
        'type': mtype,
        'reply_to_id': reply_to,
        'extra_data': extra,
        'timestamp': ts,
        'group_id': None,
        'to_user': None
    }

    if 'to_user' in data:
        # Direct Message
        to_user = data['to_user']
        # Get recipient ID
        tgt = db.execute("SELECT id FROM users WHERE username = ?", (to_user,)).fetchone()
        
        cur = db.execute("""INSERT INTO messages (from_user, to_user, message, type, reply_to_id, extra_data, timestamp) 
                            VALUES (?, ?, ?, ?, ?, ?, ?)""", 
                            (me, to_user, msg, mtype, reply_to, extra, ts))
        db.commit()
        payload['id'] = cur.lastrowid
        payload['to_user'] = to_user
        
        # Send to self and recipient
        emit('new_msg', payload) # Ack to sender
        if tgt:
            emit('new_msg', payload, room=f"user_{tgt['id']}")

    elif 'group_id' in data:
        gid = data['group_id']
        cur = db.execute("""INSERT INTO messages (group_id, from_user, message, type, reply_to_id, extra_data, timestamp) 
                            VALUES (?, ?, ?, ?, ?, ?, ?)""", 
                            (gid, me, msg, mtype, reply_to, extra, ts))
        db.commit()
        payload['id'] = cur.lastrowid
        payload['group_id'] = gid
        
        target_room = "public_chat" if gid == -1 else f"group_{gid}"
        emit('new_msg', payload, room=target_room)

@socketio.on('typing')
def handle_typing(data):
    # Relay typing status
    me = session['user']
    to = data.get('to')
    if to:
        # Find user ID
        with get_db() as db:
            row = db.execute("SELECT id FROM users WHERE username = ?", (to,)).fetchone()
            if row:
                emit('user_typing', {'from': me}, room=f"user_{row['id']}")

@socketio.on('create_group')
def create_group(data):
    name = data.get('name')
    uid = session['uid']
    if not name: return
    
    code = secrets.randbelow(899999) + 100000
    with get_db() as db:
        cur = db.execute("INSERT INTO groups (name, type, owner_id, join_code, created_at) VALUES (?, ?, ?, ?, ?)",
                         (name, 'public', uid, code, int(time.time())))
        gid = cur.lastrowid
        db.execute("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", (gid, uid))
        db.commit()
        
        join_room(f"group_{gid}")
        # Send update to creator
        emit('group_joined', {'id': gid, 'name': name, 'type': 'public', 'join_code': code})

@socketio.on('join_group')
def join_group(data):
    code = data.get('code')
    uid = session['uid']
    
    with get_db() as db:
        grp = db.execute("SELECT * FROM groups WHERE join_code = ?", (code,)).fetchone()
        if grp:
            try:
                db.execute("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", (grp['id'], uid))
                db.commit()
                join_room(f"group_{grp['id']}")
                emit('group_joined', {'id': grp['id'], 'name': grp['name'], 'type': grp['type'], 'join_code': grp['join_code']})
            except sqlite3.IntegrityError:
                pass # Already joined

@socketio.on('update_profile')
def update_profile(data):
    uid = session['uid']
    with get_db() as db:
        if 'avatar' in data:
            db.execute("UPDATE users SET avatar = ? WHERE id = ?", (data['avatar'], uid))
        if 'bio' in data:
            db.execute("UPDATE users SET bio = ? WHERE id = ?", (data['bio'], uid))
        if 'new_password' in data and data['new_password']:
            h = generate_password_hash(data['new_password'])
            db.execute("UPDATE users SET password = ? WHERE id = ?", (h, uid))
        db.commit()
    # Request fresh data to update UI
    send_initial_data()

# -------------------------------------------------------------------------
# 4. FRONTEND TEMPLATES
# -------------------------------------------------------------------------

LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Messenger - Login</title>
<style>
body{background:#121212;color:#eee;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.box{background:#1e1e1e;padding:2rem;border-radius:12px;width:300px;text-align:center;box-shadow:0 10px 30px rgba(0,0,0,0.5)}
input{width:100%;padding:12px;margin:10px 0;background:#2c2c2c;border:1px solid #333;color:#fff;border-radius:6px;box-sizing:border-box}
button{width:100%;padding:12px;background:#00a884;color:#fff;border:none;border-radius:6px;font-weight:bold;cursor:pointer}
</style>
</head>
<body>
<div class="box">
    <h2 id="ttl">Messenger</h2><div id="err" style="color:#f55;display:none;margin-bottom:10px"></div>
    <input id="u" placeholder="Username"><input type="password" id="p" placeholder="Password">
    <button onclick="sub()">Login</button>
    <p style="color:#888;cursor:pointer;font-size:0.9rem" onclick="reg=!reg;document.getElementById('ttl').innerText=reg?'Register':'Login'">Toggle Login/Register</p>
</div>
<script>
let reg=false;
async function sub(){
    let u=document.getElementById('u').value,p=document.getElementById('p').value;
    let r=await fetch('/api/auth?action='+(reg?'register':'login'),{
        method:'POST',
        headers: {'Content-Type': 'application/json'},
        body:JSON.stringify({username:u,password:p})
    });
    let d=await r.json();
    if(d.status=='success')location.reload();else{let e=document.getElementById('err');e.innerText=d.message;e.style.display='block'}
}
</script></body></html>
"""

APP_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>Messenger</title>
<!-- Socket.IO Client -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.min.js"></script>
<style>
    :root { --bg:#121212; --rail:#0b0b0b; --panel:#1e1e1e; --border:#2a2a2a; --accent:#00a884; --text:#e0e0e0; --msg-in:#2c2c2c; --msg-out:#005c4b; }
    .light-mode { --bg:#ffffff; --rail:#f0f0f0; --panel:#f5f5f5; --border:#ddd; --text:#111; --msg-in:#fff; --msg-out:#d9fdd3; }
    .light-mode .rail-btn { color:#555; }
    .light-mode .rail-btn:hover { background:#e0e0e0; color:#000; }
    .light-mode .list-item:hover { background:#f0f0f0; }
    .light-mode .list-item.active { background:#e6e6e6; }
    .light-mode input { background:#fff; border:1px solid #ccc; color:#000; }
    .light-mode .msg-meta { color:#777; }
    .light-mode .reply-ctx { background:#eee; color:#333; }

    .e2ee-on { color: #00a884; }
    body { margin:0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; background:var(--bg); color:var(--text); height:100vh; display:flex; overflow:hidden; }
    
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

    .menu-btn { cursor:pointer; color:#bbb; position:relative; }
    .menu-dropdown { position:absolute; top:35px; right:0; background:#252525; border:1px solid #444; border-radius:8px; display:none; z-index:101; width:160px; box-shadow:0 5px 15px rgba(0,0,0,0.5); }
    .menu-item { padding:12px; border-bottom:1px solid #333; font-size:0.9rem; cursor:pointer; display:block; color:#eee; }
    .menu-item:hover { background:#333; }

    .messages { flex:1; overflow-y:auto; padding:20px; display:flex; flex-direction:column; gap:5px; }
    .msg { max-width:65%; padding:8px 12px; border-radius:8px; font-size:0.95rem; line-height:1.4; position:relative; word-wrap:break-word; }
    .msg.in { align-self:flex-start; background:var(--msg-in); border-top-left-radius:0; }
    .msg.out { align-self:flex-end; background:var(--msg-out); border-top-right-radius:0; }
    .msg img { max-width:100%; border-radius:4px; margin-top:5px; cursor:pointer; }
    .msg audio { max-width:250px; margin-top:5px; }
    .file-att { background:rgba(0,0,0,0.2); padding:10px; border-radius:5px; display:flex; align-items:center; gap:10px; cursor:pointer; border:1px solid rgba(255,255,255,0.1); margin-top:5px; }
    .file-att:hover { background:rgba(0,0,0,0.3); }
    .msg-sender { font-size:0.75rem; font-weight:bold; color:var(--accent); margin-bottom:4px; cursor:pointer; }
    .msg-meta { font-size:0.7rem; color:rgba(255,255,255,0.5); text-align:right; margin-top:2px; }
    .reaction-bar { position:absolute; bottom:-12px; right:0; background:#222; border-radius:10px; padding:2px 6px; font-size:0.8rem; box-shadow:0 2px 5px rgba(0,0,0,0.5); cursor:pointer; }
    
    .input-area { padding:15px; background:var(--panel); display:flex; gap:10px; align-items:center; border-top:1px solid var(--border); }
    .input-wrapper { flex:1; position:relative; }
    .reply-ctx { background:#2a2a2a; padding:6px 10px; border-radius:5px 5px 0 0; font-size:0.8rem; color:#aaa; display:none; justify-content:space-between; }
    input[type=text] { width:100%; padding:12px; border-radius:20px; border:none; background:#333; color:#fff; outline:none; box-sizing:border-box; }
    
    #btn-e2ee svg { fill: var(--accent); }
    .btn-icon { background:none; border:none; color:#888; cursor:pointer; display:flex; align-items:center; justify-content:center; }
    .btn-icon:hover { color:#fff; }
    .btn-primary { background:var(--accent); color:#fff; border:none; padding:8px 16px; border-radius:20px; cursor:pointer; font-weight:bold; }
    
    .settings-panel { padding:20px; text-align:center; }
    .form-group { margin-top:15px; text-align:left; }
    .form-input { width:100%; padding:10px; background:#333; border:1px solid #444; color:#fff; border-radius:4px; margin-top:5px; outline:none; box-sizing:border-box; }
    
    .modal-overlay { position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.7); z-index:1000; display:none; align-items:center; justify-content:center; }
    .modal-box { background:var(--panel); padding:20px; border-radius:12px; width:300px; border:1px solid var(--border); box-shadow:0 10px 30px #000; }
    .modal-title { margin:0 0 10px 0; font-size:1.1rem; font-weight:bold; }
    .modal-body { color:#ccc; font-size:0.9rem; margin-bottom:15px; }
    .modal-btns { display:flex; justify-content:flex-end; gap:10px; margin-top:20px; }
    .btn-modal { padding:8px 16px; border-radius:6px; cursor:pointer; border:none; font-weight:bold; }
    .btn-sec { background:transparent; color:#aaa; border:1px solid #444; }
    .btn-pri { background:var(--accent); color:#fff; }

    @media (max-width: 768px) {
        .app-container { flex-direction: column; }
        .nav-rail { width: 100%; height: 60px; flex-direction: row; justify-content: space-evenly; align-items: center; padding-top: 0; border-right: none; border-top: 1px solid var(--border); position: fixed; bottom: 0; left: 0; background: var(--panel); z-index: 30; }
        .rail-btn { margin-bottom: 0; width: auto; height: 100%; flex: 1; border-radius: 0; }
        .rail-btn:hover { background: none; }
        .rail-btn.active { background: transparent; color: var(--accent); position: relative; }
        .rail-btn.active::after { content:''; position:absolute; top:0; left:0; width:100%; height:3px; background:var(--accent); }
        .rail-spacer { display: none; }
        .nav-panel { width: 100%; left: 0; top: 0; height: calc(100% - 60px); border-right: none; z-index: 5; position: absolute; }
        .nav-panel.hidden { display: flex; }
        .main-view { width: 100%; height: 100%; position: fixed; top: 0; left: 0; z-index: 40; transform: translateX(100%); transition: transform 0.3s cubic-bezier(0.4, 0.0, 0.2, 1); background: var(--bg); }
        .main-view.active { transform: translateX(0); }
        .back-btn { display: flex; align-items: center; justify-content: center; margin-right: 10px; font-size: 1.5rem; padding: 5px; }
        .list-item { padding: 20px 15px; }
        .avatar { width: 45px; height: 45px; }
    }
    @media (min-width: 769px) { .back-btn { display:none; } }
</style>
</head>
<body>

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
        <div class="rail-btn" id="nav-public" onclick="switchTab('public')">
            <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/></svg>
        </div>
        
        <div style="flex:1" class="rail-spacer"></div>
        <div class="rail-btn" onclick="location.href='/logout'" title="Logout">
            <svg viewBox="0 0 24 24"><path d="M10.09 15.59L11.5 17l5-5-5-5-1.41 1.41L12.67 11H3v2h9.67l-2.58 2.59zM19 3H5c-1.11 0-2 .9-2 2v4h2V5h14v14H5v-4H3v4c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2z"/></svg>
        </div>
    </div>

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
        <div id="tab-public" class="tab-content" style="display:none;height:100%">
            <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%">
                <div style="font-size:1.2rem;color:#888">Online Users</div>
                <div id="online-count" style="font-size:4rem;font-weight:bold;color:var(--accent)">0</div>
            </div>
        </div>
        <div id="tab-settings" class="tab-content" style="display:none">
            <div class="panel-header">Settings</div>
            <div class="settings-panel">
                <div class="avatar" id="my-av" style="width:80px;height:80px;margin:0 auto;font-size:2rem"></div>
                <h3 id="my-name"></h3>
                <p id="my-date" style="color:#777;font-size:0.8rem"></p>
                <div class="form-group"><label>Bio / Status</label><input class="form-input" id="set-bio" maxlength="50"></div>
                <div class="form-group"><label>Avatar URL</label><input class="form-input" id="set-av"></div>
                <div class="form-group"><label>New Password</label><input class="form-input" id="set-pw" type="password"></div>
                <div class="form-group"><button class="btn-sec" style="width:100%;padding:10px;border:1px solid var(--border);border-radius:4px;cursor:pointer;background:var(--panel);color:var(--text)" onclick="toggleTheme()">Toggle Dark/Light Mode</button></div>
                <br><button class="btn-primary" onclick="saveSettings()">Save</button>
            </div>
        </div>
    </div>

    <div class="main-view" id="main-view">
        <div class="chat-header">
            <div style="display:flex;align-items:center">
                <div class="back-btn" onclick="closeChat()">&larr;</div>
                <div class="avatar" id="chat-av"></div>
                <div><div id="chat-title" style="font-weight:bold"></div><div id="chat-sub" style="font-size:0.75rem;color:#999"></div><div id="typing-ind" style="font-size:0.7rem;color:var(--accent);display:none;font-style:italic">typing...</div></div>
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
                <div class="menu-btn" onclick="toggleMenu()">
                    <svg viewBox="0 0 24 24" width="24" fill="currentColor"><path d="M12 8c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm0 2c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zm0 6c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2z"/></svg>
                    <div class="menu-dropdown" id="chat-menu">
                        <div class="menu-item" onclick="clearChat()">Clear History</div>
                        <div class="menu-item" onclick="exportChat()">Export Chat</div>
                        <div class="menu-item" onclick="deleteChat()">Delete Chat</div>
                    </div>
                </div>
            </div>
        </div>

        <div class="messages" id="msgs"></div>

        <div class="input-area" id="input-box" style="visibility:hidden">
            <button class="btn-icon" id="btn-att" onclick="document.getElementById('file').click()">
                <svg viewBox="0 0 24 24" width="24" fill="currentColor"><path d="M21 19V5c0-1.1-.9-2-2-2H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2zM8.5 13.5l2.5 3.01L14.5 12l4.5 6H5l3.5-4.5z"/></svg>
            </button>
            <input type="file" id="file" hidden onchange="uploadFile(this)">
            <button class="btn-icon" id="btn-mic" onclick="startRec()">
                <svg viewBox="0 0 24 24" width="24" fill="currentColor"><path d="M12 14c1.66 0 3-1.34 3-3V5c0-1.66-1.34-3-3-3S9 3.34 9 5v6c0 1.66 1.34 3 3 3z"/><path d="M17 11c0 2.76-2.24 5-5 5s-5-2.24-5-5H5c0 3.53 2.61 6.43 6 6.92V21h2v-3.08c3.39-.49 6-3.39 6-6.92h-2z"/></svg>
            </button>
            <div class="input-wrapper">
                <div class="reply-ctx" id="reply-ui">
                    <span id="reply-txt"></span>
                    <button id="del-btn" class="btn-icon" style="display:none;font-size:0.8rem;color:#f55;margin-right:10px" onclick="deleteMsg()">Delete</button>
                    <span onclick="cancelReply()" style="cursor:pointer">&times;</span>
                </div>
                <div id="rec-ui" style="display:none;align-items:center;height:40px;background:#333;border-radius:20px;padding:0 15px;color:#f55">
                    <span style="flex:1">Recording...</span>
                    <span onclick="stopRec(false)" style="cursor:pointer;margin-right:15px;color:#ccc">&times;</span>
                    <span onclick="stopRec(true)" style="cursor:pointer;color:var(--accent)">&#10004;</span>
                </div>
                <input type="text" id="txt" placeholder="Type a message..." autocomplete="off">
            </div>
            <button class="btn-icon" id="btn-send" style="color:var(--accent)" onclick="send()">
                <svg viewBox="0 0 24 24" width="24" fill="currentColor"><path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"/></svg>
            </button>
        </div>
    </div>
</div>

<script>
const ME = "{{ username }}";
const socket = io();

let lastTyping = 0;
let lastRead = 0;
let mediaRec=null, audChunks=[];
let S = { tab:'chats', id:null, type:null, reply:null, dms:{}, groups:{}, online:[], notifs:[], keys:{pub:null,priv:null}, e2ee:{} };

// MODAL UTILS
function showModal(title, type, placeholder, callback) {
    const ov = document.getElementById('app-modal');
    const tt = document.getElementById('modal-title');
    const bd = document.getElementById('modal-body');
    const ip = document.getElementById('modal-input');
    const ok = document.getElementById('modal-ok');
    const cc = document.getElementById('modal-cancel');
    ov.style.display = 'flex'; tt.innerText = title;
    if(type === 'prompt') { bd.style.display = 'none'; ip.style.display = 'block'; ip.value = ''; ip.placeholder = placeholder || ''; ip.focus(); cc.style.display = 'block'; } 
    else if(type === 'confirm') { bd.style.display = 'block'; bd.innerText = placeholder; ip.style.display = 'none'; cc.style.display = 'block'; ok.innerText = 'Accept'; } 
    else { bd.style.display = 'block'; bd.innerText = placeholder; ip.style.display = 'none'; cc.style.display = 'none'; }
    ok.onclick = () => { const val = ip.value; ov.style.display = 'none'; if(callback) callback(type==='confirm'?true:val); };
    cc.onclick = () => { ov.style.display = 'none'; };
    ip.onkeydown = (e) => { if(e.key === 'Enter') ok.click(); if(e.key === 'Escape') cc.click(); };
}
function promptModal(t, p, cb) { showModal(t, 'prompt', p, cb); }
function alertModal(t, m) { showModal(t, 'alert', m, null); }
function confirmModal(t, m, cb) { showModal(t, 'confirm', m, cb); }

// INIT
async function loadKeys() {
    let pub = localStorage.getItem('mw_key_pub');
    let priv = localStorage.getItem('mw_key_priv');
    if (pub && priv) {
        S.keys.pub = await window.crypto.subtle.importKey("jwk", JSON.parse(pub), {name:"ECDH",namedCurve:"P-256"}, true, []);
        S.keys.priv = await window.crypto.subtle.importKey("jwk", JSON.parse(priv), {name:"ECDH",namedCurve:"P-256"}, true, ["deriveKey"]);
    } else {
        let k = await window.crypto.subtle.generateKey({name:"ECDH",namedCurve:"P-256"}, true, ["deriveKey"]);
        S.keys.pub = k.publicKey;
        S.keys.priv = k.privateKey;
        localStorage.setItem('mw_key_pub', JSON.stringify(await window.crypto.subtle.exportKey("jwk", k.publicKey)));
        localStorage.setItem('mw_key_priv', JSON.stringify(await window.crypto.subtle.exportKey("jwk", k.privateKey)));
    }
}

async function saveSession(u, k) {
    S.e2ee[u] = k;
    localStorage.setItem('mw_sess_' + u, JSON.stringify(await window.crypto.subtle.exportKey("jwk", k)));
}

async function loadSessions() {
    for (let i = 0; i < localStorage.length; i++) {
        let k = localStorage.key(i);
        if (k.startsWith('mw_sess_')) {
            let u = k.split('mw_sess_')[1];
            S.e2ee[u] = await window.crypto.subtle.importKey("jwk", JSON.parse(localStorage.getItem(k)), {name:"AES-GCM",length:256}, false, ["encrypt","decrypt"]);
        }
    }
}

async function init(){
    await loadKeys();
    await loadSessions();
    if(localStorage.getItem('mw_theme')=='light') document.body.classList.add('light-mode');
    socket.emit('get_data'); // Initial Poll
}

// STORAGE
function get(t,i){ let k=`mw_${t}_${i}`; return JSON.parse(localStorage.getItem(k))||[]; }
function save(t,i,d){ try{ localStorage.setItem(`mw_${t}_${i}`,JSON.stringify(d)); }catch(e){ alertModal('Error','Storage full! Clear some chats.'); } }
function store(t,i,m){
    let h=get(t,i);
    let idx = h.findIndex(x=>x.timestamp==m.timestamp && x.message==m.message);
    if(idx !== -1) return; // Duplicate
    if(m.type=='react'){
        let tg=h.find(x=>x.timestamp==m.extra_data);
        if(tg){ if(!tg.reacts)tg.reacts={}; tg.reacts[m.from_user]=m.message; save(t,i,h); if(S.id==i && S.type==t) renderChat(); }
        return;
    }
    h.push(m); save(t,i,h);
    if(S.id==i && S.type==t) {
        let prev = h.length>1 ? h[h.length-2] : null;
        let show = (t=='public'||t=='group') && m.from_user!=ME && (!prev || prev.from_user!=m.from_user);
        document.getElementById('msgs').appendChild(createMsgNode(m, show));
        scrollToBottom(false);
    }
}

// SOCKET EVENTS
socket.on('init_data', (d) => {
    S.online = d.online;
    if(d.profile){
        document.getElementById('my-av').style.backgroundImage=`url('${d.profile.avatar}')`;
        document.getElementById('my-name').innerText=d.profile.username;
        document.getElementById('set-bio').value=d.profile.bio||'';
        document.getElementById('my-date').innerText="Joined: "+new Date(d.profile.joined_at*1000).toLocaleDateString();
    }
    
    // Process messages into local storage
    d.dms.forEach(async m => await handleIncomingMsg(m));
    
    S.groups={}; 
    d.groups.forEach(g => { S.groups[g.id]=g; if(!get('group',g.id)) save('group',g.id,[]); });
    d.group_msgs.forEach(m => store('group', m.group_id, m));
    
    d.public_msgs.forEach(m => store('public', 'global', m));
    
    renderLists();
});

socket.on('new_msg', async (m) => {
    if(m.from_user == ME) return; // We handle optimistic UI sending separately
    
    if(m.group_id == -1) {
        store('public', 'global', m);
        if(S.tab!='public') notify('global', m.message, 'public');
    } else if(m.group_id) {
        store('group', m.group_id, m);
        notify(m.group_id, m.type=='text'?m.message:'['+m.type+']', 'group');
    } else {
        await handleIncomingMsg(m);
    }
});

socket.on('group_joined', (g) => {
    S.groups[g.id] = g;
    if(!get('group',g.id)) save('group',g.id,[]);
    renderLists();
});

socket.on('user_typing', (d) => {
    if(S.type=='dm' && S.id==d.from) {
        document.getElementById('typing-ind').style.display='block';
        setTimeout(() => document.getElementById('typing-ind').style.display='none', 3000);
    }
});

async function handleIncomingMsg(m) {
    if(m.type=='signal_req'){ handleSignalReq(m); return; }
    if(m.type=='signal_ack'){ handleSignalAck(m); return; }
    if(m.type=='enc'){ try{m.message=await dec(m.from_user,m.message,m.extra_data)}catch(e){m.message="[Encrypted]"} }
    
    let partner = m.from_user == ME ? m.to_user : m.from_user;
    store('dm', partner, m);
    if(m.from_user != ME) notify(m.from_user, m.type=='text'?m.message:'['+m.type+']', 'dm');
}

// NOTIFICATIONS & UI
function notify(id, text, type) {
    if(S.type === type && S.id == id && document.hasFocus()) return;
    let title = type=='dm'?id:(type=='public'?'Public Chat':(S.groups[id]?S.groups[id].name:'Group'));
    S.notifs.unshift({id, type, text, title: title, time:new Date()});
    updateNotifUI();
    if(type=='dm') document.getElementById('badge-chats').style.display = 'block';
    if(type=='group') document.getElementById('badge-groups').style.display = 'block';
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
    let n = S.notifs[idx]; S.notifs.splice(idx, 1); updateNotifUI(); toggleNotif(false);
    switchTab(n.type == 'dm' ? 'chats' : (n.type=='public'?'public':'groups'));
    openChat(n.type, n.id);
}

function toggleNotif(force) {
    let el = document.getElementById('notif-list');
    document.getElementById('chat-menu').style.display='none';
    if(force === false) el.style.display='none'; else el.style.display = (el.style.display=='block'?'none':'block');
}

// ENCRYPTION
async function startE2EE(){
    if(S.type!='dm'||S.e2ee[S.id])return;
    let exp=await window.crypto.subtle.exportKey("jwk",S.keys.pub);
    socket.emit('send_msg', {to_user:S.id,message:JSON.stringify(exp),type:'signal_req'});
    alertModal("Security", "Encryption request sent. Waiting for approval...");
}
async function handleSignalReq(m){
    confirmModal("Encryption Request", m.from_user + " wants to start a secure chat.", async (yes)=>{
        if(yes){
            let fk=await window.crypto.subtle.importKey("jwk",JSON.parse(m.message),{name:"ECDH",namedCurve:"P-256"},true,[]);
            await saveSession(m.from_user, await window.crypto.subtle.deriveKey({name:"ECDH",public:fk},S.keys.priv,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]));
            let exp=await window.crypto.subtle.exportKey("jwk",S.keys.pub);
            socket.emit('send_msg', {to_user:m.from_user, message:JSON.stringify(exp), type:'signal_ack'});
            alertModal("Security", "Secure channel established.");
        }
    });
}
async function handleSignalAck(m){
    let fk=await window.crypto.subtle.importKey("jwk",JSON.parse(m.message),{name:"ECDH",namedCurve:"P-256"},true,[]);
    await saveSession(m.from_user, await window.crypto.subtle.deriveKey({name:"ECDH",public:fk},S.keys.priv,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]));
    alertModal("Security", "Secure channel ready with "+m.from_user);
    if(S.id==m.from_user) { document.getElementById('btn-e2ee').classList.add('e2ee-on'); document.getElementById('txt').placeholder="Type an encrypted message..."; }
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

// NAVIGATION
function switchTab(t){
    S.tab=t;
    document.querySelectorAll('.rail-btn').forEach(e=>e.classList.remove('active'));
    document.getElementById('nav-'+t).classList.add('active');
    document.querySelectorAll('.tab-content').forEach(e=>e.style.display='none');
    
    if(t=='public') openChat('public', 'global');
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
            let sec=S.e2ee[u]?' e2ee-on':'';
            let last=h.length?h[h.length-1].message:'Start chatting';
            if(last.length>30)last=last.substring(0,30)+'...';
            let ou=S.online.find(x=>x.username==u);
            let av=ou?ou.avatar:'';
            dh+=`<div class="list-item ${S.id==u?'active':''}" onclick="openChat('dm','${u}')">
                <div class="avatar" style="background-image:url('${av}')">${av?'':u[0].toUpperCase()}</div>
                <div style="flex:1"><div style="font-weight:bold">${u} ${ou?'<span style="color:#0f0;font-size:0.8em">●</span>':''}</div><div style="font-size:0.8em;color:#888">${last}</div></div>
                <div class="btn-icon${sec}"><svg viewBox="0 0 24 24" width="16"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-9-2c0-1.66 1.34-3 3-3s3 1.34 3 3v2H9V6zm9 14H6V10h12v10zm-6-3c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2z"/></svg></div></div>`;
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
    document.getElementById('online-count').innerText=S.online.length;
}

function openChat(t,i){
    S.type=t; S.id=i;
    renderChat(); scrollToBottom(true);
    document.getElementById('input-box').style.visibility='visible';
    document.getElementById('main-view').classList.add('active');
    document.getElementById('nav-panel').classList.add('hidden');
    let tit=i, sub='', av='';
    document.getElementById('btn-e2ee').style.display=(t=='dm'?'block':'none');
    if(t=='dm'){
        let ou=S.online.find(x=>x.username==i);
        sub=ou?(ou.bio||'Online'):'Offline'; av=ou?ou.avatar:'';
        if(av) document.getElementById('chat-av').style.backgroundImage=`url('${av}')`;
        document.getElementById('chat-av').innerText=av?'':i[0];
    } else if(t=='group') {
        tit=S.groups[i]?S.groups[i].name:'Group'; sub='Group';
        document.getElementById('chat-av').innerText='#';
    } else if(t=='public') {
        tit="Public Chat"; sub="Global Room";
        document.getElementById('chat-av').innerText='P';
    }
    document.getElementById('btn-e2ee').classList.toggle('e2ee-on', S.e2ee[S.id]);
    document.getElementById('chat-title').innerText=tit;
    document.getElementById('chat-sub').innerText=sub;
    document.getElementById('txt').placeholder = (t=='dm' && S.e2ee[S.id]) ? "Type an encrypted message..." : "Type a message...";
}

function createMsgNode(m, showSender){
    let div=document.createElement('div');
    div.className=`msg ${m.from_user==ME?'out':'in'}`;
    let sender='';
    if(showSender) sender=`<div class="msg-sender" onclick="if(ME!='${m.from_user}'){openChat('dm','${m.from_user}');switchTab('chats');}">${m.from_user}</div>`;

    let txt=esc(m.message);
    if(m.type=='image') txt=`<img src="${m.message}" onclick="window.open(this.src)" onload="scrollToBottom(false)">`;
    else if(m.type=='audio') txt=`<audio controls src="${m.message}"></audio>`;
    else if(m.type=='file') {
        let fname = esc(m.extra_data || 'file');
        let safeName = (m.extra_data || 'file').replace(/'/g, "\\'");
        txt = `<div class="file-att" onclick="downloadFile('${m.message}', '${safeName}')">
            <svg viewBox="0 0 24 24" width="24" fill="currentColor"><path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>
            <span>${fname}</span></div>`;
    }
    
    let rep='';
    if(m.reply_to_id){
        let h=get(S.type,S.id);
        let p=h.find(x=>x.timestamp==m.reply_to_id);
        if(p) rep=`<div style="font-size:0.8em;border-left:2px solid var(--accent);padding-left:4px;margin-bottom:4px;opacity:0.7">Reply: ${p.type=='image'?'Image':p.message.substring(0,20)}</div>`;
    }
    div.innerHTML=`${sender}${rep}${txt}<div class="msg-meta">${new Date(m.timestamp*1000).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}</div>`;
    div.oncontextmenu=(e)=>{
        e.preventDefault(); S.reply=m.timestamp; 
        document.getElementById('reply-ui').style.display='flex'; 
        document.getElementById('reply-txt').innerText="Replying...";
        document.getElementById('del-btn').style.display=m.from_user==ME?'inline-block':'none';
    };
    return div;
}

function renderChat(){
    let c=document.getElementById('msgs'); c.innerHTML='';
    let h=get(S.type,S.id);
    let last=null;
    h.forEach(m=>{
        let show=(S.type=='public'||S.type=='group') && m.from_user!=ME && m.from_user!=last;
        c.appendChild(createMsgNode(m, show));
        last=m.from_user;
    });
}

function closeChat() { document.getElementById('main-view').classList.remove('active'); document.getElementById('nav-panel').classList.remove('hidden'); S.id=null; }

async function send(){
    let txt=document.getElementById('txt').value.trim();
    if(!txt)return;
    document.getElementById('txt').value=''; cancelReply();
    let ts = Math.floor(Date.now()/1000);
    
    // Optimistic UI
    store(S.type, S.id, { from_user: ME, message: txt, type: 'text', timestamp: ts, reply_to_id: S.reply });
    scrollToBottom(true);
    
    let load = { message: txt, type: 'text', reply_to: S.reply };
    if(S.type=='dm') load.to_user=S.id; else if(S.type=='group') load.group_id=S.id; else if(S.type=='public') load.group_id=-1;
    
    if(S.type=='dm' && S.e2ee[S.id]){
        let e=await enc(S.id,txt);
        load.message=e.c; load.extra=e.i; load.type='enc';
    }
    socket.emit('send_msg', load);
}

function deleteMsg(){ alertModal("Info", "Deletions not fully synced in WS demo."); cancelReply(); }
function toggleMenu(){ let m=document.getElementById('chat-menu'); toggleNotif(false); m.style.display=m.style.display=='block'?'none':'block'; }
function clearChat(){ if(!confirm("Clear history?")) return; save(S.type, S.id, []); renderChat(); toggleMenu(); }
function exportChat(){ let h = get(S.type, S.id); let blob = new Blob([JSON.stringify(h, null, 2)], {type : 'application/json'}); let a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `chat_${S.type}_${S.id}.json`; a.click(); toggleMenu(); }
function deleteChat(){ if(!confirm("Delete chat permanently?")) return; localStorage.removeItem(`mw_${S.type}_${S.id}`); closeChat(); switchTab('chats'); toggleMenu(); }
function toggleTheme(){ document.body.classList.toggle('light-mode'); localStorage.setItem('mw_theme', document.body.classList.contains('light-mode')?'light':'dark'); }
function uploadFile(inp){
    let f=inp.files[0]; if(!f)return;
    if(f.size > 10485760) { alertModal('Error','File too large (Max 10MB)'); return; }
    let r=new FileReader();
    r.onload=()=>{
        let ts = Math.floor(Date.now()/1000);
        let type = f.type.startsWith('image/') ? 'image' : 'file';
        let ld={message:r.result,type:type,extra:f.name};
        if(S.type=='dm')ld.to_user=S.id; else if(S.type=='group') ld.group_id=S.id; else if(S.type=='public') ld.group_id=-1;
        socket.emit('send_msg', ld);
        store(S.type,S.id,{from_user:ME,message:r.result,type:type,timestamp:ts,extra_data:f.name});
    };
    r.readAsDataURL(f);
}
function downloadFile(data, name){ let a = document.createElement('a'); a.href = data; a.download = name; a.click(); }
function cancelReply(){ S.reply=null; document.getElementById('reply-ui').style.display='none'; document.getElementById('del-btn').style.display='none'; }
function promptChat(){ promptModal("New Chat", "Username:", (u)=>{ if(u){ if(!get('dm',u).length)save('dm',u,[]); openChat('dm',u); switchTab('chats'); }}); }
function createGroup(){ promptModal("New Group", "Group Name:", (n)=>{ if(n)socket.emit('create_group',{name:n}); }); }
function joinGroup(){ promptModal("Join Group", "6-Digit Code:", (c)=>{ if(c)socket.emit('join_group',{code:c}); }); }
function saveSettings(){ socket.emit('update_profile',{bio:document.getElementById('set-bio').value,avatar:document.getElementById('set-av').value,new_password:document.getElementById('set-pw').value}); alertModal("Settings", "Profile updated."); }
function scrollToBottom(force){ 
    let c=document.getElementById('msgs'); 
    if(force) { c.scrollTop=c.scrollHeight; return; }
    if(c.scrollHeight - c.scrollTop - c.clientHeight < 150) c.scrollTo({ top: c.scrollHeight, behavior: 'smooth' });
}
function esc(t){ return t?t.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"):"" }
document.getElementById('txt').onkeypress=e=>{if(e.key=='Enter')send()};

async function startRec(){
    try{
        let s=await navigator.mediaDevices.getUserMedia({audio:true});
        let opts = {};
        if(MediaRecorder.isTypeSupported("audio/webm;codecs=opus")) opts.mimeType="audio/webm;codecs=opus";
        else if(MediaRecorder.isTypeSupported("audio/mp4")) opts.mimeType="audio/mp4";
        mediaRec=new MediaRecorder(s, opts); audChunks=[];
        mediaRec.ondataavailable=e=>{ if(e.data.size>0) audChunks.push(e.data); };
        mediaRec.start(200);
        document.getElementById('txt').style.display='none'; document.getElementById('btn-send').style.display='none'; document.getElementById('btn-att').style.display='none'; document.getElementById('btn-mic').style.display='none';
        document.getElementById('rec-ui').style.display='flex';
    }catch(e){alertModal('Error','Mic access denied');}
}
function stopRec(send){
    if(!mediaRec || mediaRec.state==='inactive')return;
    mediaRec.onstop=()=>{
        mediaRec.stream.getTracks().forEach(t=>t.stop());
        document.getElementById('txt').style.display='block'; document.getElementById('btn-send').style.display='flex'; document.getElementById('btn-att').style.display='flex'; document.getElementById('btn-mic').style.display='flex';
        document.getElementById('rec-ui').style.display='none';
        if(send && audChunks.length > 0){
            let mime = mediaRec.mimeType || 'audio/webm;codecs=opus';
            let b=new Blob(audChunks,{type:mime}); 
            if(b.size < 1000) return;
            let r=new FileReader();
            r.onload=()=>{ 
                let ts=Math.floor(Date.now()/1000);
                let ld={message:r.result,type:'audio'}; if(S.type=='dm')ld.to_user=S.id; else if(S.type=='group') ld.group_id=S.id; else if(S.type=='public') ld.group_id=-1; 
                socket.emit('send_msg', ld);
                store(S.type,S.id,{from_user:ME,message:r.result,type:'audio',timestamp:ts}); 
            };
            r.readAsDataURL(b);
        }
    };
    mediaRec.stop();
}

document.getElementById('txt').oninput=()=>{
    if(S.type=='dm' && Date.now()-lastTyping>2000){ lastTyping=Date.now(); socket.emit('typing',{to:S.id}); }
};
window.onclick=(e)=>{
    if(!e.target.closest('.notif-btn'))toggleNotif(false);
    if(!e.target.closest('.menu-btn'))document.getElementById('chat-menu').style.display='none';
};
window.onfocus=()=>{ if(S.type=='dm'&&S.id) openChat('dm',S.id); };

init();
</script>
</body>
</html>
"""

if __name__ == '__main__':
    # Use eventlet or gevent for production-ready WebSocket support
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)