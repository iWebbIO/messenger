import os
import time
import sqlite3
import secrets
import base64
from flask import Flask, render_template_string, request, session, jsonify, redirect
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change_this_to_something_random')
app.config['DATABASE'] = 'chat_mw.db'
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024  # 20MB limit

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
            created_at INTEGER,
            category TEXT DEFAULT 'group'
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
        
        try:
            db.execute("ALTER TABLE groups ADD COLUMN category TEXT DEFAULT 'group'")
            db.execute("ALTER TABLE groups ADD COLUMN join_enabled INTEGER DEFAULT 1")
        except sqlite3.OperationalError: pass

init_db()

@app.route('/', methods=['GET', 'POST'])
def index():
    action = request.args.get('action')
    
    # CSRF Check for POST
    if request.method == 'POST':
        token = request.headers.get('X-CSRF-Token')
        if not token or token != session.get('csrf_token'):
            return jsonify({'status': 'error', 'message': 'CSRF validation failed'}), 403

    # Session Init
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)

    # --- PUBLIC ACTIONS ---
    if action == 'manifest':
        return jsonify({
            "name": "moreweb Messenger",
            "short_name": "Messenger",
            "start_url": "/",
            "display": "standalone",
            "background_color": "#121212",
            "theme_color": "#121212",
            "icons": [
                {"src": "?action=icon", "sizes": "192x192", "type": "image/svg+xml"},
                {"src": "?action=icon", "sizes": "512x512", "type": "image/svg+xml"}
            ]
        })
    
    if action == 'icon':
        svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><rect width="512" height="512" rx="100" fill="#1e1e1e"/><path d="M256 85c-93 0-168 69-168 154 0 49 25 92 64 121v62l60-33c14 4 29 6 44 6 93 0 168-69 168-154S349 85 256 85z" fill="#00a884"/></svg>'
        return svg, 200, {'Content-Type': 'image/svg+xml'}

    if action == 'sw':
        js = "const CACHE='mw-v1';self.addEventListener('install',e=>{e.waitUntil(caches.open(CACHE).then(c=>c.addAll(['/','?action=icon'])));self.skipWaiting()});self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));self.addEventListener('fetch',e=>{if(e.request.method!='GET')return;e.respondWith(fetch(e.request).catch(()=>caches.match(e.request)))});self.addEventListener('notificationclick',e=>{e.notification.close();e.waitUntil(clients.matchAll({type:'window',includeUncontrolled:true}).then(cl=>{for(let c of cl){if(c.url&&'focus'in c)return c.focus();}if(clients.openWindow)return clients.openWindow('/');}));});"
        return js, 200, {'Content-Type': 'application/javascript'}

    if action == 'get_profile':
        u = request.args.get('u')
        with get_db() as db:
            row = db.execute("SELECT username, avatar, bio, joined_at, last_seen FROM users WHERE username = ?", (u,)).fetchone()
            return jsonify(dict(row) if row else {'status': 'error'})

    if action == 'get_discoverable_groups':
        cat = request.args.get('cat', 'group')
        with get_db() as db:
            rows = db.execute("SELECT id, name, type, join_code FROM groups WHERE type = 'discoverable' AND category = ? ORDER BY created_at DESC LIMIT 50", (cat,)).fetchall()
            return jsonify({'status': 'success', 'items': [dict(r) for r in rows]})

    if action == 'get_group_details':
        if 'user' not in session: return jsonify({'status': 'error'})
        gid = request.args.get('id')
        my_id = session['uid']
        with get_db() as db:
            mem = db.execute("SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?", (gid, my_id)).fetchone()
            if not mem: return jsonify({'status': 'error', 'message': 'Not a member'})
            
            grp = db.execute("SELECT * FROM groups WHERE id = ?", (gid,)).fetchone()
            mems = db.execute("SELECT u.id, u.username, u.avatar, u.last_seen, u.public_key FROM group_members gm JOIN users u ON gm.user_id = u.id WHERE gm.group_id = ?", (gid,)).fetchall()
            
            return jsonify({
                'status': 'success', 'group': dict(grp), 
                'members': [dict(m) for m in mems], 'is_owner': grp['owner_id'] == my_id
            })

    # --- AUTH ACTIONS ---
    if request.method == 'POST':
        data = request.json or {}
        
        if action == 'register':
            user = data.get('username', '').strip().lower()
            pwd = data.get('password', '')
            if len(user) > 30: return jsonify({'status': 'error', 'message': 'Username too long'})
            hashed = generate_password_hash(pwd)
            try:
                with get_db() as db:
                    cur = db.execute("INSERT INTO users (username, password, joined_at, last_seen) VALUES (?, ?, ?, ?)", 
                                (user, hashed, int(time.time()), int(time.time())))
                    db.commit()
                    session['user'] = user
                    session['uid'] = cur.lastrowid
                    return jsonify({'status': 'success'})
            except sqlite3.IntegrityError:
                return jsonify({'status': 'error', 'message': 'Username taken'})

        if action == 'login':
            user = data.get('username', '').lower()
            with get_db() as db:
                row = db.execute("SELECT * FROM users WHERE lower(username) = ?", (user,)).fetchone()
                if row and check_password_hash(row['password'], data.get('password', '')):
                    session['user'] = row['username']
                    session['uid'] = row['id']
                    return jsonify({'status': 'success'})
            return jsonify({'status': 'error', 'message': 'Invalid credentials'})

    if action == 'logout':
        session.clear()
        return redirect('/')

    # --- PROTECTED VIEW ---
    if 'user' not in session:
        return render_template_string(LOGIN_HTML, csrf_token=session['csrf_token'])

    me = session['user']
    my_id = session['uid']

    # --- PROTECTED API ---
    if request.method == 'POST':
        db = get_db()
        
        if action == 'update_profile':
            if 'avatar' in data: db.execute("UPDATE users SET avatar = ? WHERE id = ?", (data['avatar'], my_id))
            if 'bio' in data: db.execute("UPDATE users SET bio = ? WHERE id = ?", (data['bio'], my_id))
            if 'new_password' in data and data['new_password']:
                db.execute("UPDATE users SET password = ? WHERE id = ?", (generate_password_hash(data['new_password']), my_id))
            db.commit()
            return jsonify({'status': 'success'})

        if action == 'send':
            ts = data.get('timestamp', int(time.time()))
            msg = data.get('message')
            mtype = data.get('type', 'text')
            reply = data.get('reply_to')
            extra = data.get('extra')
            
            if len(msg) > 15000000: return jsonify({'status': 'error', 'message': 'Message too large'})
            
            if 'to_user' in data:
                db.execute("INSERT INTO messages (from_user, to_user, message, type, reply_to_id, extra_data, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
                           (me, data['to_user'], msg, mtype, reply, extra, ts))
            elif 'group_id' in data:
                # Channel Check
                grp = db.execute("SELECT owner_id, category FROM groups WHERE id = ?", (data['group_id'],)).fetchone()
                if grp and grp['category'] == 'channel' and grp['owner_id'] != my_id:
                    return jsonify({'status': 'error', 'message': 'Only owner can post'})
                db.execute("INSERT INTO messages (group_id, from_user, message, type, reply_to_id, extra_data, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
                           (data['group_id'], me, msg, mtype, reply, extra, ts))
            db.commit()
            return jsonify({'status': 'success'})

        if action == 'upload_msg':
            f = request.files.get('file')
            if not f: return jsonify({'status': 'error', 'message': 'No file'})
            
            # Convert to base64
            blob = f.read()
            b64 = 'data:' + f.mimetype + ';base64,' + base64.b64encode(blob).decode('utf-8')
            
            ts = request.form.get('timestamp', int(time.time()))
            reply = request.form.get('reply_to')
            extra = f.filename
            mtype = 'image' if f.mimetype.startswith('image') else 'file'
            
            if request.form.get('to_user'):
                db.execute("INSERT INTO messages (from_user, to_user, message, type, reply_to_id, extra_data, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
                           (me, request.form.get('to_user'), b64, mtype, reply, extra, ts))
            elif request.form.get('group_id'):
                grp = db.execute("SELECT owner_id, category FROM groups WHERE id = ?", (request.form.get('group_id'),)).fetchone()
                if grp and grp['category'] == 'channel' and grp['owner_id'] != my_id:
                    return jsonify({'status': 'error', 'message': 'Only owner can post'})
                db.execute("INSERT INTO messages (group_id, from_user, message, type, reply_to_id, extra_data, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
                           (request.form.get('group_id'), me, b64, mtype, reply, extra, ts))
            db.commit()
            return jsonify({'status': 'success'})

        if action == 'create_group':
            gtype = data.get('type')
            cat = data.get('category', 'group')
            code = str(secrets.randbelow(900000) + 100000) if gtype in ['public', 'discoverable'] else None
            join_enabled = 0 if gtype == 'private' else 1
            cur = db.execute("INSERT INTO groups (name, type, owner_id, join_code, created_at, join_enabled, category) VALUES (?, ?, ?, ?, ?, ?, ?)",
                       (data.get('name'), gtype, my_id, code, int(time.time()), join_enabled, cat))
            gid = cur.lastrowid
            db.execute("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", (gid, my_id))
            db.commit()
            return jsonify({'status': 'success'})

        if action == 'join_group':
            grp = db.execute("SELECT id FROM groups WHERE join_code = ?", (data.get('code'),)).fetchone()
            if grp:
                try:
                    db.execute("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", (grp['id'], my_id))
                    db.commit()
                    return jsonify({'status': 'success'})
                except:
                    return jsonify({'status': 'error', 'message': 'Already joined'})
            return jsonify({'status': 'error', 'message': 'Invalid code'})

        if action == 'typing':
            db.execute("UPDATE users SET typing_to = ?, typing_at = ? WHERE id = ?", (data.get('to'), int(time.time()), my_id))
            db.commit()
            return ''

        if action == 'poll':
            # Update last seen
            db.execute("UPDATE users SET last_seen = ? WHERE id = ?", (int(time.time()), my_id))
            
            # Cleanup old messages (1% chance)
            if secrets.randbelow(100) == 0:
                t24h = int(time.time()) - 86400
                db.execute("DELETE FROM messages WHERE timestamp < ? AND (group_id IS NULL OR group_id NOT IN (SELECT id FROM groups WHERE category = 'channel' AND type = 'discoverable'))", (t24h,))
            
            # Profile
            my_profile = db.execute("SELECT username, avatar, joined_at, bio FROM users WHERE id = ?", (my_id,)).fetchone()
            
            # DMs (Fetch & Delete)
            dms = db.execute("SELECT * FROM messages WHERE to_user = ? ORDER BY id ASC", (me,)).fetchall()
            if dms:
                ids = [str(r['id']) for r in dms]
                db.execute(f"DELETE FROM messages WHERE id IN ({','.join(ids)})")
            
            # Groups
            groups = db.execute("""
                SELECT g.id, g.name, g.type, g.join_code, g.category, g.owner_id, gm.last_received_id 
                FROM groups g 
                JOIN group_members gm ON g.id = gm.group_id 
                WHERE gm.user_id = ?
            """, (my_id,)).fetchall()
            
            grp_msgs = []
            my_groups_list = []
            for g in groups:
                g_dict = dict(g)
                msgs = db.execute("SELECT * FROM messages WHERE group_id = ? AND id > ? ORDER BY id ASC", (g['id'], g['last_received_id'])).fetchall()
                if msgs:
                    grp_msgs.extend([dict(m) for m in msgs])
                    last_id = msgs[-1]['id']
                    db.execute("UPDATE group_members SET last_received_id = ? WHERE group_id = ? AND user_id = ?", (last_id, g['id'], my_id))
                my_groups_list.append(g_dict)
            
            # Online
            online = db.execute("SELECT username, avatar, last_seen, bio FROM users WHERE last_seen > ?", (int(time.time()) - 300,)).fetchall()
            
            # Typing
            typing = db.execute("SELECT username FROM users WHERE typing_to = ? AND typing_at > ?", (me, int(time.time()) - 5)).fetchall()
            
            # Public
            last_pub = int(data.get('last_pub', 0))
            db.execute("DELETE FROM messages WHERE group_id = -1 AND timestamp < ?", (int(time.time()) - 300,))
            pub_msgs = db.execute("SELECT * FROM messages WHERE group_id = -1 AND id > ? ORDER BY id ASC", (last_pub,)).fetchall()
            
            db.commit()
            
            return jsonify({
                'profile': dict(my_profile),
                'dms': [dict(m) for m in dms],
                'groups': my_groups_list,
                'group_msgs': grp_msgs,
                'public_msgs': [dict(m) for m in pub_msgs],
                'online': [dict(u) for u in online],
                'typing': [u['username'] for u in typing]
            })

    return render_template_string(APP_HTML, username=me, csrf_token=session['csrf_token'], uid=my_id)

LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>moreweb Messenger - Login</title>
<link rel="manifest" href="?action=manifest">
<meta name="theme-color" content="#121212">
<link rel="icon" href="?action=icon" type="image/svg+xml">
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
const CSRF_TOKEN = "{{ csrf_token }}";
let reg=false;
function toggleMode() { reg = !reg; document.getElementById('ttl').innerText = reg ? 'Create Account' : 'moreweb Messenger'; document.querySelector('button').innerText = reg ? 'Sign Up' : 'Sign In'; document.getElementById('err').style.display = 'none'; }
async function sub(){
    let u=document.getElementById('u').value.trim(),p=document.getElementById('p').value;
    if(!u||!p){let e=document.getElementById('err');e.innerText="Please fill in all fields";e.style.display='block';return;}
    document.body.classList.add('login-process');
    let r=await fetch('?action='+(reg?'register':'login'),{
        method:'POST',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': CSRF_TOKEN},
        body:JSON.stringify({username:u,password:p})
    });
    let d=await r.json();
    if(d.status=='success')location.reload();else{document.body.classList.remove('login-process');let e=document.getElementById('err');e.innerText=d.message;e.style.display='block';}
}
if('serviceWorker' in navigator)navigator.serviceWorker.register('?action=sw');
</script></body></html>
"""

APP_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<link rel="manifest" href="?action=manifest">
<meta name="theme-color" content="#0f0518">
<link rel="icon" href="?action=icon" type="image/svg+xml">
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@100;300;400;700&display=swap" rel="stylesheet">
<title>moreweb Messenger</title>
<style>
    :root { --bg:#0f0518; --rail:#0b0b0b; --panel:#1a0b2e; --border:#2f1b42; --accent:#a855f7; --text:#e0e0e0; --msg-in:#261038; --msg-out:#581c87; --sb-thumb:rgba(255,255,255,0.5); --sb-hover:rgba(255,255,255,0.7); --input-bg:#333; --pattern:#222; --hover-overlay:rgba(255,255,255,0.05); }
    .light-mode { --bg:#ffffff; --rail:#f0f0f0; --panel:#f5f5f5; --border:#ddd; --text:#111; --msg-in:#fff; --msg-out:#f3e8ff; --sb-thumb:rgba(0,0,0,0.4); --sb-hover:rgba(0,0,0,0.6); --input-bg:#fff; --pattern:#e5e5e5; --hover-overlay:rgba(0,0,0,0.05); }
    .light-mode .rail-btn { color:#555; }
    .light-mode .rail-btn:hover { background:#e0e0e0; color:#000; }
    .light-mode .list-item:hover { background:#f0f0f0; }
    .light-mode .list-item.active { background:#e6e6e6; }
    .light-mode input { background:#fff; border:1px solid #ccc; color:#000; }
    .light-mode .msg-meta { color:#777; }
    .light-mode .reply-ctx { background:#eee; color:#333; }
    .light-mode .ctx-menu { background:#fff; border-color:#ccc; }
    .e2ee-on { color: var(--accent); }
    body { margin:0; font-family:'Poppins', sans-serif; background:var(--bg); color:var(--text); height:100vh; display:flex; overflow:hidden; }
    ::-webkit-scrollbar { width: 10px; height: 10px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background-color: var(--sb-thumb); border-radius: 5px; border: 1px solid transparent; background-clip: content-box; }
    ::-webkit-scrollbar-thumb:hover { background-color: var(--sb-hover); }
    
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
    .list-item:hover { background:rgba(255,255,255,0.1); }
    .list-item.active { background:rgba(255,255,255,0.15); border-left:4px solid var(--accent); padding-left:11px; }
    .avatar { width:40px; height:40px; border-radius:50%; background:#444; margin-right:12px; display:flex; align-items:center; justify-content:center; font-weight:bold; background-size:cover; flex-shrink:0; }
    
    .main-view { flex:1; display:flex; flex-direction:column; background:#0a0a0a; background-image:radial-gradient(#222 1px, transparent 1px); background-size:20px 20px; position:relative; }
    .chat-header { height:60px; background:var(--panel); border-bottom:1px solid var(--border); display:flex; align-items:center; justify-content:space-between; padding:0 20px; }
    .header-actions { display:flex; gap:15px; position:relative; }
    .chat-info-clickable { cursor: pointer; }
    
    .notif-btn { position:relative; cursor:pointer; color:#bbb; }
    .notif-badge { position:absolute; top:-5px; right:-5px; background:#f44; color:#fff; font-size:0.6rem; padding:1px 4px; border-radius:8px; display:none; }
    .notif-dropdown { position:absolute; top:40px; right:0; width:250px; background:#252525; border:1px solid #444; border-radius:8px; display:none; z-index:100; box-shadow:0 5px 15px rgba(0,0,0,0.5); overflow:hidden; }
    .notif-item { padding:12px; border-bottom:1px solid #333; font-size:0.85rem; cursor:pointer; }
    .notif-item:hover { background:#333; }

    .menu-btn { cursor:pointer; color:#bbb; position:relative; }
    .menu-dropdown { position:absolute; top:35px; right:0; background:#252525; border:1px solid #444; border-radius:8px; display:none; z-index:101; width:160px; box-shadow:0 5px 15px rgba(0,0,0,0.5); }
    .menu-item { padding:12px; border-bottom:1px solid #333; font-size:0.9rem; cursor:pointer; display:block; color:#eee; }
    .menu-item:hover { background:rgba(255,255,255,0.1); }
    .red-text { color: #ff5555; }

    .messages { flex:1; overflow-y:auto; padding:20px; display:flex; flex-direction:column; gap:5px; }
    .msg { max-width:65%; padding:8px 12px; border-radius:8px; font-size:0.95rem; line-height:1.4; position:relative; word-wrap:break-word; }
    .msg.in { align-self:flex-start; background:var(--msg-in); border-top-left-radius:0; border:1px solid transparent; }
    .msg.out { align-self:flex-end; background:var(--msg-out); border-top-right-radius:0; }
    .msg img { max-width:100%; border-radius:4px; margin-top:5px; cursor:pointer; }
    .msg audio { max-width:250px; margin-top:5px; }
    .file-att { background:rgba(0,0,0,0.2); padding:10px; border-radius:5px; display:flex; align-items:center; gap:10px; cursor:pointer; border:1px solid rgba(255,255,255,0.1); margin-top:5px; }
    .file-att:hover { background:rgba(0,0,0,0.3); }
    .msg-sender { font-size:0.75rem; font-weight:bold; color:var(--accent); margin-bottom:4px; cursor:pointer; }
    .msg-meta { font-size:0.7rem; color:rgba(255,255,255,0.5); text-align:right; margin-top:2px; }
    .msg.pinned { border: 1px solid var(--accent); }
    .reaction-bar { position:absolute; bottom:-12px; right:0; background:#222; border-radius:10px; padding:2px 6px; font-size:0.8rem; box-shadow:0 2px 5px rgba(0,0,0,0.5); cursor:pointer; }
    
    .input-area { padding:15px; background:var(--panel); display:flex; gap:10px; align-items:center; border-top:1px solid var(--border); }
    .input-wrapper { flex:1; position:relative; }
    .reply-ctx { background:#2a2a2a; padding:6px 10px; border-radius:5px 5px 0 0; font-size:0.8rem; color:#aaa; display:none; justify-content:space-between; }
    input[type=text] { width:100%; padding:12px; border-radius:20px; border:none; background:#333; color:#fff; outline:none; box-sizing:border-box; }
    
    #btn-e2ee svg { fill: var(--accent); }
    .btn-icon { background:none; border:none; color:#888; cursor:pointer; display:flex; align-items:center; justify-content:center; border-radius:50%; transition:0.2s; }
    .btn-icon:hover { color:#fff; background:rgba(255,255,255,0.1); }
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

    /* Context Menu */
    .ctx-menu { position:fixed; background:var(--panel); border:1px solid var(--border); border-radius:8px; box-shadow:0 5px 20px rgba(0,0,0,0.5); z-index:2000; min-width:180px; overflow:hidden; font-size:0.9rem; }
    .ctx-reactions { display:flex; padding:8px; gap:5px; background:rgba(0,0,0,0.2); justify-content:space-around; }
    .ctx-reaction { cursor:pointer; transition:0.2s; font-size:1.2rem; padding:2px; border-radius:4px; }
    .ctx-reaction:hover { background:rgba(255,255,255,0.2); transform:scale(1.2); }
    .ctx-item { padding:10px 15px; cursor:pointer; display:flex; align-items:center; gap:10px; }
    .ctx-item:hover { background:rgba(255,255,255,0.05); }
    .ctx-separator { height:1px; background:var(--border); margin:2px 0; }

    @media (max-width: 768px) {
        .app-container { flex-direction: column; }
        .nav-rail { 
            width: 100%; height: 60px; 
            flex-direction: row; justify-content: space-evenly; align-items: center;
            padding-top: 0; border-right: none; border-top: 1px solid var(--border);
            position: fixed; bottom: 0; left: 0; background: var(--panel);
            z-index: 30;
        }
        .rail-btn { margin-bottom: 0; width: auto; height: 100%; flex: 1; border-radius: 0; }
        .rail-btn:hover { background: none; }
        .rail-btn.active { background: transparent; color: var(--accent); position: relative; }
        .rail-btn.active::after { content:''; position:absolute; top:0; left:0; width:100%; height:3px; background:var(--accent); }
        .rail-spacer { display: none; }
        
        .nav-panel { 
            width: 100%; left: 0; top: 0; 
            height: calc(100% - 60px); 
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
        .list-item { padding: 20px 15px; }
        .avatar { width: 45px; height: 45px; }
        .btn-icon svg { width: 28px; height: 28px; }
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
        <div class="rail-btn" id="nav-public" onclick="switchTab('public')">
            <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/></svg>
        </div>
        
        <div style="flex:1" class="rail-spacer"></div>
        <div class="rail-btn" id="nav-about" onclick="switchTab('about')">
            <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>
        </div>
        <div class="rail-btn" id="nav-settings" onclick="switchTab('settings')">
            <svg viewBox="0 0 24 24"><path d="M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58a.49.49 0 0 0 .12-.61l-1.92-3.32a.488.488 0 0 0-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54a.484.484 0 0 0-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L3.16 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.09.63-.09.94s.02.64.07.94l-2.03 1.58a.49.49 0 0 0-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z"/></svg>
        </div>
        <div class="rail-btn" onclick="location.href='?action=logout'" title="Logout">
            <svg viewBox="0 0 24 24"><path d="M10.09 15.59L11.5 17l5-5-5-5-1.41 1.41L12.67 11H3v2h9.67l-2.58 2.59zM19 3H5c-1.11 0-2 .9-2 2v4h2V5h14v14H5v-4H3v4c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2z"/></svg>
        </div>
    </div>

    <!-- LIST PANEL -->
    <div class="nav-panel" id="nav-panel">
        <div id="tab-chats" class="tab-content">
            <div style="padding:20px 15px 5px 15px"><input type="text" id="chat-search" class="form-input" placeholder="Search chats..." onkeyup="renderLists()" style="margin:0;padding:10px 15px;border-radius:20px"></div>
        <div class="panel-header" style="padding-top:5px;padding-bottom:5px;border-bottom:none">Chats <div class="btn-icon" onclick="promptChat()" style="width:32px;height:32px">+</div></div>
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
                <div class="form-group"><button class="btn-sec" style="width:100%;padding:10px;border:1px solid var(--border);border-radius:4px;cursor:pointer;background:var(--panel);color:var(--text)" onclick="enableNotifs()">Enable Notifications</button></div>
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
                <button class="btn-sec" style="margin-bottom:20px;cursor:pointer;padding:8px 16px;border-radius:20px" onclick="checkUpdates()">Check for Updates</button><br>
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
                <div class="back-btn" onclick="closeChat()" style="cursor:pointer">&larr;</div>
                <div class="avatar chat-info-clickable" id="chat-av" onclick="showProfilePopup()"></div>
                <div class="chat-info-clickable" onclick="showProfilePopup()"><div id="chat-title" style="font-weight:bold"></div><div id="chat-sub" style="font-size:0.75rem;color:#999"></div><div id="typing-ind" style="font-size:0.7rem;color:var(--accent);display:none;font-style:italic">typing...</div></div>
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
                <div class="menu-btn" onclick="toggleMenu(event)">
                    <svg viewBox="0 0 24 24" width="24" fill="currentColor"><path d="M12 8c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm0 2c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zm0 6c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2z"/></svg>
                    <div class="menu-dropdown" id="chat-menu">
                        <div class="menu-item" onclick="clearChat()">Clear History</div>
                        <div class="menu-item red-text" onclick="deleteChat()">Delete Chat</div>
                        <div class="menu-item" onclick="exportChat()">Export Chat</div>
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
const CSRF_TOKEN = "{{ csrf_token }}";
let lastTyping = 0;
let lastRead = 0;
let mediaRec=null, audChunks=[];
let S = { tab:'chats', id:null, type:null, reply:null, ctx:null, dms:{}, groups:{}, online:[], notifs:[], keys:{pub:null,priv:null}, e2ee:{} };

// --- INDEXEDDB HELPERS ---
const DB_NAME = 'mw_chat_db';
const DB_STORE = 'chats';
let dbPromise = new Promise((resolve, reject) => {
    let req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = e => e.target.result.createObjectStore(DB_STORE);
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
        pollLoop();
    } catch(e) { console.error("Init failed", e); alert("App failed to initialize: " + e.message); }
}

async function req(act, data) {
    return fetch('?action='+act, {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': CSRF_TOKEN},
        body: JSON.stringify(data||{})
    });
}

// --- CORE ---
async function pollLoop() {
    await poll();
    setTimeout(pollLoop, 2000);
}

async function poll(){
    try {
        let lastPub = 0;
        let pubH = await get('public', 'global');
        if(pubH.length) lastPub = pubH[pubH.length-1].id || 0;
        let r=await req('poll', {last_pub: lastPub});
        let d=await r.json();
        S.online=d.online;
        if(d.profile){
            document.getElementById('my-av').style.backgroundImage=`url('${d.profile.avatar}')`;
            document.getElementById('my-name').innerText=d.profile.username;
            document.getElementById('set-bio').value=d.profile.bio||'';
            document.getElementById('my-date').innerText="Joined: "+new Date(d.profile.joined_at*1000).toLocaleDateString();
        }
        for(let m of d.dms){
            if(m.type=='signal_req'){ handleSignalReq(m); continue; }
            if(m.type=='signal_ack'){ handleSignalAck(m); continue; }
            if(m.type=='delete'){ await removeMsg('dm',m.from_user,m.extra_data); continue; }
            if(m.type=='read'){ 
                let h=await get('dm',m.from_user); 
                h.forEach(x=>{if(x.from_user==ME && x.timestamp<=m.extra_data)x.read=true}); 
                await save('dm',m.from_user,h); if(S.id==m.from_user) renderChat(); 
                continue; 
            }
            if(m.type=='enc'){ try{m.message=await dec(m.from_user,m.message,m.extra_data)}catch(e){m.message="[Encrypted]"} }
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
} catch(e){ console.error("Poll error:", e); }
}

function notify(id, text, type) {
    if(S.type === type && S.id == id && document.hasFocus()) return;
    if(S.notifs.some(n => n.id == id && n.text == text)) return;
    let title = type=='dm'?id:(type=='public'?'Public Chat':(S.groups[id]?S.groups[id].name:'Group'));
    S.notifs.unshift({id, type, text, title: title, time:new Date()});
    updateNotifUI();
    document.getElementById(type=='dm'?'badge-chats':'badge-groups').style.display = 'block';

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
    switchTab(n.type == 'dm' ? 'chats' : (n.type=='public'?'public':'groups'));
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
    if(m.type=='react'){
        let tg=h.find(x=>x.timestamp==m.extra_data);
        if(tg){ if(!tg.reacts)tg.reacts={}; tg.reacts[m.from_user]=m.message; await save(t,i,h); if(S.id==i && S.type==t) renderChat(); }
        return;
    }
    h.push(m); await save(t,i,h);
    if(S.id==i && S.type==t) {
        let prev = h.length>1 ? h[h.length-2] : null;
        let show = (t=='public'||t=='group') && m.from_user!=ME && (!prev || prev.from_user!=m.from_user);
        document.getElementById('msgs').appendChild(createMsgNode(m, show));
        scrollToBottom(false);
    }
}
async function removeMsg(t,i,ts){
    let h = await get(t,i);
    let idx=h.findIndex(x=>x.timestamp==ts);
    if(idx!=-1){ h.splice(idx,1); await save(t,i,h); if(S.id==i && S.type==t) renderChat(); }
}

async function startE2EE(){
    if(!window.crypto || !window.crypto.subtle) { alertModal('Error', 'Encryption requires HTTPS'); return; }
    if(S.type!='dm'||S.e2ee[S.id])return;
    let exp=await window.crypto.subtle.exportKey("jwk",S.keys.pub);
    req('send', {to_user:S.id,message:JSON.stringify(exp),type:'signal_req'});
    alertModal("Security", "Encryption request sent. Waiting for approval...");
}
async function handleSignalReq(m){
    confirmModal("Encryption Request", m.from_user + " wants to start a secure chat.", async (yes)=>{
        if(yes){
            let fk=await window.crypto.subtle.importKey("jwk",JSON.parse(m.message),{name:"ECDH",namedCurve:"P-256"},true,[]);
            await saveSession(m.from_user, await window.crypto.subtle.deriveKey({name:"ECDH",public:fk},S.keys.priv,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]));
            let exp=await window.crypto.subtle.exportKey("jwk",S.keys.pub);
            req('send', {to_user:m.from_user, message:JSON.stringify(exp), type:'signal_ack'});
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

async function renderLists(){
    try {
        let dh='';
        let filter = document.getElementById('chat-search').value.toLowerCase();
        let keys = (await dbOp('readonly', s => s.getAllKeys())) || [];
        for(let k of keys){
            if(k.startsWith('mw_dm_')){
                let u=k.split('mw_dm_')[1];
                if(filter && !u.toLowerCase().includes(filter)) continue;
                let h = await get('dm', u);
                let sec=S.e2ee[u]?' e2ee-on':'';
                let last=h.length?h[h.length-1].message:'Start chatting';
                if(last.length>30)last=last.substring(0,30)+'...';
                let ou=S.online.find(x=>x.username==u);
                let av=ou?ou.avatar:'';
                dh+=`<div class="list-item ${S.id==u?'active':''}" onclick="openChat('dm','${u}')" oncontextmenu="onChatListContext(event, 'dm', '${u}')">
                    <div class="avatar" style="background-image:url('${av}')">${av?'':u[0].toUpperCase()}</div>
                    <div style="flex:1"><div style="font-weight:bold">${u} ${ou?'<span style="color:#0f0;font-size:0.8em">●</span>':''}</div><div style="font-size:0.8em;color:#888">${last}</div></div>
                    <div class="btn-icon${sec}"><svg viewBox="0 0 24 24" width="16"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-9-2c0-1.66 1.34-3 3-3s3 1.34 3 3v2H9V6zm9 14H6V10h12v10zm-6-3c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2z"/></svg></div></div>`;
            }
        }
        document.getElementById('list-chats').innerHTML=dh;
        let gh='';
        Object.values(S.groups).forEach(g=>{
            if(filter && !g.name.toLowerCase().includes(filter)) return;
            gh+=`<div class="list-item ${S.id==g.id?'active':''}" onclick="openChat('group',${g.id})" oncontextmenu="onChatListContext(event, 'group', ${g.id})">
                <div class="avatar">#</div>
                <div><div style="font-weight:bold">${g.name}</div><div style="font-size:0.8em;color:#888">${g.type}</div></div>
            </div>`;
        });
        document.getElementById('list-groups').innerHTML=gh;
        document.getElementById('online-count').innerText=S.online.length;
    } catch(e) { console.error("RenderLists error", e); }
}

async function openChat(t,i){
    if(S.id!=i) lastRead=0;
    S.type=t; S.id=i;
    renderLists();
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
        tit=S.groups[i].name; sub='Group';
        document.getElementById('chat-av').innerText='#';
    } else if(t=='public') {
        tit="Public Chat"; sub="Global Room (5m TTL)";
        document.getElementById('chat-av').innerText='P';
    }
    document.getElementById('btn-e2ee').classList.toggle('e2ee-on', S.e2ee[S.id]);
    document.getElementById('chat-title').innerText=tit;
    document.getElementById('chat-sub').innerText=sub;
    document.getElementById('txt').placeholder = (t=='dm' && S.e2ee[S.id]) ? "Type an encrypted message..." : "Type a message...";
    
    if(t=='dm'){ let h=await get('dm',i); let last=h.filter(x=>x.from_user==i).pop(); if(last && last.timestamp>lastRead){ lastRead=last.timestamp; req('send',{to_user:i,type:'read',extra:last.timestamp}); } }
}

function createMsgNode(m, showSender){
    let div=document.createElement('div');
    div.className=`msg ${m.from_user==ME?'out':'in'} ${m.pinned?'pinned':''}`;
    let sender='';
    if(showSender) sender=`<div class="msg-sender" onclick="if(ME!='${m.from_user}'){openChat('dm','${m.from_user}');switchTab('chats');}">${m.from_user}</div>`;

    let txt=esc(m.message);
    if(m.type=='image') txt=`<img src="${m.message}" onclick="window.open(this.src)" onload="scrollToBottom(false)">`;
    else if(m.type=='audio') txt=`<div class="audio-player"><button class="play-btn" onclick="playAudio(this)"><svg viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg></button><div class="audio-progress" onclick="seekAudio(this, event)"><div class="audio-bar"></div></div><div class="audio-time">0:00</div><audio src="${m.message}" style="display:none" onloadedmetadata="this.parentElement.querySelector('.audio-time').innerText=formatTime(this.duration)"></audio></div>`;
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
        c.appendChild(createMsgNode(m, show));
        last=m.from_user;
    });
}

function closeChat() {
    if(S.id) { let c=document.getElementById('msgs'); if(c.scrollHeight - c.scrollTop - c.clientHeight > 50) S.scroll[S.type+'_'+S.id] = c.scrollTop; else delete S.scroll[S.type+'_'+S.id]; }
    document.getElementById('main-view').classList.remove('active');
    document.getElementById('nav-panel').classList.remove('hidden');
    S.id=null;
}

async function send(){
    let txt=document.getElementById('txt').value.trim();
    if(!txt)return;
    
    // Optimistic UI
    document.getElementById('txt').value=''; 
    cancelReply();
    
    let ts = Math.floor(Date.now()/1000);
    let msgObj = {
        from_user: ME,
        message: txt,
        type: 'text',
        timestamp: ts,
        reply_to_id: S.reply,
        pending: true
    };
    await store(S.type, S.id, msgObj);
    scrollToBottom(true);

    // Prepare Network Request
    let load = { message: txt, type: 'text', reply_to: S.reply, timestamp: ts };
    if(S.type=='dm') load.to_user=S.id; else if(S.type=='group'||S.type=='channel') load.group_id=S.id; else if(S.type=='public') load.group_id=-1;

    try {
        if(S.type=='dm' && S.e2ee[S.id]){
            let e=await enc(S.id,txt);
            load.message=e.c; load.extra=e.i; load.type='enc';
        }
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
        <div class="ctx-item red-text" onclick="ctxAction('delete')">Delete</div>`;
    } else if(type == 'chat_list') {
        html = `<div class="ctx-item" onclick="ctxAction('open')">Open</div>
        <div class="ctx-item" onclick="ctxAction('clear')">Clear History</div>
        <div class="ctx-separator"></div>
        <div class="ctx-item red-text" onclick="ctxAction('del_chat')">Delete Chat</div>`;
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
}

function onChatListContext(e, type, id) { showContextMenu(e, 'chat_list', {type, id}); }

async function ctxAction(act, arg) {
    document.getElementById('ctx-menu').style.display='none';
    let c = S.ctx;
    if(!c) return;
    
    if(c.type == 'message') {
        let m = c.data;
        if(act=='react') await sendReact(m.timestamp, arg);
        else if(act=='reply') { S.reply=m.timestamp; document.getElementById('reply-ui').style.display='flex'; document.getElementById('reply-txt').innerText="Replying to "+m.from_user; document.getElementById('del-btn').style.display='none'; document.getElementById('txt').focus(); }
        else if(act=='forward') promptModal("Forward", "Username:", u=>{ if(u) req('send',{message:m.message,type:m.type,extra:m.extra_data,to_user:u}); });
        else if(act=='copy') { if(m.type=='text') navigator.clipboard.writeText(m.message); }
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

async function uploadFile(inp){
    let f=inp.files[0]; if(!f)return;
    
    // Compress Image
    let fileToSend = f;
    let dataUrl = null;
    if(f.type.startsWith('image/') && f.type !== 'image/gif'){
        try {
            let img = await new Promise((res,rej)=>{let i=new Image();i.onload=()=>res(i);i.onerror=rej;i.src=URL.createObjectURL(f);});
            let cvs = document.createElement('canvas');
            let w=img.width, h=img.height, max=1600;
            if(w>max||h>max){ if(w>h){h*=max/w;w=max;}else{w*=max/h;h=max;} }
            cvs.width=w; cvs.height=h;
            cvs.getContext('2d').drawImage(img,0,0,w,h);
            dataUrl = cvs.toDataURL('image/jpeg', 0.8);
            let blob = await new Promise(r=>cvs.toBlob(r,'image/jpeg',0.8));
            fileToSend = new File([blob], f.name, {type:'image/jpeg'});
        } catch(e){ console.log("Compression failed", e); }
    }

    let fd = new FormData();
    fd.append('file', fileToSend);
    let ts = Math.floor(Date.now()/1000);
    fd.append('timestamp', ts);
    if(S.type=='dm') fd.append('to_user', S.id);
    else if(S.type=='group'||S.type=='channel') fd.append('group_id', S.id);
    else fd.append('group_id', -1);

    fetch('?action=upload_msg', { method:'POST', body:fd, headers:{'X-CSRF-Token': CSRF_TOKEN} })
    .then(r=>r.json())
    .then(d=>{
        if(d.status!='success') alertModal('Error', d.message||'Upload failed');
    });
    
    // Optimistic render (read locally)
    if(dataUrl) {
        await store(S.type,S.id,{from_user:ME,message:dataUrl,type:'image',timestamp:ts,extra_data:f.name});
    } else {
        let r = new FileReader();
        r.onload = async () => {
            let type = f.type.startsWith('image/') ? 'image' : 'file';
            await store(S.type,S.id,{from_user:ME,message:r.result,type:type,timestamp:ts,extra_data:f.name});
        };
        r.readAsDataURL(f);
    }
}

function downloadFile(data, name){
    let a = document.createElement('a'); a.href = data; a.download = name; a.click();
}

function cancelReply(){ S.reply=null; document.getElementById('reply-ui').style.display='none'; document.getElementById('del-btn').style.display='none'; }
function promptChat(){ promptModal("New Chat", "Username:", async (u)=>{ if(u){ let ex=await get('dm',u); if(!ex.length) await save('dm',u,[]); openChat('dm',u); switchTab('chats'); }}); }
function createGroup(){ createEntity('group'); }
function createChannel(){ createEntity('channel'); }
function createEntity(type){ let label = type=='channel'?'Channel':'Group'; alertModal("Create "+label, ""); document.getElementById('modal-ok').style.display='none'; document.getElementById('modal-cancel').style.display='block'; document.getElementById('modal-body').innerHTML = \`<input id="ng-name" class="form-input" placeholder="\${label} Name"><select id="ng-type" class="form-select"><option value="public">Public (Code)</option><option value="discoverable">Discoverable (Listed)</option><option value="private">Private (Invite Only)</option></select><button class="btn-primary" style="width:100%;margin-top:10px" onclick="doCreateGroup('\${type}')">Create</button>\`; }
function doCreateGroup(cat){ let n=document.getElementById('ng-name').value; let t=document.getElementById('ng-type').value; let btn=document.querySelector('#modal-body button'); if(n) { btn.disabled=true; btn.innerText='Creating...'; req('create_group',{name:n,type:t,category:cat}).then(r=>r.json()).then(d=>{ if(d.status=='success'){ document.getElementById('app-modal').style.display='none'; renderLists(); } else { alert(d.message||'Error'); btn.disabled=false; btn.innerText='Create'; } }).catch(()=>{ alert('Connection failed'); btn.disabled=false; btn.innerText='Create'; }); } }
function joinGroup(){ alertModal("Join Group", ""); document.getElementById('modal-body').innerHTML = \`<input id="jg-code" class="form-input" placeholder="Invite Code"><input id="jg-pass" class="form-input" type="password" placeholder="Password (Optional)"><button class="btn-primary" style="width:100%;margin-top:10px" onclick="doJoinGroup()">Join</button>\`; }
function doJoinGroup(){ let c=document.getElementById('jg-code').value; let p=document.getElementById('jg-pass').value; if(c) req('join_group',{code:c, password:p}).then(r=>r.json()).then(d=>{ if(d.status=='success'){ document.getElementById('app-modal').style.display='none'; renderLists(); } else alert(d.message); }); }
function saveSettings(){ req('update_profile',{bio:document.getElementById('set-bio').value,avatar:document.getElementById('set-av').value,new_password:document.getElementById('set-pw').value}); alertModal("Settings", "Profile updated."); }
async function discover(cat){ startProg(); alertModal("Discover "+(cat=='channel'?'Channels':'Groups'), '<div class="tab-loader" style="min-height:150px"><div class="rail-letters"><span>m</span><span>o</span><span>R</span><span>e</span></div><div class="rail-dot"></div></div>'); let r=await fetch('?action=get_discoverable_groups&cat='+cat); endProg(); let d=await r.json(); let h='<div style="max-height:300px;overflow-y:auto">'; d.items.forEach(g=>{ h+=\`<div style="padding:10px;border-bottom:1px solid #333;display:flex;justify-content:space-between;align-items:center"><div><b>\${g.name}</b><br><span style="color:#888;font-size:0.8rem">Code: \${g.join_code}</span></div><button class="btn-sec" onclick="req('join_group',{code:'\${g.join_code}'}).then(()=>{document.getElementById('app-modal').style.display='none';renderLists()})">Join</button></div>\`; }); h+='</div>'; document.getElementById('modal-body').innerHTML=h; }

async function showProfilePopup() {
    if(S.type === 'dm') {
        startProg(); let r = await fetch('?action=get_profile&u='+S.id); endProg(); let p = await r.json(); if(p.status === 'error') return;
        let html = \`<div style="text-align:center;margin-bottom:15px"><div class="avatar" style="width:80px;height:80px;margin:0 auto 10px auto;font-size:2rem;background-image:url('\${p.avatar||''}')">\${p.avatar?'':p.username[0]}</div><b>\${p.username}</b><br><span style="color:#888;font-size:0.8rem">\${p.bio||'-'}</span><br><div style="font-size:0.8rem;color:#666;margin-top:5px">Joined: \${new Date(p.joined_at*1000).toLocaleDateString()}<br>Last Seen: \${new Date(p.last_seen*1000).toLocaleString()}</div>\${!S.e2ee[S.id] ? \`<button class="btn-sec" style="margin-top:15px;width:100%" onclick="startE2EE();document.getElementById('app-modal').style.display='none'">Enable End-to-End Encryption</button>\` : \`<div style="margin-top:15px;color:var(--accent)">🔒 Encrypted</div>\`}</div>\`;
        alertModal("Profile", ""); document.getElementById('modal-body').innerHTML = html;
    } else if (S.type === 'group' || S.type === 'channel') {
        startProg(); let r = await fetch('?action=get_group_details&id='+S.id); endProg(); let d = await r.json(); if(d.status === 'error') return;
        let html = \`<div style="text-align:center;margin-bottom:15px"><b>\${d.group.name}</b><br><span style="color:#888;font-size:0.8rem">\${d.group.category=='channel'?'Channel':'Group'} - \${d.group.type} \${d.group.join_code ? '| Code: '+d.group.join_code : ''}</span><br>\${d.is_owner && d.group.type=='private' ? \`<button class="btn-sec" style="font-size:0.7rem;margin-top:5px" onclick="groupSettings(\${S.id})">Manage Invite</button>\` : ''}\${!S.e2ee[S.id] && d.group.category!='channel' ? \`<button class="btn-sec" style="margin-top:10px;width:100%" onclick="startWEncrypt();document.getElementById('app-modal').style.display='none'">Enable WEncrypt</button>\` : \`\`}</div><div style="max-height:200px;overflow-y:auto;text-align:left;margin-bottom:15px;background:#222;padding:10px;border-radius:8px"><div style="font-size:0.8rem;color:#aaa;margin-bottom:5px">Members (\${d.members.length})</div>\${d.members.map(m=>\`<div style="padding:5px;border-bottom:1px solid #333;display:flex;align-items:center"><div class="avatar" style="width:24px;height:24px;font-size:0.8rem;margin-right:8px;background-image:url('\${m.avatar||''}')">\${m.avatar?'':m.username[0]}</div><span>\${m.username}</span> \${m.public_key?'<span title="Key Available" style="color:#0f0;font-size:0.6rem;margin-left:5px">🔑</span>':''}</div>\`).join('')}</div><div style="display:flex;gap:10px;justify-content:center"><button class="btn-modal btn-sec" style="color:#f55;border-color:#f55" onclick="leaveGroup(\${S.id})">Leave Group</button>\${d.is_owner ? \`<button class="btn-modal btn-sec" style="color:#f55;border-color:#f55" onclick="nukeGroup(\${S.id})">Delete Group</button>\` : ''}</div>\`;
        alertModal("Group Info", ""); document.getElementById('modal-body').innerHTML = html;
    }
}
function groupSettings(gid){ alertModal("Group Settings", ""); document.getElementById('modal-body').innerHTML = \`<div class="form-group"><label>Enable Joining</label> <input type="checkbox" id="gs-join"></div><div class="form-group"><label>Code Suffix (Letter)</label><input id="gs-suff" class="form-input" maxlength="1" placeholder="A-Z"></div><div class="form-group"><label>Password (Optional)</label><input id="gs-pass" class="form-input" type="password"></div><div class="form-group"><label>Expiry (Minutes)</label><input id="gs-exp" class="form-input" type="number" placeholder="60"></div><button class="btn-primary" style="width:100%;margin-top:10px" onclick="saveGroupSettings(\${gid})">Generate New Code</button>\`; }
function saveGroupSettings(gid){ let j = document.getElementById('gs-join').checked ? 1 : 0; let s = document.getElementById('gs-suff').value; let p = document.getElementById('gs-pass').value; let e = document.getElementById('gs-exp').value; req('update_group_settings', {group_id:gid, join_enabled:j, generate_code:true, suffix:s, password:p, expiry:e}).then(r=>r.json()).then(d=>{ if(d.status=='success') { alert("Settings updated & Code generated"); showProfilePopup(); } else alert(d.message); }); }
function leaveGroup(gid){ if(confirm("Leave this group?")) req('leave_group', {group_id: gid}).then(d=>{ if(d.status=='success'){ closeChat(); delete S.groups[gid]; renderLists(); document.getElementById('app-modal').style.display='none'; } }); }
function nukeGroup(gid){ if(confirm("Delete group for everyone?")) req('delete_group', {group_id: gid}).then(d=>{ if(d.status=='success'){ closeChat(); delete S.groups[gid]; renderLists(); document.getElementById('app-modal').style.display='none'; } }); }

function scrollToBottom(force){ 
    let c=document.getElementById('msgs'); 
    if(force) { c.scrollTop=c.scrollHeight; return; }
    if(c.scrollHeight - c.scrollTop - c.clientHeight < 150) c.scrollTo({ top: c.scrollHeight, behavior: 'smooth' });
}
function esc(t){ return t?t.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"):"" }
document.getElementById('txt').onkeydown=e=>{if(e.key=='Enter' && !e.shiftKey){e.preventDefault();send()}};

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

function playAudio(btn) { let player = btn.parentElement.querySelector('audio'); let bar = btn.parentElement.querySelector('.audio-bar'); let timeDisplay = btn.parentElement.querySelector('.audio-time'); if (currentAudio && currentAudio !== player) { currentAudio.pause(); if(currentBtn) { currentBtn.innerHTML = '<svg viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg>'; currentBtn.classList.remove('playing'); } clearInterval(updateInterval); } if (player.paused) { player.play(); currentAudio = player; currentBtn = btn; btn.innerHTML = '<svg viewBox="0 0 24 24"><path d="M6 19h4V5H6v14zm8-14v14h4V5h-4z"/></svg>'; btn.classList.add('playing'); updateInterval = setInterval(() => { let pct = (player.currentTime / player.duration) * 100; bar.style.width = pct + '%'; timeDisplay.innerText = formatTime(player.currentTime); }, 100); player.onended = () => { btn.innerHTML = '<svg viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg>'; btn.classList.remove('playing'); clearInterval(updateInterval); bar.style.width = '0%'; timeDisplay.innerText = formatTime(player.duration); }; } else { player.pause(); btn.innerHTML = '<svg viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg>'; btn.classList.remove('playing'); clearInterval(updateInterval); } }
function seekAudio(progress, e) { let player = progress.parentElement.querySelector('audio'); if(!player || !player.duration) return; let rect = progress.getBoundingClientRect(); let pos = (e.clientX - rect.left) / rect.width; player.currentTime = pos * player.duration; let bar = progress.querySelector('.audio-bar'); bar.style.width = (pos * 100) + '%'; }
function formatTime(s) { if(isNaN(s) || !isFinite(s)) return "0:00"; let m = Math.floor(s / 60); let sec = Math.floor(s % 60); return m + ':' + (sec < 10 ? '0' : '') + sec; }
document.getElementById('txt').oninput=()=>{
    if(S.type=='dm' && Date.now()-lastTyping>2000){ lastTyping=Date.now(); req('typing',{to:S.id}); }
};
window.onclick=(e)=>{
    if(!e.target.closest('.notif-btn') && !e.target.closest('.menu-btn'))toggleNotif(false);
    if(!e.target.closest('.menu-btn'))document.getElementById('chat-menu').style.display='none';
    if(!e.target.closest('.ctx-menu') && !e.target.closest('.msg')) document.getElementById('ctx-menu').style.display='none';
};
window.oncontextmenu = (e) => {
    if(e.defaultPrevented) return;
    if(e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.isContentEditable) return;
    showContextMenu(e, 'app', null);
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

if('serviceWorker' in navigator)navigator.serviceWorker.register('?action=sw');
init().catch(e=>console.error(e));
</script>
</body>
</html>
"""

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
