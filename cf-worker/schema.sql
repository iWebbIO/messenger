CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    avatar TEXT, 
    joined_at INTEGER,
    last_seen INTEGER,
    typing_to TEXT,
    typing_at INTEGER,
    bio TEXT,
    public_key TEXT
);

CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    type TEXT,
    owner_id INTEGER,
    join_code TEXT,
    created_at INTEGER,
    password TEXT,
    invite_expiry INTEGER,
    join_enabled INTEGER DEFAULT 1,
    category TEXT DEFAULT 'group'
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id INTEGER,
    user_id INTEGER,
    last_received_id INTEGER DEFAULT 0,
    PRIMARY KEY (group_id, user_id)
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER DEFAULT NULL, 
    from_user TEXT,
    to_user TEXT,
    message TEXT,
    type TEXT DEFAULT 'text',
    reply_to_id INTEGER,
    extra_data TEXT,
    timestamp INTEGER
);

CREATE INDEX IF NOT EXISTS idx_msg_to ON messages(to_user);
CREATE INDEX IF NOT EXISTS idx_msg_group ON messages(group_id);
CREATE INDEX IF NOT EXISTS idx_msg_ts ON messages(timestamp);