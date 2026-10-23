CREATE TABLE IF NOT EXISTS live_rooms (
    Id          INTEGER PRIMARY KEY AUTOINCREMENT,
    live_id     VARCHAR(30) NOT NULL UNIQUE,
    user_id     VARCHAR(20) NOT NULL DEFAULT 'admin',
    房间人数    INTEGER,
    添加时间    TIMESTAMP NOT NULL DEFAULT (datetime('now', 'localtime')),
    修改时间    TIMESTAMP NOT NULL DEFAULT (datetime('now', 'localtime')),
    提取时间    DATETIME,
    提取次数    INTEGER NOT NULL DEFAULT 1
);