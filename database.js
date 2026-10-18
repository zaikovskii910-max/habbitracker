const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const path = require("path");
const fs = require("fs");

const DATA_DIR = process.env.DATA_DIR || __dirname;

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const db = new Database(
  path.join(DATA_DIR, "database.sqlite")
);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password TEXT NOT NULL,
    premium INTEGER DEFAULT 0,
    admin INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS habits (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    type TEXT NOT NULL,
    emoji TEXT DEFAULT '✨',
    created_at TEXT NOT NULL,

    FOREIGN KEY(user_id)
      REFERENCES users(id)
      ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS habit_days (
    habit_id TEXT NOT NULL,
    date TEXT NOT NULL,
    completed INTEGER DEFAULT 1,

    PRIMARY KEY(habit_id, date),

    FOREIGN KEY(habit_id)
      REFERENCES habits(id)
      ON DELETE CASCADE
  );
`);

// Создание главного администратора.
// Пароль задаётся переменной окружения.

const adminUsername = "pedik";
const adminPassword = process.env.ADMIN_PASSWORD;

if (!adminPassword) {
  throw new Error(
    "Необходимо установить ADMIN_PASSWORD в переменных окружения."
  );
}

const existingAdmin = db.prepare(`
  SELECT id FROM users WHERE username = ?
`).get(adminUsername);

if (!existingAdmin) {
  const hash = bcrypt.hashSync(adminPassword, 12);

  db.prepare(`
    INSERT INTO users (
      username,
      password,
      premium,
      admin
    )
    VALUES (?, ?, 1, 1)
  `).run(adminUsername, hash);

  console.log("Администратор создан.");
}

module.exports = db;
