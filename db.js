const Database = require('better-sqlite3')
const db = new Database('auth_demo.db')

// Création de la table avec `username` UNIQUE
db.prepare(
  `
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT,
    two_factor_secret TEXT,
    two_factor_enabled INTEGER DEFAULT 0
  )
`
).run()

const userColumns = db.prepare('PRAGMA table_info(users)').all().map(column => column.name)

if (!userColumns.includes('two_factor_secret')) {
  db.prepare('ALTER TABLE users ADD COLUMN two_factor_secret TEXT').run()
}

if (!userColumns.includes('two_factor_enabled')) {
  db.prepare('ALTER TABLE users ADD COLUMN two_factor_enabled INTEGER DEFAULT 0').run()
}

// Création de la table reports liée aux utilisateurs
db.prepare(
  `
  CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    mission_note TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )
`
).run()

db.prepare(
  `
  CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )
`
).run()

module.exports = db
