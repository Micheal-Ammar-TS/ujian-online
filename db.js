// db.js
const Database = require('better-sqlite3');
const db = new Database('data.sqlite');

// init schema
db.exec(`
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  email TEXT UNIQUE,
  password TEXT,
  role TEXT DEFAULT 'student',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS exams (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT,
  duration_minutes INTEGER,
  published INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS questions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  exam_id INTEGER,
  text TEXT,
  options TEXT, -- JSON array
  answer_index INTEGER, -- 0-based correct index
  FOREIGN KEY(exam_id) REFERENCES exams(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  exam_id INTEGER,
  user_id INTEGER,
  started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  submitted_at DATETIME,
  score REAL,
  answers TEXT, -- JSON array of chosen indexes or null
  FOREIGN KEY(exam_id) REFERENCES exams(id),
  FOREIGN KEY(user_id) REFERENCES users(id)
);
`);

module.exports = db;