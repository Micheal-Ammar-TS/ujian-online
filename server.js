// server.js
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('./db');
const createCsvWriter = require('csv-writer').createObjectCsvWriter;
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'verysecret_dev_key';

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// helpers
function sign(user) {
  return jwt.sign({ id: user.id, role: user.role, email: user.email }, JWT_SECRET, { expiresIn: '8h' });
}
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if(!auth) return res.status(401).json({ error: 'No token' });
  const token = auth.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch(e) { return res.status(401).json({ error: 'Invalid token' }); }
}
function adminOnly(req,res,next){
  if(req.user && req.user.role === 'admin') return next();
  return res.status(403).json({ error: 'Admin only' });
}

// -------- AUTH --------
app.post('/api/register', async (req,res) => {
  const { name, email, password } = req.body;
  if(!email || !password) return res.status(400).json({ error:'email/password required' });
  const hashed = await bcrypt.hash(password, 10);
  try {
    const stmt = db.prepare('INSERT INTO users (name,email,password) VALUES (?,?,?)');
    const info = stmt.run(name||'', email, hashed);
    const user = db.prepare('SELECT id,name,email,role FROM users WHERE id=?').get(info.lastInsertRowid);
    return res.json({ user, token: sign(user) });
  } catch(e) {
    return res.status(400).json({ error: 'Email mungkin sudah terdaftar' });
  }
});

app.post('/api/login', async (req,res) => {
  const { email, password } = req.body;
  if(!email || !password) return res.status(400).json({ error:'email/password required' });
  const user = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if(!user) return res.status(401).json({ error:'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.password);
  if(!ok) return res.status(401).json({ error:'Invalid credentials' });
  const safe = { id: user.id, name: user.name, email: user.email, role: user.role };
  return res.json({ user: safe, token: sign(safe) });
});

// -------- ADMIN: create exam & questions --------
app.post('/api/admin/exams', authMiddleware, adminOnly, (req,res) => {
  const { title, duration_minutes } = req.body;
  if(!title) return res.status(400).json({ error:'title required' });
  const info = db.prepare('INSERT INTO exams (title,duration_minutes) VALUES (?,?)').run(title, duration_minutes||30);
  const exam = db.prepare('SELECT * FROM exams WHERE id=?').get(info.lastInsertRowid);
  res.json({ exam });
});

app.post('/api/admin/exams/:examId/questions', authMiddleware, adminOnly, (req,res) => {
  const examId = Number(req.params.examId);
  const { text, options, answer_index } = req.body;
  if(!text || !Array.isArray(options) || typeof answer_index !== 'number') return res.status(400).json({ error:'bad payload' });
  const stmt = db.prepare('INSERT INTO questions (exam_id,text,options,answer_index) VALUES (?,?,?,?)');
  const info = stmt.run(examId, text, JSON.stringify(options), answer_index);
  const q = db.prepare('SELECT * FROM questions WHERE id=?').get(info.lastInsertRowid);
  q.options = JSON.parse(q.options);
  res.json({ question: q });
});

app.post('/api/admin/exams/:examId/publish', authMiddleware, adminOnly, (req,res) => {
  const examId = Number(req.params.examId);
  db.prepare('UPDATE exams SET published=1 WHERE id=?').run(examId);
  res.json({ ok:true });
});

app.get('/api/admin/export/:examId', authMiddleware, adminOnly, (req,res) => {
  const examId = Number(req.params.examId);
  const attempts = db.prepare('SELECT a.*, u.name, u.email FROM attempts a JOIN users u ON u.id=a.user_id WHERE a.exam_id=?').all(examId);
  // prepare csv
  const csvWriter = createCsvWriter({
    path: `export_exam_${examId}.csv`,
    header: [
      {id:'id', title:'ID'},
      {id:'user', title:'User'},
      {id:'email', title:'Email'},
      {id:'score', title:'Score'},
      {id:'started_at', title:'Started At'},
      {id:'submitted_at', title:'Submitted At'},
      {id:'answers', title:'Answers'}
    ]
  });
  const rows = attempts.map(a => ({ id: a.id, user: a.name, email: a.email, score: a.score, started_at: a.started_at, submitted_at: a.submitted_at, answers: a.answers }));
  csvWriter.writeRecords(rows).then(()=> {
    res.download(path.resolve(`export_exam_${examId}.csv`));
  }).catch(err => res.status(500).json({ error: 'Export gagal' }));
});

// -------- PUBLIC / STUDENT API --------
app.get('/api/exams', authMiddleware, (req,res) => {
  const exams = db.prepare('SELECT id,title,duration_minutes,published FROM exams WHERE published=1').all();
  res.json({ exams });
});

app.get('/api/exams/:examId/questions', authMiddleware, (req,res) => {
  const examId = Number(req.params.examId);
  const questions = db.prepare('SELECT id,text,options FROM questions WHERE exam_id=?').all(examId)
    .map(q => ({ id:q.id, text:q.text, options: JSON.parse(q.options) }));
  res.json({ questions });
});

// start attempt
app.post('/api/exams/:examId/start', authMiddleware, (req,res) => {
  const examId = Number(req.params.examId);
  const userId = req.user.id;
  // create attempt row
  const info = db.prepare('INSERT INTO attempts (exam_id,user_id) VALUES (?,?)').run(examId, userId);
  const attempt = db.prepare('SELECT * FROM attempts WHERE id=?').get(info.lastInsertRowid);
  res.json({ attemptId: attempt.id, started_at: attempt.started_at });
});

// submit answers
app.post('/api/exams/:examId/submit', authMiddleware, (req,res) => {
  const examId = Number(req.params.examId);
  const { attemptId, answers } = req.body; // answers = [index, null, index...]
  if(!Array.isArray(answers)) return res.status(400).json({ error:'answers array required' });
  // fetch questions & compute score
  const qs = db.prepare('SELECT id,answer_index FROM questions WHERE exam_id=?').all(examId);
  const total = qs.length;
  let correct = 0;
  const map = new Map(qs.map(q=>[q.id, q.answer_index]));
  // answers should align with questions order on client; for safety, accept [ {questionId, answer} ] or simple array in order
  // here we assume client sends array of objects: { questionId, answerIndex }
  if(answers.length && answers[0].questionId !== undefined){
    answers.forEach(a => {
      const correctIndex = map.get(a.questionId);
      if(correctIndex !== undefined && a.answerIndex === correctIndex) correct++;
    });
  } else {
    // fallback: treat answers as array of indexes in same order as qs
    for(let i=0;i<qs.length;i++){
      const chosen = answers[i];
      if(chosen === qs[i].answer_index) correct++;
    }
  }
  const score = total ? (correct / total) * 100 : 0;
  db.prepare('UPDATE attempts SET answers=?, submitted_at=CURRENT_TIMESTAMP, score=? WHERE id=?')
    .run(JSON.stringify(answers), score, attemptId);
  res.json({ score, correct, total });
});

// simple helper to create initial admin (if none)
(function ensureAdmin(){
  const row = db.prepare('SELECT * FROM users WHERE role="admin" LIMIT 1').get();
  if(!row){
    const bcrypt = require('bcrypt');
    const pw = 'admin123';
    bcrypt.hash(pw,10).then(hash=>{
      db.prepare('INSERT INTO users (name,email,password,role) VALUES (?,?,?,?)').run('Admin','admin@example.com',hash,'admin');
      console.log('Created default admin: admin@example.com / admin123 — please change password!');
    });
  }
})();

// fallback: serve SPA index
app.get('*', (req,res) => {
  res.sendFile(path.resolve(__dirname, 'public', 'index.html'));
});

app.listen(PORT, ()=> console.log(`CBT app running on http://localhost:${PORT}`));