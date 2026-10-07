const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const express = require('express');
const multer = require('multer');

const app = express();
const port = Number(process.env.PORT) || 3000;
const adminUser = process.env.ADMIN_USER || 'admin';
const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';
const levels = ['L3NIT', 'L4NIT', 'L5NIT'];
const sessions = new Map();
const failedLogins = new Map();
const sessionTimeout = 12 * 60 * 60 * 1000;
const dataDirectory = path.join(__dirname, 'data');
const uploadsDirectory = path.join(dataDirectory, 'uploads');
const notesDatabase = path.join(dataDirectory, 'notes.json');

fs.mkdirSync(uploadsDirectory, { recursive: true });

function loadNotes() {
  if (!fs.existsSync(notesDatabase)) {
    return [];
  }

  return JSON.parse(fs.readFileSync(notesDatabase, 'utf8'));
}

function saveNotes(notes) {
  fs.writeFileSync(notesDatabase, JSON.stringify(notes, null, 2));
}

const upload = multer({
  storage: multer.diskStorage({
    destination: uploadsDirectory,
    filename: (_request, file, callback) => {
      const extension = path.extname(file.originalname);
      callback(null, `${crypto.randomUUID()}${extension}`);
    }
  }),
  limits: {
    fileSize: 25 * 1024 * 1024
  }
});

function getBearerToken(request) {
  return (request.get('authorization') || '').replace(/^Bearer\s+/i, '');
}

function secureCompare(left, right) {
  const leftHash = crypto.createHash('sha256').update(String(left)).digest();
  const rightHash = crypto.createHash('sha256').update(String(right)).digest();
  return leftHash.length === rightHash.length && crypto.timingSafeEqual(leftHash, rightHash);
}

function requireAuthentication(request, response, next) {
  const token = getBearerToken(request);
  const session = sessions.get(token);

  if (session && session > Date.now()) {
    return next();
  }

  sessions.delete(token);
  return response.status(401).json({ error: 'Please log in first' });
}

function getFailedLogin(ipAddress) {
  const current = failedLogins.get(ipAddress);
  if (!current || Date.now() - current.timestamp > 10 * 60 * 1000) {
    return { attempts: 0, timestamp: Date.now() };
  }

  return current;
}

app.use(express.json());
app.use('/files', express.static(uploadsDirectory));
app.use(express.static(__dirname, { index: 'index.html' }));

app.post('/api/login', (request, response) => {
  const ipAddress = request.ip;
  const failedLogin = getFailedLogin(ipAddress);

  if (failedLogin.attempts >= 5) {
    return response.status(429).json({ error: 'Too many attempts. Try again in 10 minutes.' });
  }

  const { username, password } = request.body || {};
  const validCredentials = secureCompare(username, adminUser)
    && secureCompare(password, adminPassword);

  if (!validCredentials) {
    failedLogin.attempts += 1;
    failedLogins.set(ipAddress, failedLogin);
    return response.status(401).json({ error: 'Wrong username or password' });
  }

  failedLogins.delete(ipAddress);
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, Date.now() + sessionTimeout);
  return response.json({ token, username: adminUser });
});

app.post('/api/logout', (request, response) => {
  sessions.delete(getBearerToken(request));
  return response.json({ ok: true });
});

app.get('/api/me', requireAuthentication, (_request, response) => {
  response.json({ ok: true });
});

app.get('/api/notes', (request, response) => {
  let notes = loadNotes();
  const selectedLevel = request.query.level;
  const searchQuery = request.query.q;

  if (selectedLevel) {
    notes = notes.filter((note) => note.level === selectedLevel);
  }

  if (searchQuery) {
    const normalizedQuery = String(searchQuery).toLowerCase();
    notes = notes.filter((note) => {
      const searchableText = `${note.title} ${note.module} ${note.content}`.toLowerCase();
      return searchableText.includes(normalizedQuery);
    });
  }

  notes.sort((first, second) => second.created - first.created);
  return response.json(notes);
});

app.post('/api/notes', requireAuthentication, upload.single('file'), (request, response) => {
  const { level, title, module, content } = request.body;

  if (!levels.includes(level) || !title) {
    return response.status(400).json({ error: 'Level and title required' });
  }

  const note = {
    id: crypto.randomUUID(),
    level,
    title,
    module: module || '',
    content: content || '',
    created: Date.now(),
    file: request.file ? {
      name: request.file.originalname,
      url: `/files/${request.file.filename}`,
      stored: request.file.filename
    } : null
  };

  const notes = loadNotes();
  notes.push(note);
  saveNotes(notes);
  return response.status(201).json(note);
});

app.put('/api/notes/:id', requireAuthentication, (request, response) => {
  const notes = loadNotes();
  const noteIndex = notes.findIndex((note) => note.id === request.params.id);

  if (noteIndex < 0) {
    return response.status(404).json({ error: 'Not found' });
  }

  const { title, module, content, level } = request.body;
  if (levels.includes(level)) {
    notes[noteIndex].level = level;
  }
  if (title) {
    notes[noteIndex].title = title;
  }
  if (module !== undefined) {
    notes[noteIndex].module = module;
  }
  if (content !== undefined) {
    notes[noteIndex].content = content;
  }

  saveNotes(notes);
  return response.json(notes[noteIndex]);
});

app.delete('/api/notes/:id', requireAuthentication, (request, response) => {
  const notes = loadNotes();
  const note = notes.find((item) => item.id === request.params.id);

  if (!note) {
    return response.status(404).json({ error: 'Not found' });
  }

  if (note.file) {
    fs.rmSync(path.join(uploadsDirectory, note.file.stored), { force: true });
  }

  saveNotes(notes.filter((item) => item.id !== note.id));
  return response.json({ ok: true });
});

if (require.main === module) {
  app.listen(port, () => {
    console.log(`NIT Notes running: http://localhost:${port}`);
  });
}

module.exports = app;
