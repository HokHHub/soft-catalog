const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const helmet = require('helmet');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const isProd = process.env.NODE_ENV === 'production';

app.disable('x-powered-by');

// Ensure upload dirs exist
const uploadsDir = path.join(__dirname, 'data', 'uploads');
const iconsDir = path.join(__dirname, 'public', 'icons');
[uploadsDir, iconsDir].forEach(d => fs.mkdirSync(d, { recursive: true }));

const SESSION_SECRET = process.env.SESSION_SECRET || `dev-${crypto.randomBytes(32).toString('hex')}`;
if (!process.env.SESSION_SECRET) {
  console.warn('⚠️ SESSION_SECRET not set. Using a temporary in-memory secret for this run.');
}

function safeFilename(name) {
  const base = path.basename(String(name || 'file'));
  return base.replace(/[^a-zA-Z0-9._-]+/g, '_').slice(0, 140) || 'file.bin';
}

function randomPrefix() {
  return `${Date.now()}-${crypto.randomBytes(6).toString('hex')}`;
}

const storageFiles = multer.diskStorage({
  destination: uploadsDir,
  filename: (req, file, cb) => cb(null, `${randomPrefix()}-${safeFilename(file.originalname)}`),
});
const storageIcons = multer.diskStorage({
  destination: iconsDir,
  filename: (req, file, cb) => cb(null, `${randomPrefix()}-${safeFilename(file.originalname)}`),
});

function iconFileFilter(req, file, cb) {
  if (!file.mimetype || !file.mimetype.startsWith('image/')) {
    return cb(new Error('Only image files are allowed for icons'));
  }
  cb(null, true);
}

function programFileFilter(req, file, cb) {
  const ext = path.extname(file.originalname || '').toLowerCase();
  const allowed = new Set([
    '.exe', '.msi', '.zip', '.7z', '.rar', '.tar', '.gz', '.bz2', '.xz',
    '.deb', '.rpm', '.dmg', '.pkg', '.appimage', '.iso',
  ]);
  if (!allowed.has(ext)) {
    return cb(new Error('Unsupported file format'));
  }
  cb(null, true);
}

const uploadFile = multer({
  storage: storageFiles,
  fileFilter: programFileFilter,
  limits: { fileSize: 1024 * 1024 * 1024 }, // 1 GB
});

const uploadIcon = multer({
  storage: storageIcons,
  fileFilter: iconFileFilter,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB
});

app.use(
  helmet({
    contentSecurityPolicy: false, // pages use inline styles/scripts for now
    crossOriginEmbedderPolicy: false,
  })
);
app.use(express.json({ limit: '100kb' }));
app.use(
  session({
    name: 'softhub.sid',
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: isProd,
      maxAge: 1000 * 60 * 60 * 12, // 12 hours
    },
  })
);
app.use(express.static(path.join(__dirname, 'public')));

// ─── Auth ────────────────────────────────────────────────────────────────────
function adminAuth(req, res, next) {
  if (!req.session || !req.session.isAdmin) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

function adminCsrf(req, res, next) {
  const token = req.headers['x-csrf-token'];
  if (!token || token !== req.session.csrfToken) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  next();
}

const adminWriteAuth = [adminAuth, adminCsrf];

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Try again later.' },
});

// ─── Public API ──────────────────────────────────────────────────────────────

app.get('/api/info', (req, res) => res.json(db.getPublicSettings()));

app.get('/api/categories', (req, res) => res.json(db.getCategories()));

app.get('/api/programs', (req, res) => {
  const { category, search, limit, offset } = req.query;
  res.json(db.getPrograms({ category, search, limit: Number(limit) || 100, offset: Number(offset) || 0 }));
});

app.get('/api/programs/:id', (req, res) => {
  const p = db.getProgramById(req.params.id);
  if (!p) return res.status(404).json({ error: 'Not found' });
  res.json(p);
});

app.get('/api/download/:id', (req, res) => {
  const p = db.incrementDownload(req.params.id);
  if (!p || !p.filename) return res.status(404).json({ error: 'File not found' });

  const normalizedName = path.basename(p.filename);
  const candidates = [
    path.join(uploadsDir, normalizedName),
    path.join(__dirname, 'public', 'uploads', normalizedName), // fallback for legacy files
  ];
  const filePath = candidates.find(file => fs.existsSync(file));
  if (!filePath) return res.status(404).json({ error: 'File not found' });

  res.download(filePath, normalizedName);
});

// ─── Admin API ───────────────────────────────────────────────────────────────

app.post('/api/admin/login', loginLimiter, (req, res) => {
  const password = String(req.body?.password || '');
  if (!db.verifyAdminPassword(password)) {
    return res.status(401).json({ error: 'Неверный пароль' });
  }

  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: 'Session error' });
    req.session.isAdmin = true;
    req.session.csrfToken = crypto.randomBytes(24).toString('hex');
    res.json({ ok: true });
  });
});

app.post('/api/admin/logout', adminAuth, (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('softhub.sid');
    res.json({ ok: true });
  });
});

app.get('/api/admin/session', adminAuth, (req, res) => {
  res.json({ ok: true });
});

app.get('/api/admin/csrf', adminAuth, (req, res) => {
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(24).toString('hex');
  res.json({ csrfToken: req.session.csrfToken });
});

app.post('/api/admin/upload-icon', adminWriteAuth, uploadIcon.single('icon'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  res.json({ url: `/icons/${req.file.filename}` });
});

app.post('/api/admin/upload-file', adminWriteAuth, uploadFile.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  res.json({ filename: req.file.filename, size: req.file.size });
});

app.get('/api/admin/programs', adminAuth, (req, res) => res.json(db.getAllProgramsAdmin()));

app.post('/api/admin/programs', adminWriteAuth, (req, res) => {
  const id = db.addProgram(req.body);
  res.json({ id });
});

app.put('/api/admin/programs/:id', adminWriteAuth, (req, res) => {
  db.updateProgram(req.params.id, req.body);
  res.json({ ok: true });
});

app.delete('/api/admin/programs/:id', adminWriteAuth, (req, res) => {
  db.deleteProgram(req.params.id);
  res.json({ ok: true });
});

app.get('/api/admin/categories', adminAuth, (req, res) => res.json(db.getCategories()));

app.post('/api/admin/categories', adminWriteAuth, (req, res) => {
  try {
    const id = db.addCategory(req.body);
    res.json({ id });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.delete('/api/admin/categories/:id', adminWriteAuth, (req, res) => {
  db.deleteCategory(Number(req.params.id));
  res.json({ ok: true });
});

app.put('/api/admin/settings', adminWriteAuth, (req, res) => {
  const { site_title, site_description, admin_password } = req.body;
  const updates = {};

  if (typeof site_title === 'string') updates.site_title = site_title;
  if (typeof site_description === 'string') updates.site_description = site_description;
  if (Object.keys(updates).length) db.updateSettings(updates);

  let passwordUpdated = false;
  if (typeof admin_password === 'string' && admin_password.trim()) {
    if (admin_password.trim().length < 8) {
      return res.status(400).json({ error: 'Пароль должен быть не короче 8 символов' });
    }
    db.setAdminPassword(admin_password.trim());
    passwordUpdated = true;
  }

  res.json({ ok: true, passwordUpdated });
});

// SPA fallback
app.get('/admin*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: err.message });
  }
  if (err) {
    return res.status(400).json({ error: err.message || 'Request error' });
  }
  next();
});

app.listen(PORT, () => {
  console.log(`✅ SoftHub запущен: http://localhost:${PORT}`);
  console.log('🔐 Админка защищена сессией и CSRF. Логин: /admin');
});
