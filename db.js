// db.js — файловое хранилище + базовые security-хелперы
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DB_FILE = path.join(__dirname, 'catalog.json');
const DEFAULT_ADMIN_PASSWORD = process.env.ADMIN_BOOTSTRAP_PASSWORD || 'admin123';

const PBKDF2_PREFIX = 'pbkdf2';
const PBKDF2_ITERATIONS = 210000;
const PBKDF2_KEYLEN = 64;
const PBKDF2_DIGEST = 'sha512';

function asString(value) {
  if (value === null || value === undefined) return '';
  return String(value);
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const normalized = asString(password);
  const digest = crypto
    .pbkdf2Sync(normalized, salt, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, PBKDF2_DIGEST)
    .toString('hex');
  return `${PBKDF2_PREFIX}$${PBKDF2_ITERATIONS}$${salt}$${digest}`;
}

function timingSafeEqualText(a, b) {
  const left = Buffer.from(asString(a), 'utf8');
  const right = Buffer.from(asString(b), 'utf8');
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function verifyPassword(password, storedHash) {
  const hashText = asString(storedHash);
  const parts = hashText.split('$');
  if (parts.length !== 4 || parts[0] !== PBKDF2_PREFIX) return false;

  const iterations = Number(parts[1]);
  const salt = parts[2];
  const digest = parts[3];

  if (!Number.isFinite(iterations) || iterations < 100000 || !salt || !digest) return false;

  const check = crypto
    .pbkdf2Sync(asString(password), salt, iterations, PBKDF2_KEYLEN, PBKDF2_DIGEST)
    .toString('hex');

  return timingSafeEqualText(check, digest);
}

const defaultData = {
  categories: [
    { id: 1, name: 'Офис', slug: 'office', icon: '📄' },
    { id: 2, name: 'Графика', slug: 'graphics', icon: '🎨' },
    { id: 3, name: 'Утилиты', slug: 'utilities', icon: '🔧' },
    { id: 4, name: 'Медиа', slug: 'media', icon: '🎵' },
    { id: 5, name: 'Интернет', slug: 'internet', icon: '🌐' },
    { id: 6, name: 'Безопасность', slug: 'security', icon: '🔒' },
    { id: 7, name: 'Разработка', slug: 'dev', icon: '💻' },
    { id: 8, name: 'Архиваторы', slug: 'archive', icon: '📦' },
  ],
  programs: [],
  settings: {
    admin_password_hash: hashPassword(DEFAULT_ADMIN_PASSWORD),
    site_title: 'SoftHub',
    site_description: 'Каталог бесплатных и полезных программ',
  },
  _seq: { categories: 8, programs: 0 },
};

function save(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

function ensureShapeAndSecurity(data) {
  let changed = false;

  if (!data.settings || typeof data.settings !== 'object') {
    data.settings = {};
    changed = true;
  }
  if (!data._seq || typeof data._seq !== 'object') {
    data._seq = { categories: 0, programs: 0 };
    changed = true;
  }
  if (!Array.isArray(data.categories)) {
    data.categories = [];
    changed = true;
  }
  if (!Array.isArray(data.programs)) {
    data.programs = [];
    changed = true;
  }

  for (const p of data.programs) {
    if (!Object.prototype.hasOwnProperty.call(p, 'external_url')) {
      p.external_url = '';
      changed = true;
    }
  }

  if (typeof data.settings.site_title !== 'string') {
    data.settings.site_title = 'SoftHub';
    changed = true;
  }
  if (typeof data.settings.site_description !== 'string') {
    data.settings.site_description = 'Каталог бесплатных и полезных программ';
    changed = true;
  }

  const hasHash =
    typeof data.settings.admin_password_hash === 'string' &&
    data.settings.admin_password_hash.startsWith(`${PBKDF2_PREFIX}$`);

  if (!hasHash) {
    const legacy = asString(data.settings.admin_password).trim() || DEFAULT_ADMIN_PASSWORD;
    data.settings.admin_password_hash = hashPassword(legacy);
    changed = true;
  }

  if (Object.prototype.hasOwnProperty.call(data.settings, 'admin_password')) {
    delete data.settings.admin_password;
    changed = true;
  }

  if (!Number.isFinite(data._seq.categories)) {
    const maxCategoryId = data.categories.reduce((max, c) => Math.max(max, Number(c.id) || 0), 0);
    data._seq.categories = maxCategoryId;
    changed = true;
  }
  if (!Number.isFinite(data._seq.programs)) {
    const maxProgramId = data.programs.reduce((max, p) => Math.max(max, Number(p.id) || 0), 0);
    data._seq.programs = maxProgramId;
    changed = true;
  }

  return changed;
}

function load() {
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify(defaultData, null, 2));
    return JSON.parse(JSON.stringify(defaultData));
  }

  const data = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  if (ensureShapeAndSecurity(data)) save(data);
  return data;
}

function normalizeShortText(value, fallback = '') {
  const text = asString(value).trim();
  return text || fallback;
}

// ─── Categories ─────────────────────────────────────────────────────────────

function getCategories() {
  const d = load();
  return d.categories.map(c => ({
    ...c,
    program_count: d.programs.filter(p => p.category_id === c.id).length,
  }));
}

function addCategory({ name, slug, icon }) {
  const d = load();
  const cleanSlug = normalizeShortText(slug).toLowerCase();
  if (!/^[a-z0-9-]{2,50}$/.test(cleanSlug)) {
    throw new Error('Invalid slug');
  }
  if (d.categories.find(c => c.slug === cleanSlug)) throw new Error('Slug already exists');

  const id = ++d._seq.categories;
  d.categories.push({
    id,
    name: normalizeShortText(name, 'Новая категория'),
    slug: cleanSlug,
    icon: normalizeShortText(icon, '📦'),
  });
  save(d);
  return id;
}

function deleteCategory(id) {
  const d = load();
  d.categories = d.categories.filter(c => c.id !== id);
  save(d);
}

// ─── Programs ────────────────────────────────────────────────────────────────

function getPrograms({ category, search, limit = 100, offset = 0 } = {}) {
  const d = load();
  let list = d.programs.map(p => {
    const cat = d.categories.find(c => c.id === p.category_id) || {};
    return { ...p, category_name: cat.name, category_slug: cat.slug, category_icon: cat.icon };
  });

  if (category) list = list.filter(p => p.category_slug === category);
  if (search) {
    const q = asString(search).toLowerCase();
    list = list.filter(p => asString(p.name).toLowerCase().includes(q) || asString(p.description).toLowerCase().includes(q));
  }

  const pageLimit = Math.max(1, Math.min(200, Number(limit) || 100));
  const pageOffset = Math.max(0, Number(offset) || 0);

  list.sort((a, b) => (b.is_featured - a.is_featured) || (b.id - a.id));
  return { programs: list.slice(pageOffset, pageOffset + pageLimit), total: list.length };
}

function getProgramById(id) {
  const d = load();
  const p = d.programs.find(p => p.id === Number(id));
  if (!p) return null;
  const cat = d.categories.find(c => c.id === p.category_id) || {};
  return { ...p, category_name: cat.name, category_slug: cat.slug, category_icon: cat.icon };
}

function addProgram(data) {
  const d = load();
  const id = ++d._seq.programs;
  d.programs.push({
    id,
    name: normalizeShortText(data.name),
    description: normalizeShortText(data.description),
    long_description: normalizeShortText(data.long_description),
    version: normalizeShortText(data.version),
    category_id: Number(data.category_id),
    icon: normalizeShortText(data.icon),
    filename: normalizeShortText(data.filename),
    external_url: normalizeShortText(data.external_url),
    filesize: Number(data.filesize) || 0,
    os: normalizeShortText(data.os, 'Windows'),
    is_featured: data.is_featured ? 1 : 0,
    download_count: 0,
    created_at: new Date().toISOString(),
  });
  save(d);
  return id;
}

function updateProgram(id, data) {
  const d = load();
  const idx = d.programs.findIndex(p => p.id === Number(id));
  if (idx === -1) return;
  d.programs[idx] = {
    ...d.programs[idx],
    name: normalizeShortText(data.name),
    description: normalizeShortText(data.description),
    long_description: normalizeShortText(data.long_description),
    version: normalizeShortText(data.version),
    category_id: Number(data.category_id),
    icon: normalizeShortText(data.icon),
    filename: normalizeShortText(data.filename),
    external_url: normalizeShortText(data.external_url),
    filesize: Number(data.filesize) || 0,
    os: normalizeShortText(data.os, 'Windows'),
    is_featured: data.is_featured ? 1 : 0,
  };
  save(d);
}

function deleteProgram(id) {
  const d = load();
  d.programs = d.programs.filter(p => p.id !== Number(id));
  save(d);
}

function incrementDownload(id) {
  const d = load();
  const p = d.programs.find(p => p.id === Number(id));
  if (p) {
    p.download_count = (p.download_count || 0) + 1;
    save(d);
  }
  return p;
}

function getAllProgramsAdmin() {
  const d = load();
  return d.programs
    .map(p => {
      const cat = d.categories.find(c => c.id === p.category_id) || {};
      return { ...p, category_name: cat.name };
    })
    .sort((a, b) => b.id - a.id);
}

// ─── Settings/Auth ───────────────────────────────────────────────────────────

function getSettings() {
  return load().settings;
}

function getPublicSettings() {
  const settings = load().settings;
  return {
    site_title: settings.site_title || 'SoftHub',
    site_description: settings.site_description || '',
  };
}

function verifyAdminPassword(password) {
  const settings = load().settings;
  return verifyPassword(password, settings.admin_password_hash);
}

function setAdminPassword(nextPassword) {
  const clean = asString(nextPassword).trim();
  if (!clean) throw new Error('Empty password');
  const d = load();
  d.settings.admin_password_hash = hashPassword(clean);
  save(d);
}

function updateSettings(updates) {
  const d = load();
  if (Object.prototype.hasOwnProperty.call(updates, 'site_title')) {
    d.settings.site_title = asString(updates.site_title).trim();
  }
  if (Object.prototype.hasOwnProperty.call(updates, 'site_description')) {
    d.settings.site_description = asString(updates.site_description).trim();
  }
  // Backward-compatible password update path:
  // if older server code passes admin_password via updateSettings,
  // still apply secure hash instead of silently ignoring.
  if (Object.prototype.hasOwnProperty.call(updates, 'admin_password')) {
    const next = asString(updates.admin_password).trim();
    if (next) d.settings.admin_password_hash = hashPassword(next);
  }
  save(d);
}

module.exports = {
  getCategories,
  addCategory,
  deleteCategory,
  getPrograms,
  getProgramById,
  addProgram,
  updateProgram,
  deleteProgram,
  incrementDownload,
  getAllProgramsAdmin,
  getSettings,
  getPublicSettings,
  updateSettings,
  verifyAdminPassword,
  setAdminPassword,
};
