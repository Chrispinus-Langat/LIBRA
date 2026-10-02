require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const net = require('net');
const dns = require('dns').promises;
const { Readable, Transform } = require('stream');
const { pipeline } = require('stream/promises');

/* ---------- Config ---------- */
const {
  DATABASE_URL, JWT_SECRET, OWNER_PASSWORD_HASH,
  PORT = 3000, NODE_ENV = 'development',
  UPLOAD_DIR = path.join(__dirname, 'uploads'),
  MAX_FILE_MB = 500,
} = process.env;
const MAX_BYTES = Number(MAX_FILE_MB) * 1024 * 1024;
const IS_PROD = NODE_ENV === 'production';

for (const [k, v] of Object.entries({ DATABASE_URL, JWT_SECRET, OWNER_PASSWORD_HASH })) {
  if (!v) { console.error(`Missing ${k} in your .env file. See .env.example.`); process.exit(1); }
}
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const db = new Pool({ connectionString: DATABASE_URL, max: 5 });
const app = express();
if (IS_PROD) app.set('trust proxy', 1);

/* ---------- Security headers ---------- */
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdn.tailwindcss.com'],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ['https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:', 'blob:'],
      mediaSrc: ["'self'", 'blob:'],
      frameSrc: ["'self'"],
      objectSrc: ["'self'"],
      connectSrc: ["'self'"],
    },
  },
}));
app.use(express.json({ limit: '100kb' }));
app.use(cookieParser());

/* ---------- Helpers ---------- */
const httpErr = (status, message) => Object.assign(new Error(message), { status });
const wrap = fn => (req, res, next) => fn(req, res, next).catch(next);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const toFile = r => ({
  id: r.id, name: r.name, mime: r.mime, size: Number(r.size),
  created: new Date(r.created_at).getTime(), fav: r.is_favorite,
  url: `/api/files/${r.id}/content`,
});
const insertFile = (name, mime, size, key) =>
  db.query('insert into files (name, mime, size, storage_key) values ($1,$2,$3,$4) returning *', [name, mime, size, key])
    .then(r => r.rows[0]);
const unlinkQuiet = p => fs.promises.unlink(p).catch(() => {});
// Multer may hand us UTF-8 names decoded as latin1. Fix only when the round-trip proves it.
const fixName = n => {
  const fixed = Buffer.from(n, 'latin1').toString('utf8');
  return !fixed.includes('\uFFFD') && Buffer.from(fixed, 'utf8').toString('latin1') === n ? fixed : n;
};
// Only these are shown inline in the browser. Everything else is forced to download (blocks stored-XSS from html/svg).
const INLINE_OK = m => /^(image\/(?!svg)|video\/|audio\/)/.test(m) || m === 'application/pdf';

/* ---------- Auth (single owner) ---------- */
const COOKIE = 'vault_token';
const cookieOpts = { httpOnly: true, sameSite: 'strict', secure: IS_PROD, maxAge: 7 * 24 * 3600 * 1000 };
const auth = (req, res, next) => {
  try { jwt.verify(req.cookies[COOKIE], JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Please sign in' }); }
};
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many attempts. Try again in 15 minutes.' } });

app.post('/api/auth/login', loginLimiter, wrap(async (req, res) => {
  const ok = await bcrypt.compare(String(req.body.password || ''), OWNER_PASSWORD_HASH);
  if (!ok) throw httpErr(401, 'Wrong passcode');
  res.cookie(COOKIE, jwt.sign({ owner: true }, JWT_SECRET, { expiresIn: '7d' }), cookieOpts);
  res.json({ ok: true });
}));
app.post('/api/auth/logout', (req, res) => { res.clearCookie(COOKIE, cookieOpts); res.json({ ok: true }); });
app.get('/api/auth/me', auth, (req, res) => res.json({ ok: true }));

/* ---------- Files ---------- */
const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOAD_DIR,
    filename: (req, file, cb) => cb(null, crypto.randomUUID()),
  }),
  limits: { fileSize: MAX_BYTES },
});

app.get('/api/files', auth, wrap(async (req, res) => {
  const { rows } = await db.query('select * from files order by created_at desc');
  res.json(rows.map(toFile));
}));

app.post('/api/files', auth, upload.array('files', 50), wrap(async (req, res) => {
  const files = req.files || [];
  try {
    const saved = [];
    for (const f of files) {
      saved.push(toFile(await insertFile(fixName(f.originalname), f.mimetype || 'application/octet-stream', f.size, f.filename)));
    }
    res.status(201).json(saved);
  } catch (e) { await Promise.all(files.map(f => unlinkQuiet(f.path))); throw e; }
}));

app.get('/api/files/:id/content', auth, wrap(async (req, res) => {
  if (!UUID.test(req.params.id)) throw httpErr(404, 'File not found');
  const { rows } = await db.query('select * from files where id = $1', [req.params.id]);
  if (!rows[0]) throw httpErr(404, 'File not found');
  const f = rows[0];
  const inline = INLINE_OK(f.mime) && !req.query.download;
  res.setHeader('Content-Type', f.mime);
  res.setHeader('Content-Disposition', `${inline ? 'inline' : 'attachment'}; filename*=UTF-8''${encodeURIComponent(f.name)}`);
  res.setHeader('Cache-Control', 'private, max-age=3600');
  // sendFile handles Range requests, so video and audio can seek.
  res.sendFile(f.storage_key, { root: path.resolve(UPLOAD_DIR) }, err => {
    if (err && !res.headersSent) res.status(404).json({ error: 'File is missing from storage' });
  });
}));

app.patch('/api/files/:id', auth, wrap(async (req, res) => {
  if (!UUID.test(req.params.id)) throw httpErr(404, 'File not found');
  let { name, fav } = req.body;
  if (name !== undefined) {
    name = String(name).trim();
    if (!name || name.length > 255) throw httpErr(400, 'Name must be 1 to 255 characters');
  }
  const { rows } = await db.query(
    'update files set name = coalesce($2, name), is_favorite = coalesce($3, is_favorite) where id = $1 returning *',
    [req.params.id, name ?? null, typeof fav === 'boolean' ? fav : null]);
  if (!rows[0]) throw httpErr(404, 'File not found');
  res.json(toFile(rows[0]));
}));

app.delete('/api/files', auth, wrap(async (req, res) => {
  const ids = (Array.isArray(req.body.ids) ? req.body.ids : []).filter(i => UUID.test(i));
  if (!ids.length) throw httpErr(400, 'No files selected');
  const { rows } = await db.query('delete from files where id = any($1::uuid[]) returning storage_key', [ids]);
  await Promise.all(rows.map(r => unlinkQuiet(path.join(UPLOAD_DIR, r.storage_key))));
  res.json({ deleted: rows.length });
}));

/* ---------- Save from a link (server-side download) ---------- */
function isPrivate(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  }
  const v = ip.toLowerCase();
  if (v.startsWith('::ffff:')) return isPrivate(v.slice(7));
  return v === '::1' || v === '::' || v.startsWith('fc') || v.startsWith('fd') || v.startsWith('fe80');
}
async function assertPublic(input) {
  let url;
  try { url = new URL(input); } catch { throw httpErr(400, 'That is not a valid link'); }
  if (!['http:', 'https:'].includes(url.protocol)) throw httpErr(400, 'Only http and https links are supported');
  const addrs = await dns.lookup(url.hostname.replace(/^\[|\]$/g, ''), { all: true }).catch(() => []);
  if (!addrs.length || addrs.some(a => isPrivate(a.address))) throw httpErr(400, 'That address is not allowed');
  return url;
}
async function safeFetch(input) {
  let next = input;
  for (let i = 0; i < 4; i++) {
    const url = await assertPublic(next);
    const r = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(10 * 60 * 1000) });
    const loc = r.headers.get('location');
    if (r.status >= 300 && r.status < 400 && loc) { next = new URL(loc, url).href; continue; }
    return { r, url };
  }
  throw httpErr(400, 'Too many redirects');
}

app.post('/api/files/import', auth, wrap(async (req, res) => {
  const filePath = path.join(UPLOAD_DIR, crypto.randomUUID());
  try {
    const { r, url } = await safeFetch(String(req.body.url || ''));
    if (!r.ok || !r.body) throw httpErr(400, `The link returned an error (${r.status})`);
    if (Number(r.headers.get('content-length') || 0) > MAX_BYTES) throw httpErr(413, `File is larger than ${MAX_FILE_MB} MB`);
    let total = 0;
    const limiter = new Transform({ transform(chunk, _e, cb) {
      total += chunk.length;
      total > MAX_BYTES ? cb(httpErr(413, `File is larger than ${MAX_FILE_MB} MB`)) : cb(null, chunk);
    } });
    await pipeline(Readable.fromWeb(r.body), limiter, fs.createWriteStream(filePath));

    const cd = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(r.headers.get('content-disposition') || '');
    let name = cd ? cd[1] : url.pathname.split('/').pop();
    try { name = decodeURIComponent(name); } catch {}
    name = (name || 'download').slice(0, 255);
    const mime = (r.headers.get('content-type') || 'application/octet-stream').split(';')[0].trim();
    const row = await insertFile(name, mime, total, path.basename(filePath));
    res.status(201).json(toFile(row));
  } catch (e) { await unlinkQuiet(filePath); throw e; }
}));

/* ---------- Frontend + errors ---------- */
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
app.use((err, req, res, next) => {
  if (err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: `File is larger than ${MAX_FILE_MB} MB` });
  const status = err.status || 500;
  if (status === 500) console.error(err);
  res.status(status).json({ error: status === 500 ? 'Something went wrong on the server' : err.message });
});

db.query('select 1').then(() => {
  app.listen(PORT, () => console.log(`Vault is running at http://localhost:${PORT}`));
}).catch(e => { console.error('Could not connect to Neon. Check DATABASE_URL.\n', e.message); process.exit(1); });
