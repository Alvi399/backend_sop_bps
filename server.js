// ============================================================
// FILE: backend/server.js
// DESKRIPSI: Entry point backend Express.js E-SOPRA BPS Surabaya
//
// SECURITY HARDENING LOG:
// [SEC-1] Helmet: Set security HTTP headers (XSS, clickjacking, MIME sniffing, dll)
// [SEC-2] CORS: Dibatasi ke domain yang diizinkan saja (whitelist)
// [SEC-3] Rate Limiting: Login endpoint dibatasi 10 request/15 menit per IP
// [SEC-4] Rate Limiting: API umum dibatasi 200 request/menit per IP
// [SEC-5] Path Traversal: Validasi nama file uploads (tolak ../ atau path absolut)
// [SEC-6] Request Size: Batasi body 50MB (hanya untuk base64 PDF)
// [SEC-7] Error Handler: Tidak expose stack trace ke client di production
// [SEC-8] JWT Secret: Wajib ada di .env, fallback hanya untuk development
//
// PENTING UNTUK DEPLOYMENT:
//   - Set JWT_SECRET di .env / Render environment variables
//   - Set NODE_ENV=production di Render
//   - Tambahkan domain frontend Anda ke ALLOWED_ORIGINS di bawah
// ============================================================
require('dotenv').config();

// [SEC-8] Peringatan jika JWT_SECRET tidak di-set di environment
if (!process.env.JWT_SECRET || process.env.JWT_SECRET === 'secret-key-sop-bps-surabaya') {
  if (process.env.NODE_ENV === 'production') {
    console.error('🚨 CRITICAL: JWT_SECRET belum di-set di environment production!');
    console.error('   Set JWT_SECRET di Render Dashboard -> Environment Variables');
  } else {
    process.env.JWT_SECRET = 'secret-key-sop-bps-surabaya-dev-only';
    console.warn('⚠️  Development mode: menggunakan JWT_SECRET default. Jangan di production!');
  }
}

const express = require('express');
const cors = require('cors');
const helmet = require('helmet'); // [SEC-1]
const rateLimit = require('express-rate-limit'); // [SEC-3, SEC-4]
const path = require('path');
const fs = require('fs');
const { sequelize } = require('./models');

const app = express();
const PORT = process.env.PORT || 8000;

// ===================================
// [SEC-1] HELMET — Security HTTP Headers
// Melindungi dari XSS, clickjacking, MIME sniffing, dll
// ===================================
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' }, // Izinkan akses static files dari domain lain
  contentSecurityPolicy: false, // Dikelola di level SPA/Hostinger
}));

// ===================================
// [SEC-2] CORS — Whitelist Domain yang Diizinkan
// ===================================
const ALLOWED_ORIGINS = [
  'http://localhost:5173',
  'http://localhost:3000',
  'http://localhost:8000',
  'https://backend-sop-bps.onrender.com',
  'https://backendsop.serverbpsjosjis.dpdns.org', // Domain lama (keep agar tidak break existing client)
  // Tambahkan domain Hostinger frontend Anda di sini setelah deploy:
  // 'https://www.bps-surabaya.co.id',
  // 'https://bps-surabaya.co.id',
].filter(Boolean);

app.use(cors({
  origin: (origin, callback) => {
    // Izinkan request tanpa origin (Postman, curl, server-to-server)
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    console.warn(`⚠️  CORS blocked origin: ${origin}`);
    callback(new Error(`Origin ${origin} tidak diizinkan oleh CORS policy`));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// ===================================
// [SEC-3] RATE LIMITER — Login & Register
// Batasi 10 percobaan per 15 menit per IP
// Mencegah brute-force attack pada password
// ===================================
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 menit
  max: 10,
  message: { detail: 'Terlalu banyak percobaan login. Coba lagi setelah 15 menit.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ===================================
// [SEC-4] RATE LIMITER — API Umum
// Batasi 200 request per menit per IP
// ===================================
const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 menit
  max: 200,
  message: { detail: 'Terlalu banyak request. Coba lagi setelah 1 menit.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(express.json({ limit: '50mb' }));         // [SEC-6] Limit 50MB untuk support base64 PDF
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// ===================================
// [SEC-5] STATIC FILES — Path Traversal Protection
// Validasi nama file: tolak ../ atau path absolut sebelum serve
// ===================================
const safeStaticMiddleware = (req, res, next) => {
  const filename = req.params[0] || req.path;
  // Tolak jika mengandung path traversal
  if (filename.includes('..') || filename.includes('//') || path.isAbsolute(filename)) {
    return res.status(400).json({ detail: 'Nama file tidak valid' });
  }
  next();
};
app.use('/uploads', safeStaticMiddleware, express.static(path.join(__dirname, 'uploads')));
app.use('/api/uploads', safeStaticMiddleware, express.static(path.join(__dirname, 'uploads')));

// Serve Frontend Static Dist (Monolith - optional if SERVE_FRONTEND=true)
const frontendDist = path.join(__dirname, '..', 'dist');
if (process.env.SERVE_FRONTEND === 'true' && fs.existsSync(frontendDist)) {
  app.use(express.static(frontendDist));
  console.log(`📦 Serving Monolith Frontend from: ${frontendDist}`);
}

// ===================================
// ROUTES (dengan Rate Limiting)
// ===================================
const authRoutes      = require('./routes/auth');
const sopRoutes       = require('./routes/sops');
const revisionRoutes  = require('./routes/revisions');
const userRoutes      = require('./routes/users');
const pdfRoutes       = require('./routes/pdf');
const activityRoutes  = require('./routes/activities');

// [SEC-3] Terapkan rate limit ketat pada endpoint auth
app.use('/api/auth', authLimiter, authRoutes);

// [SEC-4] Terapkan rate limit umum pada semua API lain
app.use('/api/sops',      apiLimiter, sopRoutes);
app.use('/api/revisions', apiLimiter, revisionRoutes);
app.use('/api/users',     apiLimiter, userRoutes);
app.use('/api/activities', apiLimiter, activityRoutes);
app.use('/',              pdfRoutes);  // /edit-pdf/ dan /pdfs/:filename

// ===================================
// API INFO ENDPOINT
// ===================================
const getApiInfo = (req, res) => {
  res.json({
    message: 'BPS SOP Management Backend API',
    version: '3.0',
    framework: 'Express.js',
    database: 'MySQL (Sequelize)',
    status: 'Running',
    endpoints: {
      auth: '/api/auth',
      sops: '/api/sops',
      revisions: '/api/revisions',
      users: '/api/users',
      activities: '/api/activities'
    }
  });
};

app.get('/api', getApiInfo);
app.get('/', (req, res, next) => {
  if (process.env.SERVE_FRONTEND === 'true' && fs.existsSync(path.join(frontendDist, 'index.html'))) {
    return res.sendFile(path.join(frontendDist, 'index.html'));
  }
  return getApiInfo(req, res);
});

// ===================================
// SPA FALLBACK / NOT FOUND
// ===================================
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api') || req.path.startsWith('/uploads') || req.path.startsWith('/pdfs') || req.path.startsWith('/edit-pdf')) {
    return next();
  }
  if (process.env.SERVE_FRONTEND === 'true') {
    const indexPath = path.join(frontendDist, 'index.html');
    if (fs.existsSync(indexPath)) {
      return res.sendFile(indexPath);
    }
  }
  res.status(404).json({ detail: `Route ${req.method} ${req.path} not found` });
});

// ===================================
// [SEC-7] Error Handler — Jangan expose stack trace di production
// ===================================
app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err);
  // Di production, hanya kirim pesan generik — tidak expose internal detail
  const message = process.env.NODE_ENV === 'production'
    ? 'Terjadi kesalahan pada server. Silakan coba lagi.'
    : (err.message || 'Internal server error');
  res.status(err.status || 500).json({ detail: message });
});

// ===================================
// START SERVER + SYNC DATABASE
// ===================================
async function startServer() {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Monolith Server running on http://localhost:${PORT}`);
    console.log(`📖 Web Application & API: http://localhost:${PORT}`);
  });

  try {
    await sequelize.authenticate();
    console.log('✅ MySQL connected successfully');

    await sequelize.sync({ alter: false });
    console.log('✅ Database tables synced');
  } catch (err) {
    console.error('❌ Database connection error:', err.message);
  }
}

// In Vercel serverless environment, export app without blocking listen
if (process.env.VERCEL === '1') {
  // Lazy DB authenticate on serverless invocations
  sequelize.authenticate()
    .then(() => console.log('✅ MySQL connected on Vercel Serverless'))
    .catch((err) => console.warn('⚠️ MySQL connection warning on Vercel Serverless:', err.message));
} else if (require.main === module) {
  startServer();
}

module.exports = app;
