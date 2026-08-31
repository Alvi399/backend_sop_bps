// ============================================================
// FILE: backend/middleware/auth.js
// DESKRIPSI: Middleware autentikasi & otorisasi JWT
//
// SECURITY HARDENING LOG:
// [SEC-A] Verifikasi JWT signature dengan secret dari environment
// [SEC-B] Cek apakah user masih ada di database (cegah token dari akun yang sudah dihapus)
// [SEC-C] Cek is_active: user yang dinonaktifkan tidak bisa akses meski tokennya masih valid
// [SEC-D] requireRole: cegah privilege escalation dengan cek role di setiap endpoint
// ============================================================
const jwt = require('jsonwebtoken');
const { User } = require('../models');

/**
 * [SEC-A, SEC-B, SEC-C] Middleware: verifikasi JWT token
 */
const requireAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ detail: 'Akses ditolak: token tidak ditemukan' });
    }

    const token = authHeader.split(' ')[1];

    // [SEC-A] Verifikasi signature JWT
    let payload;
    try {
      payload = jwt.verify(token, process.env.JWT_SECRET || 'secret-key-sop-bps-surabaya-dev-only');
    } catch (jwtErr) {
      if (jwtErr.name === 'TokenExpiredError') {
        return res.status(401).json({ detail: 'Sesi telah berakhir. Silakan login kembali.' });
      }
      return res.status(401).json({ detail: 'Token tidak valid atau telah dimanipulasi' });
    }

    // [SEC-B] Pastikan user masih ada di database
    const user = await User.findByPk(payload.id);
    if (!user) {
      return res.status(401).json({ detail: 'Akun tidak ditemukan. Token tidak valid.' });
    }

    // [SEC-C] Pastikan user masih aktif (tidak dinonaktifkan admin)
    if (user.is_active === false) {
      return res.status(403).json({ detail: 'Akun Anda telah dinonaktifkan. Hubungi administrator.' });
    }

    req.user = user;
    next();
  } catch (err) {
    console.error('Auth middleware error:', err.message);
    return res.status(401).json({ detail: 'Tidak dapat memvalidasi kredensial' });
  }
};

/**
 * [SEC-D] Middleware: cek role user — cegah privilege escalation
 * Contoh penggunaan: requireRole(['admin', 'kepala_bagian'])
 */
const requireRole = (allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ detail: 'Tidak terautentikasi' });
    }
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ detail: `Akses ditolak. Fitur ini memerlukan role: ${allowedRoles.join(' atau ')}.` });
    }
    next();
  };
};

module.exports = { requireAuth, requireRole };
