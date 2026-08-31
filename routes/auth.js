// ============================================================
// FILE: backend/routes/auth.js
// DESKRIPSI: Endpoint login dan registrasi akun E-SOPRA
//
// SECURITY HARDENING LOG:
// [SEC-R1] Input Sanitization: email di-lowercase dan di-trim sebelum proses apapun
// [SEC-R2] Domain validation: hanya @bps-surabaya.go.id yang bisa daftar
// [SEC-R3] Password strength: minimal 8 karakter (bukan 6)
// [SEC-R4] Email normalisasi saat login: cegah bypass dengan huruf besar
// [SEC-R5] is_active check saat login: user nonaktif tidak bisa masuk
// [SEC-R6] Rate limiting: diterapkan di server.js level (authLimiter)
// [SEC-R7] bcrypt cost factor 12: cukup lambat untuk brute force
// ============================================================
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { User } = require('../models');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

// POST /api/auth/register — Pendaftaran akun pengguna baru BPS
router.post('/register', async (req, res) => {
  try {
    // [SEC-R1] Sanitasi input: hapus spasi, normalisasi case
    const email = (req.body.email || '').toLowerCase().trim();
    const password = req.body.password || '';
    const full_name = (req.body.full_name || '').trim();
    const department = (req.body.department || '').trim();
    const phone = (req.body.phone || '').trim();

    if (!email || !password || !full_name || !department) {
      return res.status(400).json({ detail: 'Email, password, nama lengkap, dan Seksi/Tim wajib diisi' });
    }

    // [SEC-R2] Validasi domain email resmi BPS
    if (!email.endsWith('@bps-surabaya.go.id')) {
      return res.status(400).json({ detail: 'Pendaftaran khusus email resmi BPS (harus berakhiran @bps-surabaya.go.id)' });
    }

    // [SEC-R3] Validasi kekuatan password: minimal 8 karakter
    if (password.length < 8) {
      return res.status(400).json({ detail: 'Password minimal 8 karakter' });
    }

    // [SEC-R1] Cek email sudah terdaftar (dengan email yang sudah di-normalize)
    const existing = await User.findOne({ where: { email } });
    if (existing) {
      return res.status(400).json({ detail: 'Email ini sudah terdaftar di sistem E-SOPRA. Silakan login atau gunakan email lain.' });
    }

    const salt = await bcrypt.genSalt(12); // [SEC-R7] cost factor 12
    const password_hash = await bcrypt.hash(password, salt);

    // Default role 'staf' untuk pendaftaran mandiri
    const userRole = 'staf'; // Role tidak bisa dipilih sendiri saat register mandiri

    const user = await User.create({
      id: uuidv4(),
      email,
      password_hash,
      full_name,
      department,
      phone: phone || null,
      role: userRole,
      is_active: true,
      join_date: new Date(),
    });

    const { password_hash: _, ...userResponse } = user.toJSON();
    console.log(`✅ User baru berhasil terdaftar: ${email} (role: ${userRole})`);
    return res.status(201).json({
      message: 'Pendaftaran berhasil! Akun Anda telah dibuat.',
      user: userResponse
    });
  } catch (err) {
    console.error('❌ Register error:', err);
    return res.status(500).json({ detail: err.message });
  }
});

// POST /api/auth/login
router.post('/login', async (req, res) => {
  try {
    // [SEC-R4] Normalisasi email sebelum lookup DB
    // Mencegah bypass: "Admin@BPS-Surabaya.GO.ID" != "admin@bps-surabaya.go.id" di DB
    const email = (req.body.email || '').toLowerCase().trim();
    const password = req.body.password || '';

    if (!email || !password) {
      return res.status(400).json({ detail: 'Email dan password wajib diisi' });
    }

    console.log(`🔐 Login attempt: ${email}`);

    const user = await User.findOne({ where: { email } });
    if (!user) {
      console.log(`❌ User not found: ${email}`);
      // [SECURITY] Pesan yang sama untuk "tidak ditemukan" dan "password salah"
      // mencegah username enumeration attack
      return res.status(401).json({ detail: 'Email atau password tidak sesuai.' });
    }

    // [SEC-R5] Cek is_active sebelum verify password
    if (user.is_active === false) {
      console.log(`❌ Login ditolak: akun nonaktif ${email}`);
      return res.status(403).json({ detail: 'Akun Anda telah dinonaktifkan. Hubungi administrator.' });
    }

    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid) {
      console.log(`❌ Password invalid untuk: ${email}`);
      return res.status(401).json({ detail: 'Email atau password tidak sesuai.' });
    }

    console.log(`✅ Login berhasil: ${email}`);

    // Update last_login
    await user.update({ last_login: new Date() });

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET || 'secret-key-sop-bps-surabaya-dev-only',
      { expiresIn: process.env.JWT_EXPIRES_IN || '8h' }  // 8 jam = 1 sesi kerja penuh
    );

    return res.json({
      access_token: token,
      token_type: 'bearer',
      user: {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        role: user.role,
        department: user.department,
        is_active: user.is_active,
        avatar_url: user.avatar_url,
        phone: user.phone,
        join_date: user.join_date,
        last_login: user.last_login,
      },
    });
  } catch (err) {
    console.error('❌ Login error:', err);
    return res.status(500).json({ detail: err.message });
  }
});

// GET /api/auth/me
router.get('/me', requireAuth, (req, res) => {
  const { password_hash: _, ...userResponse } = req.user.toJSON();
  return res.json(userResponse);
});

module.exports = router;
