// ============================================================
// FILE: backend/routes/users.js
// DESKRIPSI: Route untuk manajemen akun pengguna E-SOPRA BPS
//
// BUG FIX LOG:
// [BUG 1 - FIXED 2026-08-31] uuidv4 tidak diimport.
//   Gejala: POST /api/users (admin buat user baru) crash dengan
//           "ReferenceError: uuidv4 is not defined" di baris 117.
//   Fix: Tambahkan require('uuid') di sini.
//
// ALUR BISNIS:
//   GET  /api/users            → daftar semua user (semua role terautentikasi)
//   GET  /api/users/me         → profil user yang sedang login
//   PUT  /api/users/me         → update profil user sendiri
//   PUT  /api/users/me/avatar  → update foto profil (base64)
//   PUT  /api/users/me/password→ ganti password (perlu password lama)
//   POST /api/users            → admin buat user baru (hanya role: admin)
//   DELETE /api/users/:id      → admin hapus user (hanya role: admin)
//   GET  /api/users/:id        → detail user by ID
// ============================================================
const express = require('express');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid'); // [BUG 1 FIX] Import uuidv4 yang sebelumnya hilang
const { User, ActivityLog } = require('../models');
const { requireAuth, requireRole } = require('../middleware/auth');


const router = express.Router();

// GET /api/users — semua user
router.get('/', requireAuth, async (req, res) => {
  try {
    const users = await User.findAll({ attributes: { exclude: ['password_hash'] } });
    return res.json(users);
  } catch (err) {
    return res.status(500).json({ detail: err.message });
  }
});

// GET /api/users/me — profil user yang sedang login
router.get('/me', requireAuth, (req, res) => {
  const user = req.user.toJSON();
  delete user.password_hash;
  return res.json(user);
});

// PUT /api/users/me — update profil
router.put('/me', requireAuth, async (req, res) => {
  try {
    const { full_name, email, phone, department } = req.body;

    if (email) {
      const existing = await User.findOne({
        where: { email },
      });
      if (existing && existing.id !== req.user.id) {
        return res.status(400).json({ detail: 'Email sudah digunakan oleh akun lain' });
      }
    }

    const updates = {};
    if (full_name !== undefined) updates.full_name = full_name;
    if (email !== undefined) updates.email = email;
    if (phone !== undefined) updates.phone = phone;
    if (department !== undefined) updates.department = department;

    await req.user.update(updates);
    const user = req.user.toJSON();
    delete user.password_hash;

    return res.json({ message: 'Profil berhasil diperbarui', user });
  } catch (err) {
    return res.status(500).json({ detail: err.message });
  }
});

// PUT /api/users/me/avatar — update avatar foto profil
router.put('/me/avatar', requireAuth, async (req, res) => {
  try {
    const { avatar_url } = req.body;
    await req.user.update({ avatar_url: avatar_url || '' });
    
    const user = req.user.toJSON();
    delete user.password_hash;

    return res.json({
      message: 'Foto profil berhasil diperbarui',
      avatar_url: req.user.avatar_url,
      user
    });
  } catch (err) {
    console.error('Error updating avatar:', err);
    return res.status(500).json({ detail: err.message });
  }
});


router.put('/me/password', requireAuth, async (req, res) => {
  try {
    const { current_password, new_password } = req.body;

    if (!current_password || !new_password) {
      return res.status(400).json({ detail: 'Password lama dan baru wajib diisi' });
    }

    const isValid = await bcrypt.compare(current_password, req.user.password_hash);
    if (!isValid) {
      return res.status(400).json({ detail: 'Password saat ini salah' });
    }

    const salt = await bcrypt.genSalt(12);
    const password_hash = await bcrypt.hash(new_password, salt);
    await req.user.update({ password_hash });

    return res.json({ message: 'Password berhasil diperbarui' });
  } catch (err) {
    return res.status(500).json({ detail: err.message });
  }
});

// POST /api/users — Admin membuat user baru dengan role apapun
router.post('/', requireAuth, requireRole(['admin']), async (req, res) => {
  try {
    const { email, password, full_name, department, phone, role } = req.body;

    if (!email || !password || !full_name || !department) {
      return res.status(400).json({ detail: 'Email, password, nama lengkap, dan departemen wajib diisi' });
    }

    const existing = await User.findOne({ where: { email } });
    if (existing) {
      return res.status(400).json({ detail: 'Email sudah terdaftar di sistem' });
    }

    const salt = await bcrypt.genSalt(12);
    const password_hash = await bcrypt.hash(password, salt);

    const user = await User.create({
      id: uuidv4(),
      email: email.toLowerCase().trim(),
      password_hash,
      full_name,
      department,
      phone: phone || null,
      role: role || 'staf',
      is_active: true,
      join_date: new Date(),
    });

    const { password_hash: _, ...userResponse } = user.toJSON();
    console.log(`✅ Admin ${req.user.email} membuat user baru: ${email} (${role})`);
    return res.status(201).json(userResponse);
  } catch (err) {
    return res.status(500).json({ detail: err.message });
  }
});

// DELETE /api/users/:id — Admin menghapus user
router.delete('/:id', requireAuth, requireRole(['admin']), async (req, res) => {
  try {
    if (req.params.id === req.user.id) {
      return res.status(400).json({ detail: 'Anda tidak dapat menghapus akun Anda sendiri' });
    }

    const user = await User.findByPk(req.params.id);
    if (!user) return res.status(404).json({ detail: 'User tidak ditemukan' });

    await user.destroy();
    return res.json({ message: 'User berhasil dihapus' });
  } catch (err) {
    return res.status(500).json({ detail: err.message });
  }
});

// GET /api/users/:id — detail user by ID
router.get('/:id', requireAuth, async (req, res) => {
  try {
    const user = await User.findByPk(req.params.id, { attributes: { exclude: ['password_hash'] } });
    if (!user) return res.status(404).json({ detail: 'User tidak ditemukan' });
    return res.json(user);
  } catch (err) {
    return res.status(500).json({ detail: err.message });
  }
});

module.exports = router;
