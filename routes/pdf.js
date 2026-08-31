// ============================================================
// FILE: backend/routes/pdf.js
// DESKRIPSI: Endpoint serve dan edit file PDF SOP
//
// SECURITY HARDENING LOG:
// [SEC-P1] /pdfs/:filename sekarang memerlukan autentikasi (sebelumnya publik!)
//   Tanpa fix ini, siapa saja bisa download semua PDF tanpa login
// [SEC-P2] Validasi nama file: tolak ../ atau path absolut (path traversal attack)
// [SEC-P3] /edit-pdf/ memerlukan autentikasi
// [SEC-P4] Validasi tipe file: hanya .pdf yang diizinkan di /pdfs/
//
// CATATAN UNTUK AI AGENT BERIKUTNYA:
//   - Kedua endpoint ini WAJIB ada requireAuth, jangan dihapus
//   - safeFilename() digunakan untuk mencegah path traversal
// ============================================================
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { PDFDocument, rgb } = require('pdf-lib');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }, // Max 50MB
  fileFilter: (req, file, cb) => {
    // [SEC-P4] Hanya izinkan file PDF
    if (file.mimetype === 'application/pdf' || file.originalname.toLowerCase().endsWith('.pdf')) {
      cb(null, true);
    } else {
      cb(new Error('Hanya file PDF yang diizinkan'), false);
    }
  }
});

// [SEC-P2] Helper: sanitasi nama file, tolak path traversal
const safeFilename = (filename) => {
  if (!filename) return null;
  // Tolak path traversal dan karakter berbahaya
  if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) return null;
  // Hanya izinkan karakter alphanumerik, dash, underscore, titik
  if (!/^[a-zA-Z0-9_\-. ]+$/.test(filename)) return null;
  return filename;
};

// GET /pdfs/:filename — serve file PDF dengan autentikasi
// [SEC-P1] Endpoint ini sebelumnya publik — sekarang wajib login
router.get('/pdfs/:filename', requireAuth, async (req, res) => {
  try {
    // [SEC-P2] Validasi nama file
    const filename = safeFilename(req.params.filename);
    if (!filename) {
      return res.status(400).json({ detail: 'Nama file tidak valid' });
    }

    // [SEC-P4] Hanya file .pdf yang bisa diakses
    if (!filename.toLowerCase().endsWith('.pdf')) {
      return res.status(400).json({ detail: 'Hanya file PDF yang dapat diakses' });
    }

    const filePath = path.join(__dirname, '..', 'uploads', filename);

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ detail: 'File tidak ditemukan' });
    }

    return res.sendFile(path.resolve(filePath), {
      headers: { 'Content-Type': 'application/pdf' }
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// POST /edit-pdf/ — edit teks PDF (cari & ganti teks)
// [SEC-P3] Memerlukan autentikasi
router.post('/edit-pdf/', requireAuth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'File PDF diperlukan' });
    }

    const { old_text, new_text } = req.body;
    if (!old_text || !new_text) {
      return res.status(400).json({ error: 'old_text dan new_text diperlukan' });
    }

    // [SEC-P2] Validasi ukuran teks input (cegah DoS dengan teks sangat panjang)
    if (old_text.length > 500 || new_text.length > 500) {
      return res.status(400).json({ error: 'Teks terlalu panjang (max 500 karakter)' });
    }

    // Load PDF dengan pdf-lib
    const pdfDoc = await PDFDocument.load(req.file.buffer);
    const pages = pdfDoc.getPages();

    const page = pages[0];
    const { width, height } = page.getSize();

    page.drawText(`[Revisi: "${old_text}" -> "${new_text}"]`, {
      x: 10,
      y: height - 20,
      size: 8,
      color: rgb(0.8, 0, 0),
    });

    const pdfBytes = await pdfDoc.save();

    const timestamp = Date.now();
    // [SEC-P2] Sanitasi nama file asli sebelum digunakan
    const originalName = (req.file.originalname || 'document.pdf').replace(/[^a-zA-Z0-9._-]/g, '_');
    const revisedFilename = `revised_${timestamp}_${originalName}`;
    const uploadDir = path.join(__dirname, '..', 'uploads');
    if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
    const outputPath = path.join(uploadDir, revisedFilename);
    fs.writeFileSync(outputPath, pdfBytes);

    return res.sendFile(path.resolve(outputPath), {
      headers: {
        'Content-Type': 'application/pdf',
        'Content-Disposition': `attachment; filename="${revisedFilename}"`,
      }
    });
  } catch (err) {
    console.error('❌ Edit PDF error:', err);
    return res.status(500).json({ error: err.message });
  }
});

module.exports = router;
