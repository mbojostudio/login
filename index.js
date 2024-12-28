const express = require("express");
const bodyParser = require("body-parser");
const admin = require("firebase-admin");
const session = require("express-session");
const path = require("path");
const multer = require("multer");
const fs = require('fs');
const bcrypt = require("bcrypt");
const cors = require("cors");
require('dotenv').config();

// Setup multer untuk menangani unggahan file
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// Ambil path dari environment variable dan resolve ke path absolut
const googleCloudKeyPath = process.env.GOOGLE_CLOUD_SERVICE_ACCOUNT_KEY;

let googleCloudKey;
try {
  if (!googleCloudKeyPath) {
    throw new Error("Path ke file kunci Google Cloud tidak ditemukan. Periksa file .env Anda.");
  }
  googleCloudKey = JSON.parse(fs.readFileSync(path.resolve(__dirname, googleCloudKeyPath), 'utf8'));
} catch (error) {
  console.error("Error membaca kunci layanan Google Cloud:", error.message);
  process.exit(1); // Hentikan proses jika kunci layanan tidak valid
}

// Inisialisasi Firebase Admin SDK
admin.initializeApp({
  credential: admin.credential.cert(googleCloudKey),
  databaseURL: "https://fbuses-3e232-default-rtdb.firebaseio.com/", // Sesuaikan dengan databaseURL Anda
});

const db = admin.database();
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  session({
    secret: "iniadalahprojectujicoba", // Ganti dengan key rahasia
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 3600000, secure: false }, // Cookie aktif selama 1 jam
  })
);

// Endpoint Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email dan password harus diisi." });
  }

  try {
    const usersRef = db.ref("users");
    const snapshot = await usersRef.orderByChild("email").equalTo(email).once("value");

    if (!snapshot.exists()) {
      return res.status(404).json({ message: "Pengguna tidak ditemukan." });
    }

    const userData = Object.values(snapshot.val())[0];

    // Periksa password yang di-hash
    const isPasswordValid = await bcrypt.compare(password, userData.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Password salah." });
    }

    res.status(200).json({
      message: "Login berhasil.",
      userId: userData.id,
      name: userData.username,
    });
  } catch (error) {
    console.error("Login error:", error.message);
    res.status(500).json({ message: "Terjadi kesalahan pada server." });
  }
});

// Endpoint Logout
app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error logout:", err);
      return res.status(500).json({ message: "Gagal logout!" });
    }
    res.status(200).json({ message: "Logout berhasil!" });
  });
});

// Jalankan server
app.listen(PORT, () => {
  console.log(`Server berjalan di port ${PORT}`);
});
