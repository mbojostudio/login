const express = require("express");
const bodyParser = require("body-parser");
const admin = require("firebase-admin");
const session = require("express-session");
const path = require("path");
const multer = require("multer");
const fs = require('fs');
const bcrypt = require("bcrypt");
const axios = require('axios');
const crypto = require('crypto');

// Setup multer untuk menangani unggahan file
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });
require('dotenv').config();
// Ambil path dari environment variable dan resolve ke path absolut
const googleCloudKeyPath = path.resolve(__dirname, process.env.GOOGLE_CLOUD_SERVICE_ACCOUNT_KEY);

// Baca dan parse file JSON kunci layanan
const googleCloudKey = JSON.parse(fs.readFileSync(googleCloudKeyPath, 'utf8'));

// Inisialisasi Firebase Admin SDK
admin.initializeApp({
  credential: admin.credential.cert(googleCloudKey),
  databaseURL: "https://fbuses-3e232-default-rtdb.firebaseio.com/", // Ganti sesuai databaseURL Firebase Anda
});
// Set up multer untuk menyimpan file di server

const db = admin.database();
const app = express();
const PORT = process.env.PORT || 3000;
app.use(express.json());
const cors = require("cors");
app.use(cors());
// Middleware untuk memproses JSON
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
// Middleware session
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
    return res.status(400).json({ message: "Email and password are required." });
  }

  try {
    const usersRef = db.ref("users");
    const snapshot = await usersRef.orderByChild("email").equalTo(email).once("value");

    if (!snapshot.exists()) {
      return res.status(404).json({ message: "User not found." });
    }

    const userData = Object.values(snapshot.val())[0];

    // Periksa password yang di-hash
    const isPasswordValid = await bcrypt.compare(password, userData.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Incorrect password." });
    }

    res.status(200).json({ 
      message: "Login successful", 
      userId: userData.id,
      name: userData.username
    });
    
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});
// Endpoint untuk logout
app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: "Gagal logout!" });
    }
    res.status(200).json({ message: "Logout berhasil!" });
  });
});
// Jalankan server
// Ekspor app untuk digunakan oleh Vercel
module.exports = app;