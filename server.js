require('dotenv').config();
const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require('nodemailer');


const app = express();
app.use(cors());
app.use(express.json());

// Database connection
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "root",
  database: "user_ratings_db",
});

db.connect((err) => {
  if (err) throw err;
  console.log("MySQL Connected...");
});

// Insert rating
app.post("/ratings", (req, res) => {
  const { user_name, rating, comments } = req.body;
  const sql = "INSERT INTO ratings (user_name, rating, comments) VALUES (?, ?, ?)";
  db.query(sql, [user_name, rating, comments], (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: "Rating submitted", ratingId: result.insertId });
  });
});

// Get all ratings
app.get("/ratings", (req, res) => {
  db.query("SELECT * FROM ratings", (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});
db.connect(err => {
  if (err) {
    console.error('Database connection failed:', err);
  } else {
    console.log('Connected to MySQL');
  }
});

// 🔹 Register User (Insert into MySQL)
app.post('/users/register', (req, res) => {
  const { email, password } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000); // Generate a random OTP

  const query = 'INSERT INTO users (email, password, otp, is_verified) VALUES (?, ?, ?, ?)';
  db.query(query, [email, password, otp, 0], (err, result) => {
    if (err) {
      console.error('Error inserting user:', err);
      return res.status(500).send({ message: 'Database error' });
    }
    res.status(200).send({ message: 'OTP sent to email', otp }); // Simulating OTP sending
  });
});

// 🔹 Verify OTP
app.post('/users/verify-otp', (req, res) => {
  const { email, otp } = req.body;

  const query = 'SELECT * FROM users WHERE email = ? AND otp = ?';
  db.query(query, [email, otp], (err, result) => {
    if (err) return res.status(500).send({ message: 'Database error' });

    if (result.length > 0) {
      db.query('UPDATE users SET is_verified = 1 WHERE email = ?', [email]);
      res.status(200).send({ message: 'User verified successfully' });
    } else {
      res.status(400).send({ message: 'Invalid OTP' });
    }
  });
});

// 🔹 Login User
app.post('/users/login', (req, res) => {
  const { email, password } = req.body;

  const query = 'SELECT * FROM users WHERE email = ? AND password = ? AND is_verified = 1';
  db.query(query, [email, password], (err, result) => {
    if (err) return res.status(500).send({ message: 'Database error' });

    if (result.length > 0) {
      res.status(200).send({ message: 'Login successful', user: result[0] });
    } else {
      res.status(400).send({ message: 'Invalid credentials or not verified' });
    }
  });
});

// Start the server
app.listen(5000, () => {
  console.log('Server is running on port 5000');
});