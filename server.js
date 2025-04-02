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


app.post('/admin/register', (req, res) => {
  const { name, email, password } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000);

  bcrypt.hash(password, 10, (err, Password) => {
      if (err) return res.status(500).json({ message: 'Error hashing password' });

      const sql = 'INSERT INTO admin (name, email, password, otp, is_verified) VALUES (?, ?, ?, ?, 0)';
      db.query(sql, [name, email, Password, otp], (error, result) => {
          if (error) {
              console.error('Database error:', error);
              return res.status(500).json({ message: 'Database error' });
          }
          res.json({ message: 'Admin registered. OTP sent!', otp });
      });
  });
});

// Verify OTP
app.post('/admin/verify-otp', (req, res) => {
  const { email, otp } = req.body;

  db.query('SELECT * FROM admin WHERE email = ? AND otp = ?', [email, otp], (err, result) => {
      if (err) return res.status(500).json({ message: 'Database error' });

      if (result.length > 0) {
          db.query('UPDATE admin SET is_verified = 1 WHERE email = ?', [email], (error) => {
              if (error) return res.status(500).json({ message: 'Database update error' });
              res.status(200).json({ message: 'Admin verified successfully' });
          });
      } else {
          res.status(400).json({ message: 'Invalid OTP' });
      }
  });
});
app.post('/admin/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }

  const query = 'SELECT * FROM admin WHERE email = ? AND is_verified = 1';
  db.query(query, [email], async (err, result) => {
    if (err) return res.status(500).json({ message: 'Database error' });

    if (result.length === 0) {
      return res.status(400).json({ message: 'Invalid credentials or account not verified' });
    }

    const admin = result[0];

    // Compare hashed password
    const passwordMatch = await bcrypt.compare(password, admin.password);
    if (!passwordMatch) {
      return res.status(400).json({ message: 'Incorrect password' });
    }

    // Generate JWT token
    const token = jwt.sign({ id: admin.id, email: admin.email }, 'your_secret_key', { expiresIn: '1h' });

    res.status(200).json({ message: 'Login successful', token, admin });
  });
});



// Start the server
app.listen(5000, () => {
  console.log('Server is running on port 5000');
});