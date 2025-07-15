require('dotenv').config();
const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require('nodemailer');

const JWT_SECRET = "wkdb difu qaee ayyp";
const saltRounds = 10;

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
  if (err) {
    console.error('Database connection failed:', err);
    return;
  }
  console.log("MySQL Connected...");
});

// Email transporter (using Gmail + App Password)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
});

transporter.verify((err, success) => {
  if (err) {
    console.error("Email transporter error:", err);
  } else {
    console.log("Email transporter is ready");
  }
});

// ✅ User Registration with OTP email
app.post("/users/register", (req, res) => {
  const { first_name, last_name, email, password, confirm_password, address, phone_number } = req.body;

  if (password !== confirm_password) {
    return res.status(400).json({ message: "Passwords do not match" });
  }

  const otp = Math.floor(100000 + Math.random() * 900000); // 6-digit OTP

  bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
    if (err) return res.status(500).json({ message: "Error hashing password" });

    const sql = `
      INSERT INTO users (first_name, last_name, email, password, address, phone_number, otp, is_verified)
      VALUES (?, ?, ?, ?, ?, ?, ?, 0)
    `;

    db.query(sql, [first_name, last_name, email, hashedPassword, address, phone_number, otp], (err, result) => {
      if (err) return res.status(500).json({ message: "Database error", error: err });

      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Your OTP for Registration",
        text: `Your OTP is: ${otp}`
      };

      transporter.sendMail(mailOptions, (err, info) => {
        if (err) return res.status(500).json({ message: "Error sending OTP email", error: err });
        res.status(200).json({ message: "OTP sent to email" });
      });
    });
  });
});

// ✅ User Verify OTP
app.post("/users/verify-otp", (req, res) => {
  const { email, otp } = req.body;

  const sql = "SELECT * FROM users WHERE email = ? AND otp = ?";
  db.query(sql, [email, otp], (err, result) => {
    if (err) return res.status(500).json({ message: "Database error" });

    if (result.length > 0) {
      db.query("UPDATE users SET is_verified = 1 WHERE email = ?", [email], (err) => {
        if (err) return res.status(500).json({ message: "Error updating verification status" });
        res.status(200).json({ message: "User verified successfully" });
      });
    } else {
      res.status(400).json({ message: "Invalid OTP" });
    }
  });
});

// ✅ User Login
app.post("/users/login", (req, res) => {
  const { email, password } = req.body;

  const sql = "SELECT * FROM users WHERE email = ? AND is_verified = 1";
  db.query(sql, [email], (err, results) => {
    if (err) return res.status(500).json({ message: "Database error" });

    if (results.length === 0) {
      return res.status(400).json({ message: "User not found or not verified" });
    }

    const user = results[0];

    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) return res.status(500).json({ message: "Error comparing passwords" });

      if (isMatch) {
        res.status(200).json({ message: "Login successful", user });
      } else {
        res.status(400).json({ message: "Invalid credentials" });
      }
    });
  });
});
// ✅ Update User Name (first_name and last_name)
app.put('/users/username', (req, res) => {
  const { email, first_name, last_name } = req.body;

  if (!email || !first_name || !last_name) {
    return res.status(400).json({ message: 'Missing fields' });
  }

  const sql = 'UPDATE users SET first_name = ?, last_name = ? WHERE email = ?';
  db.query(sql, [first_name, last_name, email], (err, result) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ message: 'Database error', error: err });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ message: 'Username updated successfully' });
  });
});

app.post("/users/password", (req, res) => {
  const { email, currentPassword, newPassword } = req.body;

  if (!email || !currentPassword || !newPassword) {
    return res.status(400).json({ message: 'Missing fields' });
  }

  // Step 1: Find the user
  const sql = 'SELECT * FROM users WHERE email = ?';
  db.query(sql, [email], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error', error: err });
    if (results.length === 0) return res.status(404).json({ message: 'User not found' });

    const user = results[0];

    // Step 2: Verify current password
    bcrypt.compare(currentPassword, user.password, (err, isMatch) => {
      if (err) return res.status(500).json({ message: 'Error comparing passwords' });
      if (!isMatch) return res.status(401).json({ message: 'Incorrect current password' });

      // Step 3: Hash new password
      bcrypt.hash(newPassword, saltRounds, (err, hashedPassword) => {
        if (err) return res.status(500).json({ message: 'Error hashing new password' });

        // Step 4: Update password in DB
        const updateSql = 'UPDATE users SET password = ? WHERE email = ?';
        db.query(updateSql, [hashedPassword, email], (err) => {
          if (err) return res.status(500).json({ message: 'Error updating password', error: err });
          res.json({ message: 'Password updated successfully!' });
        });
      });
    });
  });
});
app.post('/users/phonenumber', (req, res) => {
  const { email, newPhoneNumber } = req.body;

  if (!email || !newPhoneNumber) {
    return res.status(400).json({ message: 'Missing fields' });
  }

  const sql = 'UPDATE users SET phone_number = ? WHERE email = ?';
  db.query(sql, [newPhoneNumber, email], (err, result) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ message: 'Database error' });
    }

    res.json({ message: 'Phone number updated successfully' });
  });
});
app.post('/users/address', (req, res) => {
  const { email, newAddress } = req.body;

  if (!email || !newAddress) {
    return res.status(400).json({ message: 'Missing fields' });
  }

  const sql = 'UPDATE users SET address = ? WHERE email = ?';
  db.query(sql, [newAddress, email], (err, result) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ message: 'Database error' });
    }

    res.json({ message: 'Address updated successfully' });
  });
});
app.post('/users/forgot-password', (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: 'Email is required' });
  }

  // You can generate a reset token here and send an email
  const resetToken = Math.random().toString(36).substr(2, 8); // or JWT-based

  // TODO: Save token in DB and send it via email
  res.status(200).json({ message: 'Reset token generated and email sent (mock)' });
});


// ✅ Insert Rating
// Add Rating
app.post('/ratings', (req, res) => {
  const { Product_name, rating,category,subcategory, Comment, submittedBy } = req.body;
  const query = 'INSERT INTO ratings (Product_name, rating,category,subcategory, Comment, submittedBy) VALUES (?, ?, ?,?, ?, ?)';
  db.query(query, [Product_name, rating,category,subcategory, Comment, submittedBy], (err, result) => {
    if (err) return res.status(500).send(err);
    res.json({ message: "Rating submitted", id: result.insertId });
  });
});

// Get Ratings
app.get('/ratings', (req, res) => {
  db.query('SELECT * FROM ratings', (err, results) => {
    if (err) return res.status(500).send(err);
    res.json(results);
  });
});

// Update Rating
app.put('/ratings/:id', (req, res) => {
  const { id } = req.params['id'];
  const { Product_name, rating, category,subcategory,Comment, submittedBy } = req.body;
  const query = 'UPDATE ratings SET Product_name=?, rating=?,category=?,subcategory=?, Comment=?, submittedBy=? WHERE id=?';
  db.query(query, [Product_name, rating,category,subcategory, Comment, submittedBy, id], (err, result) => {
    if (err) return res.status(500).send(err);
    res.json({ message: "Rating updated" });
  });
});

// Delete Rating
app.delete('/ratings/:id', (req, res) => {
  const { id } = req.params;
  db.query('DELETE FROM ratings WHERE id = ?', [id], (err, result) => {
    if (err) return res.status(500).send(err);
    res.json({ message: "Rating deleted" });
  });
});
// ✅ Admin Registration with OTP
app.post('/admin/register', async (req, res) => {
  const { first_name, last_name, email, password, confirm_password,address, phone_number } = req.body;

  if (password !== confirm_password) {
    return res.status(400).json({ message: "Passwords do not match" });
  }

  const otp = Math.floor(100000 + Math.random() * 900000);

  try {
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const sql = `
      INSERT INTO admin (first_name, last_name, email, password,address, phone_number, otp, is_verified) 
      VALUES (?, ?, ?, ?, ?, ?,?, 0)
    `;

    db.query(sql, [first_name, last_name, email, hashedPassword,address, phone_number, otp], (error, result) => {
      if (error) {
        console.error('Database error:', error);
        return res.status(500).json({ message: 'Database error' });
      }

      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Your Admin OTP",
        text: `Your OTP is: ${otp}`
      };

      transporter.sendMail(mailOptions, (err, info) => {
        if (err) return res.status(500).json({ message: "Error sending OTP email", error: err });
        res.json({ message: 'Admin registered. OTP sent!' });
      });
    });
  } catch (err) {
    res.status(500).json({ message: 'Error hashing password' });
  }
});

// ✅ Admin Verify OTP
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

// ✅ Admin Login
app.post('/admin/login', (req, res) => {
  const { email, password } = req.body;

  const sql = 'SELECT * FROM admin WHERE email = ? AND is_verified = 1';
  db.query(sql, [email], async (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    if (results.length === 0) return res.status(400).json({ message: 'Admin not found or not verified' });

    const admin = results[0];
    const passwordMatch = await bcrypt.compare(password, admin.password);

    if (!passwordMatch) {
      return res.status(401).json({ message: 'Incorrect password' });
    }

    const token = jwt.sign({ adminId: admin.id }, JWT_SECRET, { expiresIn: '1h' });
    res.status(200).json({ message: 'Login successful', token });
  });
});

// ✅ Start the server
app.listen(5000, () => {
  console.log('Server is running on port 5000');
});
