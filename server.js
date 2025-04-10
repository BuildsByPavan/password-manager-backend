// server.js
require("dotenv").config();
const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const authMiddleware = require('./authMiddleware');
const User = require('./models/User');


// Constants for encryption (already present)
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '12345678901234567890123456789012';
const IV_LENGTH = 16;

const JWT_SECRET = process.env.JWT_SECRET;

const app = express();
app.use(cors());
app.use(bodyParser.json());


// Connect to MongoDB
mongoose
  .connect(process.env.DB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error(err));

// Encryption Functions
function encrypt(text) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
  let encrypted = Buffer.concat([cipher.update(text), cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
  const parts = text.split(':');
  const iv = Buffer.from(parts.shift(), 'hex');
  const encryptedText = Buffer.from(parts.join(':'), 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
  let decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()]);
  return decrypted.toString();
}

// Mongoose Models
const Credential = mongoose.model('Credential', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true }, // Encrypted password
  notes: { type: String }
}));

// ---------- Authentication Endpoints ----------

// Registration
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if(!username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required.' });
    }
    
    // Check if the email is already registered
    const existingUser = await User.findOne({ email });
    if(existingUser) {
      return res.status(400).json({ error: 'User with this email already exists.' });
    }
    
    // Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    const user = new User({ username, email, password: hashedPassword });
    await user.save();
    
    res.status(201).json({ message: 'User registered successfully.' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error during registration.' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if(!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }
    
    const user = await User.findOne({ email });
    if(!user) {
      return res.status(400).json({ error: 'Invalid credentials.' });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if(!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials.' });
    }
    
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1d' });
    
    res.json({ token, user: { id: user._id, username: user.username, email: user.email } });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login.' });
  }
});

// ---------- Credential Endpoints (Protected) ----------

// Create new credential (requires authentication)
app.post('/api/credentials', authMiddleware, async (req, res) => {
  try {
    const { title, username, password, notes } = req.body;
    if (!title || !username || !password) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    const encryptedPassword = encrypt(password);
    const credential = new Credential({ userId: req.userId, title, username, password: encryptedPassword, notes });
    await credential.save();
    res.status(201).json({ message: 'Credential saved' });
  } catch (error) {
    console.error('Error saving credential:', error);
    res.status(500).json({ error: 'Error saving credential' });
  }
});

// Get all credentials for the logged-in user
app.get('/api/credentials', authMiddleware, async (req, res) => {
  try {
    const credentials = await Credential.find({ userId: req.userId });
    const decryptedCredentials = credentials.map(cred => ({
      _id: cred._id,
      title: cred.title,
      username: cred.username,
      password: decrypt(cred.password),
      notes: cred.notes
    }));
    res.json(decryptedCredentials);
  } catch (error) {
    console.error('Error retrieving credentials:', error);
    res.status(500).json({ error: 'Error retrieving credentials' });
  }
});

// Update an existing credential
app.put('/api/credentials/:id', authMiddleware, async (req, res) => {
  try {
    const { title, username, password, notes } = req.body;
    if (!title || !username || !password) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    const encryptedPassword = encrypt(password);
    const updatedCredential = await Credential.findOneAndUpdate(
      { _id: req.params.id, userId: req.userId },
      { title, username, password: encryptedPassword, notes },
      { new: true }
    );
    if (!updatedCredential) {
      return res.status(404).json({ error: 'Credential not found' });
    }
    res.json({ message: 'Credential updated successfully' });
  } catch (error) {
    console.error('Error updating credential:', error);
    res.status(500).json({ error: 'Error updating credential' });
  }
});

// Delete a credential
app.delete('/api/credentials/:id', authMiddleware, async (req, res) => {
  try {
    const deleted = await Credential.findOneAndDelete({ _id: req.params.id, userId: req.userId });
    if (!deleted) {
      return res.status(404).json({ error: 'Credential not found' });
    }
    res.json({ message: 'Credential deleted successfully' });
  } catch (error) {
    console.error('Error deleting credential:', error);
    res.status(500).json({ error: 'Error deleting credential' });
  }
});

const PORT = process.env.PORT ;
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
