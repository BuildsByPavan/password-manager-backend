// server.js
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const crypto = require("crypto");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const authMiddleware = require("./authMiddleware");
const User = require("./models/User");

// Constants for encryption
const ENCRYPTION_KEY =
  process.env.ENCRYPTION_KEY || "12345678901234567890123456789012"; // Must be 32 bytes
const IV_LENGTH = 16;

const JWT_SECRET = process.env.JWT_SECRET;

const app = express();
app.use(cors()); // Restrict origins in production if needed
app.use(bodyParser.json());

const mongooseUri = process.env.DB_URI;

// Connect to MongoDB
mongoose
  .connect(mongooseUri, { serverSelectionTimeoutMS: 30000 })
  .then(() => console.log("MongoDB Atlas connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

// Encryption Functions
function encrypt(text) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(
    "aes-256-cbc",
    Buffer.from(ENCRYPTION_KEY),
    iv
  );
  let encrypted = Buffer.concat([cipher.update(text), cipher.final()]);
  return iv.toString("hex") + ":" + encrypted.toString("hex");
}

function decrypt(text) {
  const parts = text.split(":");
  const iv = Buffer.from(parts.shift(), "hex");
  const encryptedText = Buffer.from(parts.join(":"), "hex");
  const decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    Buffer.from(ENCRYPTION_KEY),
    iv
  );
  let decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()]);
  return decrypted.toString();
}

// Mongoose Models
const Credential = mongoose.model(
  "Credential",
  new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    title: { type: String, required: true },
    username: { type: String, required: true },
    password: { type: String, required: true }, // Encrypted password
    notes: { type: String },
  })
);

// ---------- Authentication Endpoints ----------

// Registration
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ error: "All fields are required." });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: "Invalid email address." });
    }

    // Validate password length
    if (password.length < 8) {
      return res
        .status(400)
        .json({ error: "Password must be at least 8 characters long." });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res
        .status(400)
        .json({ error: "User with this email already exists." });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const user = new User({ username, email, password: hashedPassword });
    await user.save();

    res.status(201).json({ message: "User registered successfully." });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ error: "Server error during registration." });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res
        .status(400)
        .json({ error: "Email and password are required." });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: "Invalid credentials." });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: "Invalid credentials." });
    }

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "1d" });
    res.json({
      token,
      user: { id: user._id, username: user.username, email: user.email },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Server error during login." });
  }
});

// ---------- Credential Endpoints (Protected) ----------

// Create new credential
app.post("/api/credentials", authMiddleware, async (req, res) => {
  try {
    const { title, username, password, notes } = req.body;
    if (!title || !username || !password) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    const encryptedPassword = encrypt(password);
    const credential = new Credential({
      userId: req.userId,
      title,
      username,
      password: encryptedPassword,
      notes,
    });
    await credential.save();
    res.status(201).json({ message: "Credential saved" });
  } catch (error) {
    console.error("Error saving credential:", error);
    res.status(500).json({ error: "Error saving credential" });
  }
});

// Get all credentials
app.get("/api/credentials", authMiddleware, async (req, res) => {
  try {
    const credentials = await Credential.find({ userId: req.userId });
    const decryptedCredentials = credentials.map((cred) => ({
      _id: cred._id,
      title: cred.title,
      username: cred.username,
      password: decrypt(cred.password),
      notes: cred.notes,
    }));
    res.json(decryptedCredentials);
  } catch (error) {
    console.error("Error retrieving credentials:", error);
    res.status(500).json({ error: "Error retrieving credentials" });
  }
});

// Update an existing credential
app.put("/api/credentials/:id", authMiddleware, async (req, res) => {
  try {
    const { title, username, password, notes } = req.body;
    if (!title || !username || !password) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    const encryptedPassword = encrypt(password);
    const updatedCredential = await Credential.findOneAndUpdate(
      { _id: req.params.id, userId: req.userId },
      { title, username, password: encryptedPassword, notes },
      { new: true }
    );
    if (!updatedCredential) {
      return res.status(404).json({ error: "Credential not found" });
    }
    res.json({ message: "Credential updated successfully" });
  } catch (error) {
    console.error("Error updating credential:", error);
    res.status(500).json({ error: "Error updating credential" });
  }
});

// Delete a credential
app.delete("/api/credentials/:id", authMiddleware, async (req, res) => {
  try {
    const deleted = await Credential.findOneAndDelete({
      _id: req.params.id,
      userId: req.userId,
    });
    if (!deleted) {
      return res.status(404).json({ error: "Credential not found" });
    }
    res.json({ message: "Credential deleted successfully" });
  } catch (error) {
    console.error("Error deleting credential:", error);
    res.status(500).json({ error: "Error deleting credential" });
  }
});

// Global error handler
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err.stack);
  res.status(500).json({ error: "Something went wrong!" });
});

// Start the server with a default port
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));