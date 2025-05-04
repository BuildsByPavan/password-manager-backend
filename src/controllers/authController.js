import User from '../models/User.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { Credential } from '../models/Credential.js';
import crypto from "crypto";

// Register a new user
export const registerUser = async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ message: 'Please add all fields' });
  }

  const userExists = await User.findOne({ email });
  if (userExists) {
    return res.status(400).json({ message: 'User already exists' });
  }

  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  const user = await User.create({ name, email, password: hashedPassword });

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
    expiresIn: '30d',
  });

  res.status(201).json({
    id: user._id,
    name: user.name,
    email: user.email,
    token,
  });
};

// Login existing user
export const loginUser = async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });

  if (user && (await bcrypt.compare(password, user.password))) {
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: '30d',
    });
    return res.json({
      id: user._id,
      name: user.name,
      email: user.email,
      token,
    });
  } else {
    return res.status(401).json({ message: 'Invalid credentials' });
  }
};

// Encryption Functions

const ENCRYPTION_KEY =
  process.env.ENCRYPTION_KEY || "12345678901234567890123456789012"; // Must be 32 bytes
const IV_LENGTH = 16;

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

export const createCredential = async (req, res) => {
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
}

export const allCredential = async (req, res) => {
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
}

export const updateCredential = async (req, res) => {
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
}

export const deleteCredential = async (req, res) => {
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
}

