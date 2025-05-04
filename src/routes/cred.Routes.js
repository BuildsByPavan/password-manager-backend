import express from 'express';
import { createCredential, allCredential, updateCredential, deleteCredential } from '../controllers/authController.js';
import protect from '../middleware/authMiddleware.js';

const router = express.Router();

// ---------- Credential Endpoints (Protected) ----------

// Create new credential
router.post("/credentials", protect , createCredential);

// Get all credentials
router.get("/credentials", protect, allCredential );

// Update an existing credential
router.put("/credentials/:id", protect, updateCredential);

// Delete a credential
router.delete("/credentials/:id", protect, deleteCredential);

export default router;
