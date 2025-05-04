import mongoose from 'mongoose';

export const Credential = mongoose.model(
    "Credential",
    new mongoose.Schema({
      userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
      title: { type: String, required: true },
      username: { type: String, required: true },
      password: { type: String, required: true }, // Encrypted password
      notes: { type: String },
    })
  );