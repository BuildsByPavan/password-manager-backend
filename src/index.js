import express from 'express';
import dotenv from 'dotenv';
import connectDB from './config/db.js';
import authRoutes from './routes/authRoutes.js';
import cors from "cors";
import credRoutes from "./routes/cred.Routes.js"

dotenv.config();
connectDB();

const app = express();

app.use(cors());

app.use(express.json());

app.use('/api', authRoutes);
app.use('/api', credRoutes);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
