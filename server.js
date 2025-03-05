require('dotenv').config();
const express = require('express');
const cors = require('cors');
const connectDB = require('./config/db');

const app = express();

// Connect Database
connectDB();

// Middleware
app.use(cors({
    origin: ['http://localhost:3000','http://localhost:3001','https://full-auth-system.vercel.app'], 
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization']

  }));
  app.use(express.json());

// Define Routes
app.use('/api/auth', require('./routes/auth'));

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => console.log(`Server started on port ${PORT}`));