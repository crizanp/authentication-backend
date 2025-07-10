// server.js

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const createTables = require('./config/initDB'); // Add this

const app = express();

// Connect Database
createTables(); // Add this line

// Middleware
app.use(cors({
    origin: ['http://localhost:3000', 'http://localhost:3001', 'https://full-auth-system.vercel.app'],
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Increase payload limit for file uploads (base64 documents can be large)
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Trust proxy for getting real IP addresses (important for application tracking)
app.set('trust proxy', true);

// Define Routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/applications', require('./routes/applications')); // Add the applications route

// Health check endpoint
app.get('/health', (req, res) => {
    res.status(200).json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// Root endpoint
app.get('/', (req, res) => {
    res.json({ 
        message: 'Application API Server',
        version: '1.0.0',
        endpoints: {
            auth: '/api/auth',
            applications: '/api/applications'
        }
    });
});

// Global error handling middleware
app.use((err, req, res, next) => {
    console.error('Global error handler:', err);
    
    // Handle specific error types
    if (err.name === 'ValidationError') {
        return res.status(400).json({
            message: 'Validation Error',
            errors: Object.values(err.errors).map(e => e.message)
        });
    }
    
    if (err.name === 'MongoError' && err.code === 11000) {
        return res.status(400).json({
            message: 'Duplicate entry detected'
        });
    }
    
    if (err.type === 'entity.too.large') {
        return res.status(413).json({
            message: 'File too large. Please reduce file size and try again.'
        });
    }
    
    // Default error response
    res.status(500).json({
        message: 'Internal Server Error',
        error: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
    });
});

// Handle 404 routes
app.use('*', (req, res) => {
    res.status(404).json({
        message: 'Route not found',
        path: req.originalUrl
    });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Server started on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`Available routes:`);
    console.log(`  - GET  / (Root endpoint)`);
    console.log(`  - GET  /health (Health check)`);
    console.log(`  - POST /api/auth/* (Authentication routes)`);
    console.log(`  - GET|POST /api/applications/* (Application routes)`);
});