// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const createTables = require('./config/initDB');
const app = express();

createTables();

app.use(cors({
    origin: ['http://localhost:3000', 'http://localhost:3001', 'https://full-auth-system.vercel.app','portal.nepalishram.com'],
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

app.set('trust proxy', true);

app.use((req, res, next) => {
    console.log(`📡 ${new Date().toISOString()} - ${req.method} ${req.originalUrl}`);
    console.log('📋 Headers:', req.headers);
    console.log('🔍 Query:', req.query);
    if (req.body && Object.keys(req.body).length > 0) {
        console.log('📦 Body:', req.body);
    }
    next();
});

try {
    const authRoutes = require('./routes/auth');
    app.use('/api/auth', authRoutes);
    console.log('✅ Auth routes loaded successfully');
} catch (error) {
    console.error('❌ Failed to load auth routes:', error.message);
}

try {
    const adminDashboardRoutes = require('./routes/adminDashboard');
    app.use('/api/admin/dashboard', adminDashboardRoutes);
    console.log('✅ Admin dashboard routes loaded successfully');
} catch (error) {
    console.error('❌ Failed to load admin dashboard routes:', error.message);
}

try {
    const adminApplicationsRoutes = require('./routes/adminApplications');
    app.use('/api/admin/applications', adminApplicationsRoutes);
    console.log('✅ Admin applications routes loaded successfully');
} catch (error) {
    console.error('❌ Failed to load admin applications routes:', error.message);
}

try {
    const adminRoutes = require('./routes/admin');
    app.use('/api/admin', adminRoutes);
    console.log('✅ Admin routes loaded successfully');
} catch (error) {
    console.error('❌ Failed to load admin routes:', error.message);
}

try {
    const applicationsRoutes = require('./routes/applications');
    app.use('/api/applications', applicationsRoutes);
    console.log('✅ Applications routes loaded successfully');
} catch (error) {
    console.error('❌ Failed to load applications routes:', error.message);
}

app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

app.get('/', (req, res) => {
    res.json({
        message: 'Application API Server',
        version: '1.0.0',
        endpoints: {
            auth: '/api/auth',
            admin: '/api/admin',
            adminDashboard: '/api/admin/dashboard',
            adminApplications: '/api/admin/applications',
            applications: '/api/applications'
        }
    });
});

app.get('/debug/routes', (req, res) => {
    const routes = [];
    
    app._router.stack.forEach((middleware) => {
        if (middleware.route) {
            routes.push({
                path: middleware.route.path,
                methods: Object.keys(middleware.route.methods)
            });
        } else if (middleware.name === 'router') {
            middleware.handle.stack.forEach((handler) => {
                if (handler.route) {
                    const basePath = middleware.regexp.source
                        .replace('^\\\/', '')
                        .replace('\\/?(?=\\/|$)', '')
                        .replace(/\\\//g, '/');
                    
                    routes.push({
                        path: `/${basePath}${handler.route.path}`,
                        methods: Object.keys(handler.route.methods)
                    });
                }
            });
        }
    });
    
    res.json({
        message: 'All registered routes',
        routes: routes.sort((a, b) => a.path.localeCompare(b.path))
    });
});

app.use((err, req, res, next) => {
    console.error('🚨 Global error handler:', err);
    
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
    
    res.status(500).json({
        message: 'Internal Server Error',
        error: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
    });
});

app.use('*', (req, res) => {
    console.log('❌ 404 - Route not found:', {
        method: req.method,
        originalUrl: req.originalUrl,
        baseUrl: req.baseUrl,
        path: req.path,
        headers: req.headers,
        timestamp: new Date().toISOString()
    });
    
    res.status(404).json({
        message: 'Route not found',
        path: req.originalUrl,
        method: req.method,
        timestamp: new Date().toISOString(),
        suggestion: 'Check /debug/routes endpoint to see all available routes'
    });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Server started on port ${PORT}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`📍 Available routes:`);
    console.log(`  - GET  / (Root endpoint)`);
    console.log(`  - GET  /health (Health check)`);
    console.log(`  - GET  /debug/routes (Debug all routes)`);
    console.log(`  - POST /api/auth/* (User authentication routes)`);
    console.log(`  - GET|POST /api/admin/dashboard/* (Admin dashboard routes)`);
    console.log(`  - GET|POST /api/admin/applications/* (Admin application routes)`);
    console.log(`  - POST /api/admin/* (Admin authentication routes)`);
    console.log(`  - GET|POST /api/applications/* (Application routes)`);
    console.log(`\n🔧 Debug endpoints:`);
    console.log(`  - Visit http://localhost:${PORT}/debug/routes to see all registered routes`);
    console.log(`  - Check console for detailed request logging\n`);
});