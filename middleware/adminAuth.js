// middleware/adminAuth.js

const jwt = require('jsonwebtoken');
const Admin = require('../models/Admin');

const adminAuth = async (req, res, next) => {
  try {
    // Get token from header
    const authHeader = req.header('Authorization');
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'No token provided, authorization denied' });
    }

    const token = authHeader.substring(7); // Remove 'Bearer ' prefix

    if (!token) {
      return res.status(401).json({ message: 'No token provided, authorization denied' });
    }

    try {
      // Verify token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      // Check if it's an admin token (has admin property)
      if (!decoded.admin) {
        return res.status(401).json({ message: 'Invalid token format for admin access' });
      }

      // Verify admin still exists and is active
      const admin = await Admin.findById(decoded.admin.id);
      if (!admin || !admin.is_active) {
        return res.status(401).json({ message: 'Admin account not found or deactivated' });
      }

      // Add admin info to request
      req.admin = decoded.admin;
      next();
    } catch (tokenError) {
      console.error('Token verification error:', tokenError);
      return res.status(401).json({ message: 'Invalid token' });
    }
  } catch (err) {
    console.error('Admin auth middleware error:', err);
    res.status(500).json({ message: 'Server error in authentication' });
  }
};

// Middleware for SuperAdmin only routes
const superAdminAuth = async (req, res, next) => {
  try {
    // First run the regular admin auth
    await adminAuth(req, res, () => {
      // Check if admin has superadmin role
      if (req.admin.role !== 'superadmin') {
        return res.status(403).json({ 
          message: 'Access denied. SuperAdmin privileges required.' 
        });
      }
      next();
    });
  } catch (err) {
    console.error('SuperAdmin auth middleware error:', err);
    res.status(500).json({ message: 'Server error in authentication' });
  }
};

module.exports = { adminAuth, superAdminAuth };