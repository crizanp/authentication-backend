// middleware/auth.js
const jwt = require('jsonwebtoken');

module.exports = function(req, res, next) {
  // Get token from header
  const authHeader = req.header('Authorization');
  const token = authHeader && authHeader.startsWith('Bearer ') 
    ? authHeader.substring(7) 
    : null;

  console.log('Auth middleware - Received token:', token ? 'Token present' : 'No token');
  console.log('Auth middleware - Authorization header:', authHeader);

  // Check if no token
  if (!token) {
    return res.status(401).json({ message: 'No token, authorization denied' });
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Add user info to request
    req.user = decoded.user || { id: decoded.id }; // Handle both token formats
    
    console.log('Auth middleware - Decoded user:', req.user);
    next();
  } catch (err) {
    console.log('Auth middleware - Token verification error:', err.message);
    res.status(401).json({ message: 'Token is not valid' });
  }
};