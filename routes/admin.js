// routes/admin.js

const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Admin = require('../models/Admin');
const { adminAuth, superAdminAuth } = require('../middleware/adminAuth');
const { body, validationResult } = require('express-validator');
const pool = require('../config/database'); // Adjust path as needed



router.post('/login', [
  body('email').optional().isEmail().withMessage('Please provide a valid email'),
  body('username').optional().notEmpty().withMessage('Username is required'),
  body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
  try {
    console.log('🔍 LOGIN ATTEMPT STARTED');
    console.log('🔍 Request body:', req.body);
    console.log('🔍 Request headers:', req.headers);
    
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.log('❌ Validation errors:', errors.array());
      return res.status(400).json({ 
        message: 'Validation failed', 
        errors: errors.array() 
      });
    }

    const { username, email, password } = req.body;
    console.log('🔍 Extracted fields:', { 
      username, 
      email, 
      password: password ? '***' + password.slice(-3) : 'undefined',
      passwordLength: password ? password.length : 0
    });

    // Check if either username or email is provided
    if (!username && !email) {
      console.log('❌ Neither username nor email provided');
      return res.status(400).json({ message: 'Username or email is required' });
    }

    // Find admin by username or email
    let admin;
    console.log('🔍 Searching for admin...');
    
    if (email) {
      console.log('🔍 Searching by email:', email);
      admin = await Admin.findByEmail(email);
      console.log('🔍 Admin found by email:', admin ? 'YES' : 'NO');
    } else {
      console.log('🔍 Searching by username:', username);
      admin = await Admin.findByUsername(username);
      console.log('🔍 Admin found by username:', admin ? 'YES' : 'NO');
    }

    if (admin) {
      console.log('🔍 Admin details:', {
        id: admin.id,
        username: admin.username,
        email: admin.email,
        role: admin.role,
        is_active: admin.is_active,
        hasPassword: !!admin.password
      });
    }

    if (!admin) {
      console.log('❌ Admin not found in database');
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Check if admin is active
    if (!admin.is_active) {
      console.log('❌ Admin account is deactivated');
      return res.status(401).json({ message: 'Admin account is deactivated' });
    }

    // Check password
    console.log('🔍 Checking password...');
    console.log('🔍 Stored password hash:', admin.password ? admin.password.substring(0, 20) + '...' : 'undefined');
    
    const isMatch = await bcrypt.compare(password, admin.password);
    console.log('🔍 Password match result:', isMatch);
    
    if (!isMatch) {
      console.log('❌ Password does not match');
      // Additional debug: let's verify the password hashing
      console.log('🔍 Testing password hash generation...');
      const testHash = await bcrypt.hash(password, 12);
      console.log('🔍 New hash for same password:', testHash.substring(0, 20) + '...');
      
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    console.log('✅ Password verified successfully');

    // Check JWT_SECRET
    console.log('🔍 JWT_SECRET exists:', !!process.env.JWT_SECRET);
    console.log('🔍 JWT_SECRET length:', process.env.JWT_SECRET ? process.env.JWT_SECRET.length : 0);

    // Update last login
    console.log('🔍 Updating last login...');
    await Admin.updateLastLogin(admin.id);
    console.log('✅ Last login updated');

    // Generate JWT token
    console.log('🔍 Generating JWT token...');
    const tokenPayload = { 
      admin: { 
        id: admin.id, 
        username: admin.username, 
        role: admin.role 
      } 
    };
    console.log('🔍 Token payload:', tokenPayload);

    const token = jwt.sign(
      tokenPayload,
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );

    console.log('✅ JWT token generated:', token ? 'YES' : 'NO');
    console.log('🔍 Token length:', token ? token.length : 0);

    // Remove password from response
    const { password: _, ...adminWithoutPassword } = admin;

    console.log('✅ Login successful for admin:', admin.username);
    console.log('🔍 Response data:', {
      message: 'Login successful',
      tokenExists: !!token,
      adminId: adminWithoutPassword.id,
      adminUsername: adminWithoutPassword.username,
      adminRole: adminWithoutPassword.role
    });

    res.json({
      message: 'Login successful',
      token,
      admin: adminWithoutPassword
    });

  } catch (err) {
    console.error('❌ Admin login error:', err);
    console.error('❌ Error stack:', err.stack);
    res.status(500).json({ 
      message: 'Server error during login',
      error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});
// @route   GET /api/admin/me
// @desc    Get current admin profile
// @access  Private (Admin)
router.get('/me', adminAuth, async (req, res) => {
  try {
    const admin = await Admin.findById(req.admin.id);
    if (!admin) {
      return res.status(404).json({ message: 'Admin not found' });
    }

    // Remove password from response
    const { password, ...adminWithoutPassword } = admin;
    res.json(adminWithoutPassword);
  } catch (err) {
    console.error('Get admin profile error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   PUT /api/admin/update-profile
// @desc    Update admin profile
// @access  Private (Admin)
router.put('/update-profile', adminAuth, [
  body('full_name').optional().isLength({ min: 2 }).withMessage('Full name must be at least 2 characters'),
  body('email').optional().isEmail().withMessage('Please provide a valid email')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        message: 'Validation failed', 
        errors: errors.array() 
      });
    }

    const { full_name, email } = req.body;

    // Check if email is already taken by another admin
    if (email) {
      const existingAdmin = await Admin.findByEmail(email);
      if (existingAdmin && existingAdmin.id !== req.admin.id) {
        return res.status(400).json({ message: 'Email already in use' });
      }
    }

    const updateData = {};
    if (full_name !== undefined) updateData.full_name = full_name;
    if (email !== undefined) updateData.email = email;

    const updatedAdmin = await Admin.updateProfile(req.admin.id, updateData);
    
    if (!updatedAdmin) {
      return res.status(404).json({ message: 'Admin not found' });
    }

    res.json({
      message: 'Profile updated successfully',
      admin: updatedAdmin
    });
  } catch (err) {
    console.error('Admin profile update error:', err);
    res.status(500).json({ message: err.message || 'Server error' });
  }
});

// @route   PUT /api/admin/change-password
// @desc    Change admin password
// @access  Private (Admin)
router.put('/change-password', adminAuth, [
  body('currentPassword').notEmpty().withMessage('Current password is required'),
  body('newPassword').isLength({ min: 8 }).withMessage('New password must be at least 8 characters long')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        message: 'Validation failed', 
        errors: errors.array() 
      });
    }

    const { currentPassword, newPassword } = req.body;

    const admin = await Admin.findById(req.admin.id);
    if (!admin) {
      return res.status(404).json({ message: 'Admin not found' });
    }

    // Check current password
    const isMatch = await bcrypt.compare(currentPassword, admin.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Current password is incorrect' });
    }

    // Hash new password
    const salt = await bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    await Admin.updatePassword(admin.id, hashedPassword);

    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    console.error('Admin password change error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   POST /api/admin/create-admin
// @desc    Create new admin (SuperAdmin only)
// @access  Private (SuperAdmin)
router.post('/create-admin', adminAuth, [
  body('username').isLength({ min: 3 }).withMessage('Username must be at least 3 characters'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
  body('role').isIn(['admin', 'superadmin']).withMessage('Role must be either admin or superadmin'),
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('full_name').isLength({ min: 2 }).withMessage('Full name must be at least 2 characters')
], async (req, res) => {
  try {
    // Check if requesting admin is superadmin
    if (req.admin.role !== 'superadmin') {
      return res.status(403).json({ message: 'Access denied. SuperAdmin privileges required.' });
    }

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        message: 'Validation failed', 
        errors: errors.array() 
      });
    }

    const { username, password, role, email, full_name } = req.body;

    // Check if username already exists
    const existingAdmin = await Admin.findByUsername(username);
    if (existingAdmin) {
      return res.status(400).json({ message: 'Username already exists' });
    }

    // Check if email already exists
    const existingEmail = await Admin.findByEmail(email);
    if (existingEmail) {
      return res.status(400).json({ message: 'Email already exists' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create admin
    const newAdmin = await Admin.create({
      username,
      password: hashedPassword,
      role,
      email,
      full_name,
      created_by: req.admin.id
    });

    res.status(201).json({
      message: 'Admin created successfully',
      admin: newAdmin
    });
  } catch (err) {
    console.error('Create admin error:', err);
    res.status(500).json({ message: err.message || 'Server error' });
  }
});

// @route   GET /api/admin/admins
// @desc    Get all admins
// @access  Private (Admin)
router.get('/admins', adminAuth, async (req, res) => {
  try {
    const admins = await Admin.getAllAdmins(req.admin.role);
    res.json(admins);
  } catch (err) {
    console.error('Get admins error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   PUT /api/admin/admins/:id/role
// @desc    Change admin role (SuperAdmin only)
// @access  Private (SuperAdmin)
router.put('/admins/:id/role', adminAuth, [
  body('role').isIn(['admin', 'superadmin']).withMessage('Role must be either admin or superadmin')
], async (req, res) => {
  try {
    // Check if requesting admin is superadmin
    if (req.admin.role !== 'superadmin') {
      return res.status(403).json({ message: 'Access denied. SuperAdmin privileges required.' });
    }

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        message: 'Validation failed', 
        errors: errors.array() 
      });
    }

    const { id } = req.params;
    const { role } = req.body;

    // Prevent changing own role
    if (parseInt(id) === req.admin.id) {
      return res.status(400).json({ message: 'Cannot change your own role' });
    }

    const updatedAdmin = await Admin.changeAdminRole(id, role, req.admin.id);
    
    if (!updatedAdmin) {
      return res.status(404).json({ message: 'Admin not found' });
    }

    res.json({
      message: 'Admin role updated successfully',
      admin: updatedAdmin
    });
  } catch (err) {
    console.error('Change admin role error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   PUT /api/admin/admins/:id/deactivate
// @desc    Deactivate admin (SuperAdmin only)
// @access  Private (SuperAdmin)
router.put('/admins/:id/deactivate', adminAuth, async (req, res) => {
  try {
    // Check if requesting admin is superadmin
    if (req.admin.role !== 'superadmin') {
      return res.status(403).json({ message: 'Access denied. SuperAdmin privileges required.' });
    }

    const { id } = req.params;

    // Prevent deactivating own account
    if (parseInt(id) === req.admin.id) {
      return res.status(400).json({ message: 'Cannot deactivate your own account' });
    }

    const updatedAdmin = await Admin.deactivateAdmin(id);
    
    if (!updatedAdmin) {
      return res.status(404).json({ message: 'Admin not found' });
    }

    res.json({
      message: 'Admin deactivated successfully',
      admin: updatedAdmin
    });
  } catch (err) {
    console.error('Deactivate admin error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   PUT /api/admin/admins/:id/activate
// @desc    Activate admin (SuperAdmin only)
// @access  Private (SuperAdmin)
router.put('/admins/:id/activate', adminAuth, async (req, res) => {
  try {
    // Check if requesting admin is superadmin
    if (req.admin.role !== 'superadmin') {
      return res.status(403).json({ message: 'Access denied. SuperAdmin privileges required.' });
    }

    const { id } = req.params;

    const updatedAdmin = await Admin.activateAdmin(id);
    
    if (!updatedAdmin) {
      return res.status(404).json({ message: 'Admin not found' });
    }

    res.json({
      message: 'Admin activated successfully',
      admin: updatedAdmin
    });
  } catch (err) {
    console.error('Activate admin error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   GET /api/admin/stats
// @desc    Get admin statistics (SuperAdmin only)
// @access  Private (SuperAdmin)
router.get('/stats', adminAuth, async (req, res) => {
  try {
    // Check if requesting admin is superadmin
    if (req.admin.role !== 'superadmin') {
      return res.status(403).json({ message: 'Access denied. SuperAdmin privileges required.' });
    }

    const stats = await Admin.getAdminStats();
    res.json(stats);
  } catch (err) {
    console.error('Get admin stats error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   POST /api/admin/logout
// @desc    Admin logout (just for client-side cleanup)
// @access  Private (Admin)
router.post('/logout', adminAuth, (req, res) => {
  res.json({ message: 'Logout successful' });
});

// @route   GET /api/admin/users
// @desc    Get all users with pagination and filtering
// @access  Private (Admin)
router.get('/users', adminAuth, async (req, res) => {
  try {
    const {
      page = 1,
      limit = 10,
      verified = 'all',
      search = '',
      sortBy = 'created_at',
      sortOrder = 'DESC'
    } = req.query;

    console.log('📋 Get users request:', { page, limit, verified, search, sortBy, sortOrder });

    const offset = (parseInt(page) - 1) * parseInt(limit);
    
    // Build where conditions
    const whereConditions = [];
    const queryParams = [];
    let paramIndex = 1;

    // Verification filter
    if (verified !== 'all') {
      whereConditions.push(`is_verified = $${paramIndex}`);
      queryParams.push(verified === 'true');
      paramIndex++;
    }

    // Search filter
    if (search.trim()) {
      whereConditions.push(`(
        LOWER(name) LIKE LOWER($${paramIndex}) OR 
        LOWER(email) LIKE LOWER($${paramIndex}) OR 
        phone LIKE $${paramIndex}
      )`);
      queryParams.push(`%${search.trim()}%`);
      paramIndex++;
    }

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(' AND ')}` : '';

    // Build ORDER BY clause
    const validSortColumns = ['created_at', 'name', 'email', 'is_verified'];
    const validSortOrders = ['ASC', 'DESC'];
    
    const orderColumn = validSortColumns.includes(sortBy) ? sortBy : 'created_at';
    const orderDirection = validSortOrders.includes(sortOrder.toUpperCase()) ? sortOrder.toUpperCase() : 'DESC';

    // Get total count
    const countQuery = `SELECT COUNT(*) as total FROM users ${whereClause}`;
    const countResult = await pool.query(countQuery, queryParams);
    const totalUsers = parseInt(countResult.rows[0].total);

    // Get users
    const usersQuery = `
      SELECT id, name, email, phone, is_verified, created_at, updated_at 
      FROM users 
      ${whereClause}
      ORDER BY ${orderColumn} ${orderDirection}
      LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
    `;
    
    queryParams.push(parseInt(limit), offset);
    
    console.log('📊 Users query:', usersQuery);
    console.log('📊 Query params:', queryParams);

    const usersResult = await pool.query(usersQuery, queryParams);

    const totalPages = Math.ceil(totalUsers / parseInt(limit));
    const currentPage = parseInt(page);

    res.json({
      users: usersResult.rows,
      pagination: {
        currentPage,
        totalPages,
        totalUsers,
        hasNextPage: currentPage < totalPages,
        hasPrevPage: currentPage > 1
      }
    });

  } catch (err) {
    console.error('❌ Get users error:', err);
    res.status(500).json({ 
      message: 'Server error',
      error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

// Move the bulk-delete route BEFORE the single user delete route
// This ensures the more specific route is matched first

// @route   DELETE /api/admin/users/bulk-delete
// @desc    Delete multiple users
// @access  Private (Admin)
router.delete('/users/bulk-delete', adminAuth, async (req, res) => {
  try {
    const { userIds } = req.body;
    console.log('🗑️ Bulk deleting users:', userIds);

    if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
      return res.status(400).json({ message: 'User IDs array is required' });
    }

    // Validate that all IDs are numbers
    const validIds = userIds.filter(id => Number.isInteger(Number(id)));
    if (validIds.length !== userIds.length) {
      return res.status(400).json({ message: 'Invalid user IDs provided' });
    }

    // Create placeholders for the IN clause
    const placeholders = validIds.map((_, index) => `$${index + 1}`).join(', ');
    
    // Check how many users exist
    const checkQuery = `SELECT COUNT(*) as count FROM users WHERE id IN (${placeholders})`;
    const checkResult = await pool.query(checkQuery, validIds);
    const existingCount = parseInt(checkResult.rows[0].count);

    if (existingCount === 0) {
      return res.status(404).json({ message: 'No users found with provided IDs' });
    }

    // Delete users
    const deleteQuery = `DELETE FROM users WHERE id IN (${placeholders}) RETURNING id, name, email`;
    const deleteResult = await pool.query(deleteQuery, validIds);

    console.log('✅ Bulk delete completed:', {
      requested: userIds.length,
      found: existingCount,
      deleted: deleteResult.rows.length
    });

    res.json({
      message: `${deleteResult.rows.length} users deleted successfully`,
      deletedCount: deleteResult.rows.length,
      deletedUsers: deleteResult.rows
    });

  } catch (err) {
    console.error('❌ Bulk delete users error:', err);
    res.status(500).json({ 
      message: 'Server error',
      error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

// @route   DELETE /api/admin/users/:id
// @desc    Delete a single user
// @access  Private (Admin)
// THIS ROUTE MUST COME AFTER THE BULK-DELETE ROUTE
router.delete('/users/:id', adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    console.log('🗑️ Deleting user with ID:', id);

    // Validate that id is a number
    if (!Number.isInteger(Number(id))) {
      return res.status(400).json({ message: 'Invalid user ID' });
    }

    // Check if user exists
    const checkQuery = 'SELECT id, name, email FROM users WHERE id = $1';
    const checkResult = await pool.query(checkQuery, [id]);

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Delete user (this will cascade delete applications if foreign key is set up)
    const deleteQuery = 'DELETE FROM users WHERE id = $1 RETURNING id, name, email';
    const deleteResult = await pool.query(deleteQuery, [id]);

    console.log('✅ User deleted:', deleteResult.rows[0]);

    res.json({
      message: 'User deleted successfully',
      deletedUser: deleteResult.rows[0]
    });

  } catch (err) {
    console.error('❌ Delete user error:', err);
    res.status(500).json({ 
      message: 'Server error',
      error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});
// @route   PUT /api/admin/users/:id/verify
// @desc    Update user verification status
// @access  Private (Admin)
router.put('/users/:id/verify', adminAuth, [
  body('verified').isBoolean().withMessage('Verified must be a boolean value')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        message: 'Validation failed', 
        errors: errors.array() 
      });
    }

    const { id } = req.params;
    const { verified } = req.body;

    console.log('🔄 Updating verification status:', { id, verified });

    // Check if user exists
    const checkQuery = 'SELECT id, name, email, is_verified FROM users WHERE id = $1';
    const checkResult = await pool.query(checkQuery, [id]);

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Update verification status
    const updateQuery = `
      UPDATE users 
      SET is_verified = $1, updated_at = CURRENT_TIMESTAMP 
      WHERE id = $2 
      RETURNING id, name, email, is_verified, updated_at
    `;
    const updateResult = await pool.query(updateQuery, [verified, id]);

    console.log('✅ User verification updated:', updateResult.rows[0]);

    res.json({
      message: `User ${verified ? 'verified' : 'unverified'} successfully`,
      user: updateResult.rows[0]
    });

  } catch (err) {
    console.error('❌ Update verification error:', err);
    res.status(500).json({ 
      message: 'Server error',
      error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

module.exports = router;