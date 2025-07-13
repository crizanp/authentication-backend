// routes/adminDashboard.js
const express = require('express');
const router = express.Router();
const { adminAuth } = require('../middleware/adminAuth');
const pool = require('../config/database');

// @route   GET /api/admin/dashboard/applications
// @desc    Get all applications with pagination and filtering
// @access  Private (Admin)
router.get('/applications', adminAuth, async (req, res) => {
  try {
    console.log('📡 Admin Dashboard - Applications endpoint hit');
    console.log('📋 Query params:', req.query);
    console.log('👤 Admin user:', req.admin);

    const { 
      page = 1, 
      limit = 10, 
      status, 
      search,
      sortBy = 'submitted_at',
      sortOrder = 'DESC' 
    } = req.query;

    const offset = (page - 1) * limit;
    
    let whereClause = 'WHERE 1=1';
    const queryParams = [];
    let paramIndex = 1;

    // Add status filter
    if (status && status !== 'all') {
      whereClause += ` AND a.status = $${paramIndex}`;
      queryParams.push(status);
      paramIndex++;
    }

    // Add search filter
    if (search) {
      whereClause += ` AND (
        a.full_name ILIKE $${paramIndex} OR 
        a.email ILIKE $${paramIndex} OR 
        a.application_number ILIKE $${paramIndex} OR
        a.passport_number ILIKE $${paramIndex}
      )`;
      queryParams.push(`%${search}%`);
      paramIndex++;
    }

    // Validate sort column
    const allowedSortColumns = ['submitted_at', 'full_name', 'email', 'status', 'application_number'];
    const sortColumn = allowedSortColumns.includes(sortBy) ? sortBy : 'submitted_at';
    const sortDirection = sortOrder.toUpperCase() === 'ASC' ? 'ASC' : 'DESC';

    // Get total count
    const countQuery = `
      SELECT COUNT(*) as total
      FROM applications a
      JOIN users u ON a.user_id = u.id
      ${whereClause}
    `;
    
    console.log('📊 Count query:', countQuery);
    console.log('📊 Count params:', queryParams);
    
    const countResult = await pool.query(countQuery, queryParams);
    const totalApplications = parseInt(countResult.rows[0].total);

    // Get applications
    const applicationsQuery = `
      SELECT 
        a.id,
        a.application_number,
        a.full_name,
        a.email,
        a.phone,
        a.whatsapp_number,
        a.passport_number,
        a.status,
        a.submitted_at,
        a.updated_at,
        a.admin_notes,
        a.ip_address,
        u.name as user_name,
        u.email as user_email
      FROM applications a
      JOIN users u ON a.user_id = u.id
      ${whereClause}
      ORDER BY a.${sortColumn} ${sortDirection}
      LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
    `;
    
    queryParams.push(limit, offset);
    
    console.log('📋 Applications query:', applicationsQuery);
    console.log('📋 Applications params:', queryParams);
    
    const applicationsResult = await pool.query(applicationsQuery, queryParams);

    const response = {
      applications: applicationsResult.rows,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(totalApplications / limit),
        totalApplications,
        hasNextPage: page * limit < totalApplications,
        hasPrevPage: page > 1
      }
    };

    console.log('✅ Sending response:', {
      applicationsCount: response.applications.length,
      totalApplications: response.pagination.totalApplications,
      currentPage: response.pagination.currentPage
    });

    res.json(response);
  } catch (err) {
    console.error('❌ Get applications error:', err);
    res.status(500).json({ 
      message: 'Server error',
      error: process.env.NODE_ENV === 'development' ? err.message : 'Database error'
    });
  }
});

// @route   GET /api/admin/dashboard/stats
// @desc    Get dashboard statistics
// @access  Private (Admin)
router.get('/stats', adminAuth, async (req, res) => {
  try {
    // Get application statistics
    const applicationStats = await pool.query(`
      SELECT 
        COUNT(*) as total_applications,
        COUNT(CASE WHEN status = 'submitted' THEN 1 END) as submitted_applications,
        COUNT(CASE WHEN status = 'under_review' THEN 1 END) as under_review_applications,
        COUNT(CASE WHEN status = 'approved' THEN 1 END) as approved_applications,
        COUNT(CASE WHEN status = 'rejected' THEN 1 END) as rejected_applications,
        COUNT(CASE WHEN DATE(submitted_at) = CURRENT_DATE THEN 1 END) as todays_applications,
        COUNT(CASE WHEN submitted_at >= CURRENT_DATE - INTERVAL '7 days' THEN 1 END) as weekly_applications,
        COUNT(CASE WHEN submitted_at >= CURRENT_DATE - INTERVAL '30 days' THEN 1 END) as monthly_applications
      FROM applications
    `);

    // Get user statistics
    const userStats = await pool.query(`
      SELECT 
        COUNT(*) as total_users,
        COUNT(CASE WHEN is_verified = true THEN 1 END) as verified_users,
        COUNT(CASE WHEN is_verified = false THEN 1 END) as unverified_users,
        COUNT(CASE WHEN DATE(created_at) = CURRENT_DATE THEN 1 END) as todays_registrations,
        COUNT(CASE WHEN created_at >= CURRENT_DATE - INTERVAL '7 days' THEN 1 END) as weekly_registrations,
        COUNT(CASE WHEN created_at >= CURRENT_DATE - INTERVAL '30 days' THEN 1 END) as monthly_registrations
      FROM users
    `);

    // Get recent applications
    const recentApplications = await pool.query(`
      SELECT 
        a.id,
        a.application_number,
        a.full_name,
        a.email,
        a.status,
        a.submitted_at,
        u.name as user_name
      FROM applications a
      JOIN users u ON a.user_id = u.id
      ORDER BY a.submitted_at DESC
      LIMIT 10
    `);

    res.json({
      applicationStats: applicationStats.rows[0],
      userStats: userStats.rows[0],
      recentApplications: recentApplications.rows
    });
  } catch (err) {
    console.error('Get dashboard stats error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   GET /api/admin/dashboard/application/:id
// @desc    Get single application details
// @access  Private (Admin)
router.get('/application/:id', adminAuth, async (req, res) => {
  try {
    const { id } = req.params;

    const query = `
      SELECT 
        a.*,
        u.name as user_name,
        u.email as user_email,
        u.phone as user_phone,
        u.created_at as user_created_at
      FROM applications a
      JOIN users u ON a.user_id = u.id
      WHERE a.id = $1
    `;

    const result = await pool.query(query, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Application not found' });
    }

    const application = result.rows[0];
    
    // Parse JSON fields
    application.documents = JSON.parse(application.documents);
    application.agreements = JSON.parse(application.agreements);
    application.admin_notes = JSON.parse(application.admin_notes);

    res.json(application);
  } catch (err) {
    console.error('Get application details error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   PUT /api/admin/dashboard/application/:id/status
// @desc    Update application status
// @access  Private (Admin)
router.put('/application/:id/status', adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, note } = req.body;

    const validStatuses = ['submitted', 'under_review', 'approved', 'rejected', 'processing'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ message: 'Invalid status value' });
    }

    // Get current application
    const currentApp = await pool.query('SELECT admin_notes FROM applications WHERE id = $1', [id]);
    if (currentApp.rows.length === 0) {
      return res.status(404).json({ message: 'Application not found' });
    }

    let adminNotes = JSON.parse(currentApp.rows[0].admin_notes);
    
    // Add new note if provided
    if (note) {
      adminNotes.push({
        note,
        status,
        admin_id: req.admin.id,
        admin_username: req.admin.username,
        timestamp: new Date().toISOString()
      });
    }

    // Update application
    const updateQuery = `
      UPDATE applications 
      SET status = $1, admin_notes = $2, updated_at = CURRENT_TIMESTAMP
      WHERE id = $3
      RETURNING *
    `;

    const result = await pool.query(updateQuery, [status, JSON.stringify(adminNotes), id]);

    res.json({
      message: 'Application status updated successfully',
      application: result.rows[0]
    });
  } catch (err) {
    console.error('Update application status error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   GET /api/admin/dashboard/users
// @desc    Get all users with pagination
// @access  Private (Admin)
router.get('/users', adminAuth, async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 10, 
      search,
      verified,
      sortBy = 'created_at',
      sortOrder = 'DESC' 
    } = req.query;

    const offset = (page - 1) * limit;
    
    let whereClause = 'WHERE 1=1';
    const queryParams = [];
    let paramIndex = 1;

    // Add verification filter
    if (verified !== undefined) {
      whereClause += ` AND is_verified = $${paramIndex}`;
      queryParams.push(verified === 'true');
      paramIndex++;
    }

    // Add search filter
    if (search) {
      whereClause += ` AND (
        name ILIKE $${paramIndex} OR 
        email ILIKE $${paramIndex} OR
        phone ILIKE $${paramIndex}
      )`;
      queryParams.push(`%${search}%`);
      paramIndex++;
    }

    // Validate sort column
    const allowedSortColumns = ['created_at', 'name', 'email', 'is_verified'];
    const sortColumn = allowedSortColumns.includes(sortBy) ? sortBy : 'created_at';
    const sortDirection = sortOrder.toUpperCase() === 'ASC' ? 'ASC' : 'DESC';

    // Get total count
    const countQuery = `SELECT COUNT(*) as total FROM users ${whereClause}`;
    const countResult = await pool.query(countQuery, queryParams);
    const totalUsers = parseInt(countResult.rows[0].total);

    // Get users (excluding password)
    const usersQuery = `
      SELECT 
        id, name, email, phone, is_verified, created_at, updated_at,
        address, nationality, date_of_birth
      FROM users
      ${whereClause}
      ORDER BY ${sortColumn} ${sortDirection}
      LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
    `;
    
    queryParams.push(limit, offset);
    const usersResult = await pool.query(usersQuery, queryParams);

    res.json({
      users: usersResult.rows,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(totalUsers / limit),
        totalUsers,
        hasNextPage: page * limit < totalUsers,
        hasPrevPage: page > 1
      }
    });
  } catch (err) {
    console.error('Get users error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;