// routes/adminApplications.js
const express = require('express');
const router = express.Router();
const { adminAuth } = require('../middleware/adminAuth');
const { pool } = require('../config/database');

// @route   GET /api/admin/applications
// @desc    Get all applications - SIMPLE VERSION
// @access  Private (Admin)
router.get('/', adminAuth, async (req, res) => {
  try {
    // Simple query - just get basic application info, no documents
    const query = `
      SELECT 
        id,
        application_number,
        full_name,
        email,
        phone,
        status,
        submitted_at
      FROM applications 
      ORDER BY submitted_at DESC
    `;
    
    const result = await pool.query(query);

    res.json({
      applications: result.rows
    });

  } catch (error) {
    console.error('Error fetching applications:', error);
    res.status(500).json({ 
      message: 'Server error',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Database error'
    });
  }
});

module.exports = router;