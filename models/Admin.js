// models/Admin.js

const pool = require('../config/database');

class Admin {
  static async create(adminData) {
    const { username, password, role = 'admin', email, full_name, created_by } = adminData;
    
    const query = `
      INSERT INTO admins (username, password, role, email, full_name, created_by)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING id, username, role, email, full_name, is_active, created_at, updated_at
    `;
    
    const values = [username, password, role, email, full_name, created_by];
    const result = await pool.query(query, values);
    return result.rows[0];
  }

  static async findByUsername(username) {
    const query = 'SELECT * FROM admins WHERE username = $1 AND is_active = true';
    const result = await pool.query(query, [username]);
    return result.rows[0];
  }

  static async findById(id) {
    const query = 'SELECT * FROM admins WHERE id = $1 AND is_active = true';
    const result = await pool.query(query, [id]);
    return result.rows[0];
  }

  static async findByEmail(email) {
    const query = 'SELECT * FROM admins WHERE email = $1 AND is_active = true';
    const result = await pool.query(query, [email]);
    return result.rows[0];
  }

  static async getAllAdmins(requestingAdminRole) {
    let query = `
      SELECT id, username, role, email, full_name, is_active, 
             last_login, created_at, updated_at, created_by
      FROM admins 
      WHERE is_active = true
    `;
    
    // Only superadmins can see all admins, regular admins can only see other regular admins
    if (requestingAdminRole !== 'superadmin') {
      query += ` AND role = 'admin'`;
    }
    
    query += ` ORDER BY created_at DESC`;
    
    const result = await pool.query(query);
    return result.rows;
  }

  static async updateById(id, updates) {
    const fields = Object.keys(updates);
    const values = Object.values(updates);
    const setClause = fields.map((field, index) => `${field} = $${index + 2}`).join(', ');
    
    const query = `
      UPDATE admins 
      SET ${setClause}, updated_at = CURRENT_TIMESTAMP
      WHERE id = $1
      RETURNING id, username, role, email, full_name, is_active, created_at, updated_at
    `;
    
    const result = await pool.query(query, [id, ...values]);
    return result.rows[0];
  }

  static async updateProfile(id, profileData) {
    const allowedFields = ['full_name', 'email'];
    const fieldsToUpdate = {};
    
    Object.keys(profileData).forEach(key => {
      if (allowedFields.includes(key) && profileData[key] !== undefined) {
        fieldsToUpdate[key] = profileData[key];
      }
    });

    if (Object.keys(fieldsToUpdate).length === 0) {
      throw new Error('No valid fields to update');
    }

    const fields = Object.keys(fieldsToUpdate);
    const values = Object.values(fieldsToUpdate);
    const setClause = fields.map((field, index) => `${field} = $${index + 2}`).join(', ');

    const query = `
      UPDATE admins 
      SET ${setClause}, updated_at = CURRENT_TIMESTAMP
      WHERE id = $1
      RETURNING id, username, role, email, full_name, is_active, created_at, updated_at
    `;

    const result = await pool.query(query, [id, ...values]);
    return result.rows[0];
  }

  static async updatePassword(id, hashedPassword) {
    const query = `
      UPDATE admins 
      SET password = $1, updated_at = CURRENT_TIMESTAMP
      WHERE id = $2
      RETURNING id, username, role, email, full_name, is_active, created_at, updated_at
    `;
    
    const result = await pool.query(query, [hashedPassword, id]);
    return result.rows[0];
  }

  static async updateLastLogin(id) {
    const query = `
      UPDATE admins 
      SET last_login = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
      WHERE id = $1
    `;
    
    await pool.query(query, [id]);
  }

  static async deactivateAdmin(id) {
    const query = `
      UPDATE admins 
      SET is_active = false, updated_at = CURRENT_TIMESTAMP
      WHERE id = $1
      RETURNING id, username, role, email, full_name, is_active, created_at, updated_at
    `;
    
    const result = await pool.query(query, [id]);
    return result.rows[0];
  }

  static async activateAdmin(id) {
    const query = `
      UPDATE admins 
      SET is_active = true, updated_at = CURRENT_TIMESTAMP
      WHERE id = $1
      RETURNING id, username, role, email, full_name, is_active, created_at, updated_at
    `;
    
    const result = await pool.query(query, [id]);
    return result.rows[0];
  }

  static async changeAdminRole(id, newRole, changedBy) {
    const query = `
      UPDATE admins 
      SET role = $1, updated_at = CURRENT_TIMESTAMP
      WHERE id = $2
      RETURNING id, username, role, email, full_name, is_active, created_at, updated_at
    `;
    
    const result = await pool.query(query, [newRole, id]);
    
    // Log the role change (you might want to create an audit log table)
    console.log(`Admin role changed: Admin ID ${id} role changed to ${newRole} by Admin ID ${changedBy}`);
    
    return result.rows[0];
  }

  static async getAdminStats() {
    const query = `
      SELECT 
        COUNT(*) as total_admins,
        COUNT(CASE WHEN role = 'admin' THEN 1 END) as regular_admins,
        COUNT(CASE WHEN role = 'superadmin' THEN 1 END) as super_admins,
        COUNT(CASE WHEN is_active = true THEN 1 END) as active_admins,
        COUNT(CASE WHEN is_active = false THEN 1 END) as inactive_admins
      FROM admins
    `;
    
    const result = await pool.query(query);
    return result.rows[0];
  }
}

module.exports = Admin;