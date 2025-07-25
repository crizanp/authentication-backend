// models/User.js

const pool = require('../config/database');

class User {
  static async create(userData) {
    const { name, email, password, emailVerificationToken, emailVerificationTokenExpires } = userData;
    
    const query = `
      INSERT INTO users (name, email, password, email_verification_token, email_verification_token_expires)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *
    `;
    
    const values = [name, email, password, emailVerificationToken, emailVerificationTokenExpires];
    const result = await pool.query(query, values);
    return result.rows[0];
  }
  
 static async updateProfile(id, profileData) {
  const allowedFields = [
    'name', 'phone', 'address', 'date_of_birth', 'nationality', 
    'emergency_contact', 'emergency_phone', 'bio', 'profile_photo'
  ];
  
  const fieldsToUpdate = {};
  
  // Map frontend field names to database column names
  const fieldMappings = {
    dateOfBirth: 'date_of_birth',
    emergencyContact: 'emergency_contact',
    emergencyPhone: 'emergency_phone',
    profilePhoto: 'profile_photo'
  };

  Object.keys(profileData).forEach(key => {
    const dbField = fieldMappings[key] || key;
    
    if (allowedFields.includes(dbField)) {
      // Handle all values including empty strings and null
      // Special handling for date fields - convert empty strings to null
      if (dbField === 'date_of_birth' && profileData[key] === '') {
        fieldsToUpdate[dbField] = null;
      } else {
        fieldsToUpdate[dbField] = profileData[key] !== undefined ? profileData[key] : null;
      }
    }
  });

  if (Object.keys(fieldsToUpdate).length === 0) {
    throw new Error('No valid fields to update');
  }

  const fields = Object.keys(fieldsToUpdate);
  const values = Object.values(fieldsToUpdate);
  const setClause = fields.map((field, index) => `${field} = $${index + 2}`).join(', ');

  const query = `
    UPDATE users 
    SET ${setClause}, updated_at = CURRENT_TIMESTAMP
    WHERE id = $1
    RETURNING *
  `;

  console.log('Update query:', query);
  console.log('Values:', [id, ...values]);

  const result = await pool.query(query, [id, ...values]);
  return result.rows[0];
}

  static async findByEmail(email) {
    const query = 'SELECT * FROM users WHERE email = $1';
    const result = await pool.query(query, [email]);
    return result.rows[0];
  }
  
  static async findById(id) {
    const query = 'SELECT * FROM users WHERE id = $1';
    const result = await pool.query(query, [id]);
    return result.rows[0];
  }
  
  static async findByVerificationToken(token) {
    const query = `
      SELECT * FROM users 
      WHERE email_verification_token = $1 
      AND email_verification_token_expires > NOW()
    `;
    const result = await pool.query(query, [token]);
    return result.rows[0];
  }
  
  static async findByResetToken(token) {
    const query = `
      SELECT * FROM users 
      WHERE reset_password_token = $1 
      AND reset_password_expires > NOW()
    `;
    const result = await pool.query(query, [token]);
    return result.rows[0];
  }
  
  static async updateById(id, updates) {
    const fields = Object.keys(updates);
    const values = Object.values(updates);
    const setClause = fields.map((field, index) => `${field} = $${index + 2}`).join(', ');
    
    const query = `
      UPDATE users 
      SET ${setClause}
      WHERE id = $1
      RETURNING *
    `;
    
    const result = await pool.query(query, [id, ...values]);
    return result.rows[0];
  }
  
  static async verifyEmail(token) {
    const query = `
      UPDATE users 
      SET is_verified = TRUE, 
          email_verification_token = NULL, 
          email_verification_token_expires = NULL
      WHERE email_verification_token = $1 
      AND email_verification_token_expires > NOW()
      RETURNING *
    `;
    
    const result = await pool.query(query, [token]);
    return result.rows[0];
  }
  
  static async updatePassword(id, hashedPassword) {
    const query = `
      UPDATE users 
      SET password = $1,
          reset_password_token = NULL,
          reset_password_expires = NULL
      WHERE id = $2
      RETURNING *
    `;
    
    const result = await pool.query(query, [hashedPassword, id]);
    return result.rows[0];
  }
}

module.exports = User;