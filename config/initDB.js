// config/initDB.js
const pool = require('./database');

const createTables = async () => {
  try {
    // Create users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        is_verified BOOLEAN DEFAULT FALSE,
        email_verification_token VARCHAR(255),
        email_verification_token_expires TIMESTAMP,
        reset_password_token VARCHAR(255),
        reset_password_expires TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create applications table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS applications (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        application_number VARCHAR(255) UNIQUE NOT NULL,
        full_name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        phone VARCHAR(50) NOT NULL,
        whatsapp_number VARCHAR(50), -- Add this field
        passport_number VARCHAR(100) NOT NULL,
        documents TEXT NOT NULL,
        agreements TEXT NOT NULL,
        status VARCHAR(50) DEFAULT 'submitted',
        admin_notes TEXT DEFAULT '[]',
        user_agent TEXT,
        ip_address VARCHAR(45),
        submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create indexes for better performance
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_applications_user_id ON applications(user_id)
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_applications_status ON applications(status)
    `);
    await pool.query(`
      ALTER TABLE applications 
      ADD COLUMN IF NOT EXISTS whatsapp_number VARCHAR(50)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_applications_number ON applications(application_number)
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_applications_submitted_at ON applications(submitted_at)
    `);

    console.log('Tables created successfully');
  } catch (error) {
    console.error('Error creating tables:', error);
  }
};

module.exports = createTables;