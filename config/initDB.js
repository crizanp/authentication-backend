// config/initDB.js
const pool = require('./database');
const bcrypt = require('bcryptjs');

const createTables = async () => {
  try {
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
        phone VARCHAR(50),
        address TEXT,
        date_of_birth DATE,
        nationality VARCHAR(100),
        emergency_contact VARCHAR(255),
        emergency_phone VARCHAR(50),
        bio TEXT,
        profile_photo TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log('Users table created successfully');

    await pool.query(`
      ALTER TABLE users
      ADD COLUMN IF NOT EXISTS phone VARCHAR(50),
      ADD COLUMN IF NOT EXISTS address TEXT,
      ADD COLUMN IF NOT EXISTS date_of_birth DATE,
      ADD COLUMN IF NOT EXISTS nationality VARCHAR(100),
      ADD COLUMN IF NOT EXISTS emergency_contact VARCHAR(255),
      ADD COLUMN IF NOT EXISTS emergency_phone VARCHAR(50),
      ADD COLUMN IF NOT EXISTS bio TEXT,
      ADD COLUMN IF NOT EXISTS profile_photo TEXT,
      ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS admins (
        id SERIAL PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'admin' CHECK (role IN ('admin', 'superadmin')),
        email VARCHAR(255) UNIQUE NOT NULL,
        full_name VARCHAR(255) NOT NULL,
        is_active BOOLEAN DEFAULT TRUE,
        last_login TIMESTAMP,
        created_by INTEGER REFERENCES admins(id) ON DELETE SET NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log('Admins table created successfully');

    await pool.query(`
  CREATE TABLE IF NOT EXISTS applications (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    application_number VARCHAR(255) UNIQUE NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    phone VARCHAR(50) NOT NULL,
    whatsapp_number VARCHAR(50),
    passport_number VARCHAR(100) NOT NULL,
    address TEXT,  -- Add this line
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

    console.log('Applications table created successfully');
await pool.query(`
  ALTER TABLE applications
  ADD COLUMN IF NOT EXISTS address TEXT
`);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_applications_user_id ON applications(user_id)
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_applications_status ON applications(status)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_applications_number ON applications(application_number)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_applications_submitted_at ON applications(submitted_at)
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_admins_username ON admins(username)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_admins_email ON admins(email)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_admins_role ON admins(role)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_admins_is_active ON admins(is_active)
    `);

    await pool.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS whatsapp_number VARCHAR(50)
    `);

    const existingSuperAdmin = await pool.query(`
      SELECT id FROM admins WHERE username = 'superadmin' LIMIT 1
    `);

    if (existingSuperAdmin.rows.length === 0) {
      console.log('Creating initial superadmin...');

      const saltRounds = 12;
      const hashedPassword = await bcrypt.hash('admin123', saltRounds);

      console.log('🔍 Generated hash for admin123:', hashedPassword.substring(0, 20) + '...');

      await pool.query(`
        INSERT INTO admins (username, password, role, email, full_name) 
        VALUES ($1, $2, 'superadmin', $3, $4)
      `, ['superadmin', hashedPassword, 'superadmin@example.com', 'Super Administrator']);

      console.log('✅ Initial superadmin created with username: superadmin, password: admin123');
      console.log('⚠️  Please change the default password after first login!');

      const testMatch = await bcrypt.compare('admin123', hashedPassword);
      console.log('🔍 Hash verification test:', testMatch ? 'PASSED' : 'FAILED');
    } else {
      console.log('Superadmin already exists');

      const existingAdmin = await pool.query(`
        SELECT password FROM admins WHERE username = 'superadmin' LIMIT 1
      `);

      if (existingAdmin.rows.length > 0) {
        const existingHash = existingAdmin.rows[0].password;
        console.log('🔍 Existing hash:', existingHash.substring(0, 20) + '...');

        const testMatch = await bcrypt.compare('admin123', existingHash);
        console.log('🔍 Existing hash verification test:', testMatch ? 'PASSED' : 'FAILED');

        if (!testMatch) {
          console.log('🔄 Updating superadmin password hash...');
          const saltRounds = 12;
          const newHashedPassword = await bcrypt.hash('admin123', saltRounds);

          await pool.query(`
            UPDATE admins SET password = $1 WHERE username = 'superadmin'
          `, [newHashedPassword]);

          console.log('✅ Superadmin password hash updated');

          const newTestMatch = await bcrypt.compare('admin123', newHashedPassword);
          console.log('🔍 New hash verification test:', newTestMatch ? 'PASSED' : 'FAILED');
        }
      }
    }

    console.log('All tables created successfully');
  } catch (error) {
    console.error('Error creating tables:', error);
  }
};

module.exports = createTables;