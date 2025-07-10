// models/Application.js
const pool = require('../config/database');

class Application {
  static async create(applicationData) {
    const {
      userId,
      fullName,
      email,
      phone,
      whatsappNumber,
      passportNumber,
      documents,
      agreements,
      userAgent,
      ipAddress
    } = applicationData;

    // Generate application number
    const applicationNumber = `APP-${Date.now()}-${Math.random().toString(36).substr(2, 9).toUpperCase()}`;

    const query = `
      INSERT INTO applications (
        user_id, application_number, full_name, email, phone, whatsapp_number,
        address, date_of_birth, nationality, passport_number, experience,
        documents, agreements, user_agent, ip_address
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
      RETURNING *
    `;

    const values = [
      userId,
      applicationNumber,
      fullName,
      email,
      phone,
      whatsappNumber,
      JSON.stringify({}),  // Empty object for address
      null,                // null for date_of_birth
      null,                // null for nationality
      passportNumber,
      null,                // null for experience
      JSON.stringify(documents),
      JSON.stringify(agreements),
      userAgent,
      ipAddress
    ];

    const result = await pool.query(query, values);
    const application = result.rows[0];

    // Parse JSON fields back to objects and normalize field names
    const normalizedApplication = {
      id: application.id,
      _id: application.id,
      userId: application.user_id,
      applicationNumber: application.application_number,
      fullName: application.full_name,
      email: application.email,
      phone: application.phone,
      whatsappNumber: application.whatsapp_number,
      passportNumber: application.passport_number,
      documents: JSON.parse(application.documents),
      agreements: JSON.parse(application.agreements),
      status: application.status,
      adminNotes: JSON.parse(application.admin_notes || '[]'),
      userAgent: application.user_agent,
      ipAddress: application.ip_address,
      submittedAt: application.submitted_at,
      updatedAt: application.updated_at,
      createdAt: application.created_at
    };
    return normalizedApplication;
  }

  static async findOne(conditions) {
    let query = 'SELECT * FROM applications WHERE ';
    const values = [];
    const conditionParts = [];
    let valueIndex = 1;

    for (const [key, value] of Object.entries(conditions)) {
      if (key === 'userId') {
        conditionParts.push(`user_id = $${valueIndex}`);
        values.push(value);
        valueIndex++;
      } else if (key === 'status') {
        if (value.$in) {
          const placeholders = value.$in.map(() => `$${valueIndex++}`).join(', ');
          conditionParts.push(`status IN (${placeholders})`);
          values.push(...value.$in);
        } else {
          conditionParts.push(`status = $${valueIndex}`);
          values.push(value);
          valueIndex++;
        }
      } else if (key === '_id' || key === 'id') {
        conditionParts.push(`id = $${valueIndex}`);
        values.push(value);
        valueIndex++;
      } else if (key === 'applicationNumber') {
        conditionParts.push(`application_number = $${valueIndex}`);
        values.push(value);
        valueIndex++;
      } else if (key === 'application_number') {
        conditionParts.push(`application_number = $${valueIndex}`);
        values.push(value);
        valueIndex++;
      }
    }

    if (conditionParts.length === 0) {
      throw new Error('No valid conditions provided');
    }

    query += conditionParts.join(' AND ');

    const result = await pool.query(query, values);
    if (result.rows.length === 0) return null;

    const application = result.rows[0];
    
    // Normalize field names for frontend compatibility
    return {
      id: application.id,
      _id: application.id,
      userId: application.user_id,
      applicationNumber: application.application_number,
      fullName: application.full_name,
      email: application.email,
      phone: application.phone,
      whatsappNumber: application.whatsapp_number,
      address: application.address ? JSON.parse(application.address) : null,
      dateOfBirth: application.date_of_birth,
      nationality: application.nationality,
      passportNumber: application.passport_number,
      experience: application.experience,
      documents: JSON.parse(application.documents),
      agreements: JSON.parse(application.agreements),
      status: application.status,
      adminNotes: JSON.parse(application.admin_notes || '[]'),
      userAgent: application.user_agent,
      ipAddress: application.ip_address,
      submittedAt: application.submitted_at,
      updatedAt: application.updated_at,
      createdAt: application.created_at
    };
  }

  static async find(conditions = {}) {
    let query = 'SELECT * FROM applications';
    const values = [];
    let valueIndex = 1;

    if (Object.keys(conditions).length > 0) {
      query += ' WHERE ';
      const conditionParts = [];

      for (const [key, value] of Object.entries(conditions)) {
        if (key === 'userId') {
          conditionParts.push(`user_id = $${valueIndex}`);
          values.push(value);
          valueIndex++;
        }
      }

      query += conditionParts.join(' AND ');
    }

    query += ' ORDER BY submitted_at DESC';

    const result = await pool.query(query, values);

    return result.rows.map(application => ({
      id: application.id,
      _id: application.id,
      userId: application.user_id,
      applicationNumber: application.application_number,
      fullName: application.full_name,
      email: application.email,
      phone: application.phone,
      whatsappNumber: application.whatsapp_number,
      address: application.address ? JSON.parse(application.address) : null,
      dateOfBirth: application.date_of_birth,
      nationality: application.nationality,
      passportNumber: application.passport_number,
      experience: application.experience,
      documents: JSON.parse(application.documents),
      agreements: JSON.parse(application.agreements),
      status: application.status,
      adminNotes: JSON.parse(application.admin_notes || '[]'),
      userAgent: application.user_agent,
      ipAddress: application.ip_address,
      submittedAt: application.submitted_at,
      updatedAt: application.updated_at,
      createdAt: application.created_at
    }));
  }

  static async findById(id) {
    if (!id || id === 'undefined') {
      throw new Error('Invalid ID provided');
    }

    const query = 'SELECT * FROM applications WHERE id = $1';
    const result = await pool.query(query, [id]);

    if (result.rows.length === 0) return null;

    const application = result.rows[0];
    
    return {
      id: application.id,
      _id: application.id,
      userId: application.user_id,
      applicationNumber: application.application_number,
      fullName: application.full_name,
      email: application.email,
      phone: application.phone,
      whatsappNumber: application.whatsapp_number,
      address: application.address ? JSON.parse(application.address) : null,
      dateOfBirth: application.date_of_birth,
      nationality: application.nationality,
      passportNumber: application.passport_number,
      experience: application.experience,
      documents: JSON.parse(application.documents),
      agreements: JSON.parse(application.agreements),
      status: application.status,
      adminNotes: JSON.parse(application.admin_notes || '[]'),
      userAgent: application.user_agent,
      ipAddress: application.ip_address,
      submittedAt: application.submitted_at,
      updatedAt: application.updated_at,
      createdAt: application.created_at
    };
  }

  static async findByApplicationNumber(applicationNumber) {
    if (!applicationNumber || applicationNumber === 'undefined') {
      throw new Error('Invalid application number provided');
    }

    const query = 'SELECT * FROM applications WHERE application_number = $1';
    const result = await pool.query(query, [applicationNumber]);

    if (result.rows.length === 0) return null;

    const application = result.rows[0];
    
    return {
      id: application.id,
      _id: application.id,
      userId: application.user_id,
      applicationNumber: application.application_number,
      fullName: application.full_name,
      email: application.email,
      phone: application.phone,
      whatsappNumber: application.whatsapp_number,
      address: application.address ? JSON.parse(application.address) : null,
      dateOfBirth: application.date_of_birth,
      nationality: application.nationality,
      passportNumber: application.passport_number,
      experience: application.experience,
      documents: JSON.parse(application.documents),
      agreements: JSON.parse(application.agreements),
      status: application.status,
      adminNotes: JSON.parse(application.admin_notes || '[]'),
      userAgent: application.user_agent,
      ipAddress: application.ip_address,
      submittedAt: application.submitted_at,
      updatedAt: application.updated_at,
      createdAt: application.created_at
    };
  }

  static async updateById(id, updates) {
    if (!id || id === 'undefined') {
      throw new Error('Invalid ID provided');
    }

    const fields = Object.keys(updates);
    const values = Object.values(updates);

    // Convert objects to JSON strings for storage
    const processedValues = values.map(value => {
      if (typeof value === 'object' && value !== null) {
        return JSON.stringify(value);
      }
      return value;
    });

    const setClause = fields.map((field, index) => {
      // Map field names to database column names
      const fieldMap = {
        'adminNotes': 'admin_notes',
        'userId': 'user_id',
        'applicationNumber': 'application_number',
        'fullName': 'full_name',
        'whatsappNumber': 'whatsapp_number',
        'dateOfBirth': 'date_of_birth',
        'passportNumber': 'passport_number',
        'userAgent': 'user_agent',
        'ipAddress': 'ip_address',
        'submittedAt': 'submitted_at',
        'updatedAt': 'updated_at'
      };

      const dbField = fieldMap[field] || field;
      return `${dbField} = $${index + 2}`;
    }).join(', ');

    const query = `
      UPDATE applications 
      SET ${setClause}, updated_at = NOW()
      WHERE id = $1
      RETURNING *
    `;

    const result = await pool.query(query, [id, ...processedValues]);

    if (result.rows.length === 0) return null;

    const application = result.rows[0];
    
    return {
      id: application.id,
      _id: application.id,
      userId: application.user_id,
      applicationNumber: application.application_number,
      fullName: application.full_name,
      email: application.email,
      phone: application.phone,
      whatsappNumber: application.whatsapp_number,
      address: application.address ? JSON.parse(application.address) : null,
      dateOfBirth: application.date_of_birth,
      nationality: application.nationality,
      passportNumber: application.passport_number,
      experience: application.experience,
      documents: JSON.parse(application.documents),
      agreements: JSON.parse(application.agreements),
      status: application.status,
      adminNotes: JSON.parse(application.admin_notes || '[]'),
      userAgent: application.user_agent,
      ipAddress: application.ip_address,
      submittedAt: application.submitted_at,
      updatedAt: application.updated_at,
      createdAt: application.created_at
    };
  }

  static async save(applicationData) {
    const {
      id,
      status,
      admin_notes,
      ...otherFields
    } = applicationData;

    const updates = {
      status,
      adminNotes: admin_notes
    };

    return await this.updateById(id, updates);
  }
}

module.exports = Application;