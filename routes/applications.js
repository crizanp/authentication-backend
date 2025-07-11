// routes/applications.js

const express = require('express');
const router = express.Router();
const Application = require('../models/Applications');
const auth = require('../middleware/auth');
const nodemailer = require('nodemailer');

// Helper function to send confirmation email
// Helper function to send confirmation email - FIXED VERSION
const sendApplicationConfirmationEmail = async (email, applicationNumber, fullName) => {
  try {
    // Add validation for required parameters
    if (!email || !applicationNumber || !fullName) {
      console.error('Missing required parameters for email sending:', { email, applicationNumber, fullName });
      return;
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      console.error('Invalid email format:', email);
      return;
    }

    // Check if required environment variables are set
    if (!process.env.EMAIL_HOST || !process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
      console.error('Missing email configuration environment variables');
      console.error('EMAIL_HOST:', process.env.EMAIL_HOST ? 'Set' : 'Not set');
      console.error('EMAIL_USER:', process.env.EMAIL_USER ? 'Set' : 'Not set');
      console.error('EMAIL_PASS:', process.env.EMAIL_PASS ? 'Set' : 'Not set');
      return;
    }

    console.log('Attempting to send email to:', email);

    // Create transporter with more detailed configuration
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: process.env.EMAIL_PORT || 587, // Default to 587 for STARTTLS
      secure: process.env.EMAIL_SECURE === 'true', // true for 465, false for other ports
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      },
      // Add these options for better compatibility
      tls: {
        rejectUnauthorized: false // Only use this in development
      },
      debug: process.env.NODE_ENV === 'development', // Enable debug in development
      logger: process.env.NODE_ENV === 'development' // Enable logging in development
    });

    // Test the connection before sending
    await transporter.verify();
    console.log('SMTP connection verified successfully');

    const htmlContent = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #2563eb;">Application Submitted Successfully</h2>
        <p>Dear ${fullName},</p>
        <p>Thank you for submitting your application. We have received your application and it is now under review.</p>
        
        <div style="background-color: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0;">
          <h3 style="margin-top: 0; color: #1f2937;">Application Details:</h3>
          <p><strong>Application Number:</strong> ${applicationNumber}</p>
          <p><strong>Submitted On:</strong> ${new Date().toLocaleDateString()}</p>
          <p><strong>Status:</strong> Submitted</p>
        </div>
        
        <p>You can track your application status using the application number provided above.</p>
        <p>Our team will review your application and get back to you within 5-7 business days.</p>
        
        <p>If you have any questions, please don't hesitate to contact us.</p>
        
        <p>Best regards,<br>The Application Team</p>
      </div>
    `;

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: `Application Confirmation - ${applicationNumber}`,
      html: htmlContent
    };

    console.log('Sending email with options:', {
      from: mailOptions.from,
      to: mailOptions.to,
      subject: mailOptions.subject
    });

    const result = await transporter.sendMail(mailOptions);
    console.log(`Confirmation email sent successfully to ${email}`, result.messageId);
    
    return result;

  } catch (error) {
    console.error('Detailed error sending confirmation email:', {
      error: error.message,
      code: error.code,
      command: error.command,
      response: error.response,
      responseCode: error.responseCode
    });
    
    // Don't throw the error to prevent breaking the application submission
    // but log it for debugging
    if (process.env.NODE_ENV === 'development') {
      console.error('Full error object:', error);
    }
  }
};

// @route   POST /api/applications
// @desc    Submit new application
router.post('/', auth, async (req, res) => {
  try {
    const {
      fullName,
      email,
      phone,
      whatsappNumber,
      passportNumber,
      documents,
      termsAccepted,
      privacyAccepted,
      dataProcessingAccepted,
      userAgent
    } = req.body;

    // Validation - Personal Details
    if (!fullName || !email || !phone || !passportNumber) {
      return res.status(400).json({
        message: 'Full name, email, phone, and passport number are required'
      });
    }

    // Validation - Required Documents
    if (!documents) {
      return res.status(400).json({
        message: 'Documents are required'
      });
    }

    const requiredDocuments = [
      'passport_front',
      'labor_visa_front',
      'arrival',
      'agreement_paper',
      'passport_back',
      'departure',
      'payment_proof'
    ];

    const missingDocuments = requiredDocuments.filter(docType => !documents[docType]);

    if (missingDocuments.length > 0) {
      return res.status(400).json({
        message: `Required documents missing: ${missingDocuments.join(', ')}`
      });
    }

    // Validation - Agreements
    if (!termsAccepted || !privacyAccepted || !dataProcessingAccepted) {
      return res.status(400).json({
        message: 'All agreements must be accepted'
      });
    }

    // **NEW LOGIC: Check user's application status and enforce rules**
    const userApplications = await Application.find({ userId: req.user.id });

    // Check if user has any existing applications
    if (userApplications.length > 0) {
      // Find the most recent application
      const latestApplication = userApplications.sort((a, b) =>
        new Date(b.submittedAt) - new Date(a.submittedAt)
      )[0];

      // Rule 1: If user has an approved application, they can submit new applications
      // Rule 2: If user has a non-approved application, they cannot submit new applications
      const nonApprovedStatuses = ['submitted', 'under_review', 'pending_documents', 'rejected'];

      if (nonApprovedStatuses.includes(latestApplication.status)) {
        return res.status(400).json({
          message: 'You cannot submit a new application until your current application is approved. Please edit your existing application instead.',
          currentApplicationStatus: latestApplication.status,
          applicationNumber: latestApplication.applicationNumber,
          canEdit: true,
          canSubmitNew: false
        });
      }
    }

    // Helper function to get file type from base64
    const getFileTypeFromBase64 = (base64String) => {
      // Handle case where base64String might be an object or null
      if (!base64String || typeof base64String !== 'string') {
        return 'application/octet-stream';
      }

      if (base64String.startsWith('data:')) {
        const mimeType = base64String.split(';')[0].split(':')[1];
        return mimeType;
      }
      return 'application/octet-stream';
    };

    // Helper function to get file extension from mime type
    const getExtensionFromMimeType = (mimeType) => {
      const extensions = {
        'application/pdf': '.pdf',
        'image/jpeg': '.jpg',
        'image/jpg': '.jpg',
        'image/png': '.png'
      };
      return extensions[mimeType] || '.bin';
    };

    // Process documents
    const processedDocuments = {};
    const documentTypes = [
      'passport_front',
      'valid_visa',
      'labor_visa_front',
      'labor_visa_back',
      'arrival',
      'agreement_paper',
      'passport_back',
      'previous_visa',
      'departure',
      'further_info',
      'payment_proof'
    ];
    for (const docType of documentTypes) {
      if (documents[docType]) {
        const documentData = documents[docType];

        // Check if it's already a processed document object
        if (typeof documentData === 'object' && documentData.fileName) {
          // It's already processed, keep it as is
          processedDocuments[docType] = documentData;
        } else if (typeof documentData === 'string') {
          // It's a new base64 string, process it
          const base64Data = documentData;
          const fileType = getFileTypeFromBase64(base64Data);
          const extension = getExtensionFromMimeType(fileType);

          processedDocuments[docType] = {
            fileName: `${docType}_${req.user.id}_${Date.now()}${extension}`,
            fileType: fileType,
            fileSize: base64Data ? Buffer.byteLength(base64Data.split(',')[1] || base64Data, 'base64') : 0,
            uploadedAt: new Date(),
            base64Data: base64Data
          };
        }
      }
    }
    // Create new application data
    const applicationData = {
      userId: req.user.id,
      fullName,
      email,
      phone,
      whatsappNumber: whatsappNumber || null,
      passportNumber,
      documents: processedDocuments,
      agreements: {
        termsAccepted,
        privacyAccepted,
        dataProcessingAccepted,
        acceptedAt: new Date()
      },
      userAgent,
      ipAddress: req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for']
    };

    const application = await Application.create(applicationData);

    // Send confirmation email (async, don't wait for it)
 try {
      await sendApplicationConfirmationEmail(email, application.applicationNumber, fullName);
      console.log('Email sent successfully');
    } catch (emailError) {
      console.error('Email sending failed but application was created:', emailError);
      // Don't fail the entire request if email fails
    }

    res.status(201).json({
      success: true,
      message: 'Application submitted successfully',
      data: {
        applicationNumber: application.applicationNumber,
        submittedAt: application.submittedAt,
        status: application.status,
        id: application.id
      }
    });

  } catch (error) {
    console.error('Application submission error:', error);

    if (error.code === '23505') {
      return res.status(400).json({
        message: 'Duplicate application detected'
      });
    }

    if (error.code === '23502') {
      return res.status(400).json({
        message: 'Required field is missing',
        error: error.message
      });
    }

    res.status(500).json({
      message: 'Server error while submitting application',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// @route   PUT /api/applications/:id
// @desc    Edit existing application (only if not approved)
router.put('/:id', auth, async (req, res) => {
  try {
    const applicationId = req.params.id;
    const {
      fullName,
      email,
      phone,
      whatsappNumber,
      passportNumber,
      documents,
      termsAccepted,
      privacyAccepted,
      dataProcessingAccepted,
      userAgent
    } = req.body;

    // Validate ID
    if (!applicationId || applicationId === 'undefined') {
      return res.status(400).json({ message: 'Invalid application ID' });
    }

    // Find the application
    const application = await Application.findOne({
      id: applicationId,
      userId: req.user.id
    });

    if (!application) {
      return res.status(404).json({ message: 'Application not found' });
    }

    // **NEW LOGIC: Check if application can be edited**
    // Only allow editing if application is not approved
    if (application.status === 'approved') {
      return res.status(400).json({
        message: 'Approved applications cannot be edited. Please submit a new application instead.',
        canEdit: false,
        canSubmitNew: true
      });
    }

    // Only allow editing for certain statuses
    const editableStatuses = ['submitted', 'under_review', 'pending_documents', 'rejected'];
    if (!editableStatuses.includes(application.status)) {
      return res.status(400).json({
        message: `Application cannot be edited when status is ${application.status}`,
        canEdit: false
      });
    }

    // Validation - Personal Details
    if (!fullName || !email || !phone || !passportNumber) {
      return res.status(400).json({
        message: 'Full name, email, phone, and passport number are required'
      });
    }

    // Validation - Required Documents
    if (!documents) {
      return res.status(400).json({
        message: 'Documents are required'
      });
    }

    const requiredDocuments = [
      'passport_front',
      'labor_visa_front',
      'arrival',
      'agreement_paper',
      'passport_back',
      'departure',
      'payment_proof'
    ];

    const missingDocuments = requiredDocuments.filter(docType => !documents[docType]);

    if (missingDocuments.length > 0) {
      return res.status(400).json({
        message: `Required documents missing: ${missingDocuments.join(', ')}`
      });
    }

    // Validation - Agreements
    if (!termsAccepted || !privacyAccepted || !dataProcessingAccepted) {
      return res.status(400).json({
        message: 'All agreements must be accepted'
      });
    }

    // Helper functions (same as in POST)
    const getFileTypeFromBase64 = (base64String) => {
      // Handle case where base64String might be an object or null
      if (!base64String || typeof base64String !== 'string') {
        return 'application/octet-stream';
      }

      if (base64String.startsWith('data:')) {
        const mimeType = base64String.split(';')[0].split(':')[1];
        return mimeType;
      }
      return 'application/octet-stream';
    };

    const getExtensionFromMimeType = (mimeType) => {
      const extensions = {
        'application/pdf': '.pdf',
        'image/jpeg': '.jpg',
        'image/jpg': '.jpg',
        'image/png': '.png'
      };
      return extensions[mimeType] || '.bin';
    };

    // Process documents - FIXED VERSION
    const processedDocuments = {};
    const documentTypes = [
      'passport_front',
      'valid_visa',
      'labor_visa_front',
      'labor_visa_back',
      'arrival',
      'agreement_paper',
      'passport_back',
      'previous_visa',
      'departure',
      'further_info',
      'payment_proof'
    ];

    for (const docType of documentTypes) {
      if (documents[docType]) {
        const documentData = documents[docType];

        // Check if it's already a processed document object
        if (typeof documentData === 'object' && documentData.fileName) {
          // It's already processed, keep it as is
          processedDocuments[docType] = documentData;
        } else if (typeof documentData === 'string') {
          // It's a new base64 string, process it
          const base64Data = documentData;
          const fileType = getFileTypeFromBase64(base64Data);
          const extension = getExtensionFromMimeType(fileType);

          processedDocuments[docType] = {
            fileName: `${docType}_${req.user.id}_${Date.now()}${extension}`,
            fileType: fileType,
            fileSize: base64Data ? Buffer.byteLength(base64Data.split(',')[1] || base64Data, 'base64') : 0,
            uploadedAt: new Date(),
            base64Data: base64Data
          };
        }
      }
    }

    // Update application data
    const updateData = {
      fullName,
      email,
      phone,
      whatsappNumber: whatsappNumber || null,
      passportNumber,
      documents: processedDocuments,
      agreements: {
        termsAccepted,
        privacyAccepted,
        dataProcessingAccepted,
        acceptedAt: new Date()
      },
      userAgent,
      status: 'submitted', // Reset status to submitted when edited
      ipAddress: req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for']
    };

    const updatedApplication = await Application.updateById(applicationId, updateData);

    // Send confirmation email for updated application
    sendApplicationConfirmationEmail(email, updatedApplication.applicationNumber, fullName);

    res.json({
      success: true,
      message: 'Application updated successfully',
      data: {
        applicationNumber: updatedApplication.applicationNumber,
        submittedAt: updatedApplication.submittedAt,
        status: updatedApplication.status,
        id: updatedApplication.id
      }
    });

  } catch (error) {
    console.error('Application update error:', error);
    res.status(500).json({
      message: 'Server error while updating application',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// @route   GET /api/applications/status
// @desc    Check user's application status and permissions
router.get('/status', auth, async (req, res) => {
  try {
    const userApplications = await Application.find({ userId: req.user.id });

    if (userApplications.length === 0) {
      return res.json({
        canSubmitNew: true,
        canEdit: false,
        hasApplications: false,
        message: 'No applications found. You can submit a new application.'
      });
    }

    // Find the most recent application
    const latestApplication = userApplications.sort((a, b) =>
      new Date(b.submittedAt) - new Date(a.submittedAt)
    )[0];

    // Remove base64 data for response
    const sanitizedApp = { ...latestApplication };
    if (sanitizedApp.documents) {
      Object.keys(sanitizedApp.documents).forEach(docType => {
        if (sanitizedApp.documents[docType] && sanitizedApp.documents[docType].base64Data) {
          delete sanitizedApp.documents[docType].base64Data;
        }
      });
    }

    const isApproved = latestApplication.status === 'approved';
    const canEdit = !isApproved && ['submitted', 'under_review', 'pending_documents', 'rejected'].includes(latestApplication.status);
    const canSubmitNew = isApproved;

    res.json({
      canSubmitNew,
      canEdit,
      hasApplications: true,
      latestApplication: sanitizedApp,
      allApplications: userApplications.length,
      message: isApproved
        ? 'Your application is approved. You can submit a new application.'
        : 'You have a pending application. You can edit it but cannot submit a new one until it\'s approved.'
    });

  } catch (error) {
    console.error('Error checking application status:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   GET /api/applications
// @desc    Get all applications for authenticated user
router.get('/', auth, async (req, res) => {
  try {
    console.log('Fetching applications for user:', req.user.id);

    const applications = await Application.find({ userId: req.user.id });
    console.log('Found applications:', applications.length);

    // Remove base64 data from documents for list view
    const sanitizedApplications = applications.map(app => {
      const sanitizedApp = { ...app };
      if (sanitizedApp.documents) {
        Object.keys(sanitizedApp.documents).forEach(docType => {
          if (sanitizedApp.documents[docType] && sanitizedApp.documents[docType].base64Data) {
            delete sanitizedApp.documents[docType].base64Data;
          }
        });
      }
      return sanitizedApp;
    });

    res.json(sanitizedApplications);
  } catch (error) {
    console.error('Error fetching applications:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   GET /api/applications/:id
// @desc    Get specific application by ID (for authenticated user)
router.get('/:id', auth, async (req, res) => {
  try {
    const applicationId = req.params.id;
    console.log('Fetching application with ID:', applicationId);

    if (!applicationId || applicationId === 'undefined') {
      return res.status(400).json({ message: 'Invalid application ID' });
    }

    const application = await Application.findOne({
      id: applicationId,
      userId: req.user.id
    });

    if (!application) {
      return res.status(404).json({ message: 'Application not found' });
    }

    // For application details page, we need to include the base64 data
    const applicationData = { ...application };
    
    // Keep the documents structure as is - don't remove base64Data for details view
    // The frontend will handle displaying images and PDFs appropriately
    
    res.json(applicationData);
  } catch (error) {
    console.error('Error fetching application:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   GET /api/applications/number/:applicationNumber
// @desc    Get application by application number (for authenticated user)
router.get('/number/:applicationNumber', auth, async (req, res) => {
  try {
    const applicationNumber = req.params.applicationNumber;
    console.log('Fetching application with number:', applicationNumber);

    if (!applicationNumber || applicationNumber === 'undefined') {
      return res.status(400).json({ message: 'Invalid application number' });
    }

    const application = await Application.findOne({
      applicationNumber: applicationNumber,
      userId: req.user.id
    });

    if (!application) {
      return res.status(404).json({ message: 'Application not found' });
    }

    // Remove base64 data from documents
    const sanitizedApp = { ...application };
    if (sanitizedApp.documents) {
      Object.keys(sanitizedApp.documents).forEach(docType => {
        if (sanitizedApp.documents[docType] && sanitizedApp.documents[docType].base64Data) {
          delete sanitizedApp.documents[docType].base64Data;
        }
      });
    }

    res.json(sanitizedApp);
  } catch (error) {
    console.error('Error fetching application:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   PUT /api/applications/:id/withdraw
// @desc    Withdraw application (only if status is submitted or under_review)
router.put('/:id/withdraw', auth, async (req, res) => {
  try {
    const applicationId = req.params.id;
    console.log('Withdrawing application with ID:', applicationId);

    if (!applicationId || applicationId === 'undefined') {
      return res.status(400).json({ message: 'Invalid application ID' });
    }

    const application = await Application.findOne({
      id: applicationId,
      userId: req.user.id
    });

    if (!application) {
      return res.status(404).json({ message: 'Application not found' });
    }

    if (!['submitted', 'under_review'].includes(application.status)) {
      return res.status(400).json({
        message: 'Application cannot be withdrawn at this stage'
      });
    }

    // Update status and add admin note
    const adminNotes = application.adminNotes || [];
    adminNotes.push({
      note: 'Application withdrawn by user',
      addedBy: req.user.id,
      addedAt: new Date()
    });

    const updatedApplication = await Application.updateById(application.id, {
      status: 'withdrawn',
      adminNotes: adminNotes
    });

    res.json({
      message: 'Application withdrawn successfully',
      status: updatedApplication.status
    });
  } catch (error) {
    console.error('Error withdrawing application:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   GET /api/applications/:id/download/:documentType
// @desc    Download specific document (for authenticated user)
router.get('/:id/download/:documentType', auth, async (req, res) => {
  try {
    const { documentType } = req.params;
    const applicationId = req.params.id;

    const validDocuments = [
      'passport_front',
      'valid_visa',
      'labor_visa_front',
      'labor_visa_back',
      'arrival',
      'agreement_paper',
      'passport_back',
      'previous_visa',
      'departure',
      'further_info',
      'payment_proof'
    ];

    if (!applicationId || applicationId === 'undefined') {
      return res.status(400).json({ message: 'Invalid application ID' });
    }

    if (!validDocuments.includes(documentType)) {
      return res.status(400).json({ message: 'Invalid document type' });
    }

    const application = await Application.findOne({
      id: applicationId,
      userId: req.user.id
    });

    if (!application) {
      return res.status(404).json({ message: 'Application not found' });
    }

    const document = application.documents[documentType];
    if (!document || !document.base64Data) {
      return res.status(404).json({ message: 'Document not found' });
    }

    const base64Data = document.base64Data.split(',')[1] || document.base64Data;
    const buffer = Buffer.from(base64Data, 'base64');

    res.setHeader('Content-Type', document.fileType);
    res.setHeader('Content-Disposition', `attachment; filename="${document.fileName}"`);
    res.send(buffer);

  } catch (error) {
    console.error('Error downloading document:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;