const express = require('express');
const router = express.Router();
const Application = require('../models/Applications');
const auth = require('../middleware/auth');
const nodemailer = require('nodemailer');

// Helper function to send confirmation email
const sendApplicationConfirmationEmail = async (email, applicationNumber, fullName) => {
  try {
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

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

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: `Application Confirmation - ${applicationNumber}`,
      html: htmlContent
    });

    console.log(`Confirmation email sent to ${email}`);
  } catch (error) {
    console.error('Error sending confirmation email:', error);
    // Don't throw error here - application should still be saved even if email fails
  }
};

// Updated POST route in your applications.js file
router.post('/', auth, async (req, res) => {
  try {
    const {
      fullName,
      email,
      phone,
      address,
      dateOfBirth,
      nationality,
      passportNumber,
      experience,
      documents,
      termsAccepted,
      privacyAccepted,
      dataProcessingAccepted,
      userAgent
    } = req.body;

    // Validation
    if (!fullName || !email || !phone || !address || !dateOfBirth || 
        !nationality || !passportNumber || !experience) {
      return res.status(400).json({ 
        message: 'All personal details are required' 
      });
    }

    if (!documents || !documents.passport || !documents.photo || 
        !documents.certificate || !documents.experience_letter) {
      return res.status(400).json({ 
        message: 'All required documents must be uploaded' 
      });
    }

    if (!termsAccepted || !privacyAccepted || !dataProcessingAccepted) {
      return res.status(400).json({ 
        message: 'All agreements must be accepted' 
      });
    }

    // Check if user already has a pending/submitted application
    const existingApplication = await Application.findOne({ 
      userId: req.user.id,
      status: { $in: ['submitted', 'under_review', 'pending_documents'] }
    });

    if (existingApplication) {
      return res.status(400).json({ 
        message: 'You already have a pending application. Please wait for it to be processed.',
        applicationNumber: existingApplication.applicationNumber
      });
    }

    // Helper function to get file type from base64
    const getFileTypeFromBase64 = (base64String) => {
      if (base64String.startsWith('data:')) {
        const mimeType = base64String.split(';')[0].split(':')[1];
        return mimeType;
      }
      return 'application/octet-stream'; // fallback
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

    // Process documents - improved handling
    const processedDocuments = {};
    const documentTypes = ['passport', 'photo', 'certificate', 'experience_letter'];

    for (const docType of documentTypes) {
      if (documents[docType]) {
        const base64Data = documents[docType];
        const fileType = getFileTypeFromBase64(base64Data);
        const extension = getExtensionFromMimeType(fileType);
        
        processedDocuments[docType] = {
          fileName: `${docType}_${req.user.id}_${Date.now()}${extension}`,
          fileType: fileType,
          fileSize: base64Data ? Buffer.byteLength(base64Data.split(',')[1] || base64Data, 'base64') : 0,
          uploadedAt: new Date(),
          base64Data: base64Data // In production, upload to cloud storage and store URL instead
        };
      }
    }

    // Create new application
    const application = new Application({
      userId: req.user.id,
      fullName,
      email,
      phone,
      address,
      dateOfBirth: new Date(dateOfBirth),
      nationality,
      passportNumber,
      experience,
      documents: processedDocuments,
      agreements: {
        termsAccepted,
        privacyAccepted,
        dataProcessingAccepted,
        acceptedAt: new Date()
      },
      userAgent,
      ipAddress: req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for']
    });

    await application.save();

    // Send confirmation email (async, don't wait for it)
    sendApplicationConfirmationEmail(email, application.applicationNumber, fullName);

    res.status(201).json({
      success: true,
      message: 'Application submitted successfully',
      data: {
        applicationNumber: application.applicationNumber,
        submittedAt: application.submittedAt,
        status: application.status,
        id: application._id
      }
    });

  } catch (error) {
    console.error('Application submission error:', error);
    
    // Handle specific MongoDB errors
    if (error.name === 'ValidationError') {
      const errorMessages = Object.values(error.errors).map(err => err.message);
      return res.status(400).json({ 
        message: 'Validation failed',
        errors: errorMessages
      });
    }

    if (error.code === 11000) {
      return res.status(400).json({ 
        message: 'Duplicate application detected'
      });
    }

    res.status(500).json({ 
      message: 'Server error while submitting application',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});
// @route   GET /api/applications
// @desc    Get all applications for authenticated user
router.get('/', auth, async (req, res) => {
  try {
    const applications = await Application.find({ userId: req.user.id })
      .select('-documents.passport.base64Data -documents.photo.base64Data -documents.certificate.base64Data -documents.experience_letter.base64Data')
      .sort({ submittedAt: -1 });

    res.json(applications);
  } catch (error) {
    console.error('Error fetching applications:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   GET /api/applications/:id
// @desc    Get specific application by ID (for authenticated user)
router.get('/:id', auth, async (req, res) => {
  try {
    const application = await Application.findOne({ 
      _id: req.params.id, 
      userId: req.user.id 
    }).select('-documents.passport.base64Data -documents.photo.base64Data -documents.certificate.base64Data -documents.experience_letter.base64Data');

    if (!application) {
      return res.status(404).json({ message: 'Application not found' });
    }

    res.json(application);
  } catch (error) {
    console.error('Error fetching application:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   GET /api/applications/number/:applicationNumber
// @desc    Get application by application number (for authenticated user)
router.get('/number/:applicationNumber', auth, async (req, res) => {
  try {
    const application = await Application.findOne({ 
      applicationNumber: req.params.applicationNumber,
      userId: req.user.id 
    }).select('-documents.passport.base64Data -documents.photo.base64Data -documents.certificate.base64Data -documents.experience_letter.base64Data');

    if (!application) {
      return res.status(404).json({ message: 'Application not found' });
    }

    res.json(application);
  } catch (error) {
    console.error('Error fetching application:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   PUT /api/applications/:id/withdraw
// @desc    Withdraw application (only if status is submitted or under_review)
router.put('/:id/withdraw', auth, async (req, res) => {
  try {
    const application = await Application.findOne({ 
      _id: req.params.id, 
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

    application.status = 'withdrawn';
    application.adminNotes.push({
      note: 'Application withdrawn by user',
      addedBy: req.user.id,
      addedAt: new Date()
    });

    await application.save();

    res.json({ 
      message: 'Application withdrawn successfully',
      status: application.status
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
    const validDocuments = ['passport', 'photo', 'certificate', 'experience_letter'];
    
    if (!validDocuments.includes(documentType)) {
      return res.status(400).json({ message: 'Invalid document type' });
    }

    const application = await Application.findOne({ 
      _id: req.params.id, 
      userId: req.user.id 
    });

    if (!application) {
      return res.status(404).json({ message: 'Application not found' });
    }

    const document = application.documents[documentType];
    if (!document || !document.base64Data) {
      return res.status(404).json({ message: 'Document not found' });
    }

    // Extract the base64 data (remove data:type;base64, prefix if present)
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