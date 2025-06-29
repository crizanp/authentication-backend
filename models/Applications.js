const mongoose = require('mongoose');

const ApplicationSchema = new mongoose.Schema({
  // Reference to the user who submitted the application
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true // Single index declaration
  },
 
  // Personal Details
  fullName: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    lowercase: true,
    trim: true
  },
  phone: {
    type: String,
    required: true,
    trim: true
  },
  address: {
    type: String,
    required: true,
    trim: true
  },
  dateOfBirth: {
    type: Date,
    required: true
  },
  nationality: {
    type: String,
    required: true,
    trim: true
  },
  passportNumber: {
    type: String,
    required: true,
    trim: true
  },
  experience: {
    type: String,
    required: true,
    trim: true
  },
 
  // Document Information (storing metadata and file references)
  documents: {
    passport: {
      fileName: String,
      fileType: String,
      fileSize: Number,
      uploadedAt: { type: Date, default: Date.now },
      fileUrl: String, // If storing files separately
      base64Data: String // If storing base64 in DB (not recommended for production)
    },
    photo: {
      fileName: String,
      fileType: String,
      fileSize: Number,
      uploadedAt: { type: Date, default: Date.now },
      fileUrl: String,
      base64Data: String
    },
    certificate: {
      fileName: String,
      fileType: String,
      fileSize: Number,
      uploadedAt: { type: Date, default: Date.now },
      fileUrl: String,
      base64Data: String
    },
    experience_letter: {
      fileName: String,
      fileType: String,
      fileSize: Number,
      uploadedAt: { type: Date, default: Date.now },
      fileUrl: String,
      base64Data: String
    }
  },
 
  // Agreement Acceptance
  agreements: {
    termsAccepted: {
      type: Boolean,
      required: true,
      default: false
    },
    privacyAccepted: {
      type: Boolean,
      required: true,
      default: false
    },
    dataProcessingAccepted: {
      type: Boolean,
      required: true,
      default: false
    },
    acceptedAt: {
      type: Date,
      default: Date.now
    }
  },
 
  // Application Status
  status: {
    type: String,
    enum: ['submitted', 'under_review', 'approved', 'rejected', 'pending_documents', 'withdrawn'],
    default: 'submitted',
    index: true // Single index declaration
  },
 
  // Application Reference Number
  applicationNumber: {
    type: String,
    unique: true // This creates an index automatically
  },
 
  // Admin Notes
  adminNotes: [{
    note: String,
    addedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    addedAt: {
      type: Date,
      default: Date.now
    }
  }],
 
  // Metadata
  submittedAt: {
    type: Date,
    default: Date.now,
    index: -1 // Single index declaration (descending order)
  },
  lastUpdated: {
    type: Date,
    default: Date.now
  },
  userAgent: String,
  ipAddress: String
});

// Generate application number before saving
ApplicationSchema.pre('save', async function(next) {
  if (this.isNew && !this.applicationNumber) {
    const count = await mongoose.model('Application').countDocuments();
    this.applicationNumber = `APP-${new Date().getFullYear()}-${String(count + 1).padStart(6, '0')}`;
  }
  this.lastUpdated = new Date();
  next();
});

// Compound indexes for better query performance
ApplicationSchema.index({ userId: 1, status: 1 });
ApplicationSchema.index({ userId: 1, submittedAt: -1 });

module.exports = mongoose.model('Application', ApplicationSchema);