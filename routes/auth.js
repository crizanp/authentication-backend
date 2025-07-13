// routes/auth.js

const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const User = require('../models/User');
const auth = require('../middleware/auth');
const { generateToken, generateResetToken } = require('../utils/tokens');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');

// Create a more robust transporter with better error handling
const createTransporter = () => {
  const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT || 587, // Add port
    secure: false, // true for 465, false for other ports
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    },
    tls: {
      rejectUnauthorized: false // For development/testing
    }
  });

  // Verify transporter configuration
  transporter.verify((error, success) => {
    if (error) {
      console.error('Email transporter verification failed:', error);
    } else {
      console.log('Email transporter is ready to send messages');
    }
  });

  return transporter;
};

// Improved email sending function with better error handling
const sendVerificationEmail = async (email, verificationToken) => {
  try {
    const transporter = createTransporter();
    
    const verificationUrl = `https://portal.nepalishram.com/verify-email?token=${verificationToken}`;

    const mailOptions = {
      from: `"Nepali Shram" <${process.env.EMAIL_USER}>`, // Better sender format
      to: email,
      subject: 'Verify Your Email - Action Required',
      html: `
        <div style="max-width: 600px; margin: 0 auto; padding: 20px; font-family: Arial, sans-serif;">
          <h2 style="color: #003479; text-align: center;">Verify Your Email Address</h2>
          <p>Hello,</p>
          <p>Thank you for signing up! Please verify your email address by clicking the button below:</p>
          
          <div style="text-align: center; margin: 30px 0;">
            <a href="${verificationUrl}" 
               style="background-color: #003479; color: white; padding: 12px 30px; 
                      text-decoration: none; border-radius: 5px; display: inline-block;">
              Verify Email Address
            </a>
          </div>
          
          <p>Or copy and paste this link into your browser:</p>
          <p style="word-break: break-all; color: #666;">${verificationUrl}</p>
          
          <p style="color: #666; font-size: 14px;">
            This link will expire in 1 hour. If you didn't create an account, you can safely ignore this email.
          </p>
        </div>
      `
    };

    console.log('Attempting to send verification email to:', email);
    const info = await transporter.sendMail(mailOptions);
    console.log('Verification email sent successfully:', info.messageId);
    return info;
  } catch (error) {
    console.error('Error sending verification email:', error);
    throw new Error('Failed to send verification email: ' + error.message);
  }
};

// Improved password reset email function
const sendPasswordResetEmail = async (email, resetToken) => {
  try {
    const transporter = createTransporter();
    
    const resetUrl = `https://portal.nepalishram.com/reset-password?token=${resetToken}`;

    const mailOptions = {
      from: `"Nepali Shram" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Password Reset Request - Action Required',
      html: `
        <div style="max-width: 600px; margin: 0 auto; padding: 20px; font-family: Arial, sans-serif;">
          <h2 style="color: #003479; text-align: center;">Reset Your Password</h2>
          <p>Hello,</p>
          <p>We received a request to reset your password. Click the button below to create a new password:</p>
          
          <div style="text-align: center; margin: 30px 0;">
            <a href="${resetUrl}" 
               style="background-color: #dc3545; color: white; padding: 12px 30px; 
                      text-decoration: none; border-radius: 5px; display: inline-block;">
              Reset Password
            </a>
          </div>
          
          <p>Or copy and paste this link into your browser:</p>
          <p style="word-break: break-all; color: #666;">${resetUrl}</p>
          
          <p style="color: #666; font-size: 14px;">
            This link will expire in 1 hour. If you didn't request this reset, you can safely ignore this email.
          </p>
        </div>
      `
    };

    console.log('Attempting to send password reset email to:', email);
    const info = await transporter.sendMail(mailOptions);
    console.log('Password reset email sent successfully:', info.messageId);
    return info;
  } catch (error) {
    console.error('Error sending password reset email:', error);
    throw new Error('Failed to send password reset email: ' + error.message);
  }
};

// @route   POST /api/auth/resend-verification-email
router.post('/resend-verification-email', async (req, res) => {
  const { email } = req.body;

  try {
    console.log('Resend verification request for:', email);
    
    const user = await User.findByEmail(email);
    
    if (!user) {
      return res.status(404).json({ message: 'No user found with this email' });
    }

    // If user is already verified
    if (user.is_verified) {
      return res.status(400).json({ message: 'Email is already verified' });
    }

    // Generate new verification token
    const emailVerificationToken = crypto.randomBytes(32).toString('hex');
    const emailVerificationTokenExpires = new Date(Date.now() + 3600000); // 1 hour

    await User.updateById(user.id, {
      email_verification_token: emailVerificationToken,
      email_verification_token_expires: emailVerificationTokenExpires
    });

    // Send new verification email
    await sendVerificationEmail(email, emailVerificationToken);

    res.json({ 
      message: 'Verification email resent successfully. Please check your inbox.',
      email: user.email 
    });
  } catch (err) {
    console.error('Resend verification error:', err);
    res.status(500).json({ message: err.message || 'Failed to resend verification email' });
  }
});

// @route   POST /api/auth/signup
router.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    console.log('Signup request for:', email);
    
    // Check if user already exists
    const existingUser = await User.findByEmail(email);
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Generate verification token
    const emailVerificationToken = crypto.randomBytes(32).toString('hex');
    const emailVerificationTokenExpires = new Date(Date.now() + 3600000); // 1 hour

    // Create new user
    const user = await User.create({
      name,
      email,
      password: hashedPassword,
      emailVerificationToken,
      emailVerificationTokenExpires
    });

    console.log('User created successfully:', user.id);

    // Send verification email
    await sendVerificationEmail(email, emailVerificationToken);

    res.status(201).json({ 
      message: 'Account created successfully! Please check your email to verify your account.',
      email: user.email 
    });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ message: err.message || 'Failed to create account' });
  }
});

// @route   GET /api/auth/verify-email
router.get('/verify-email', async (req, res) => {
  const { token } = req.query;

  try {
    console.log('Email verification attempt with token:', token);
    
    const user = await User.verifyEmail(token);

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired verification token' });
    }

    console.log('Email verified successfully for user:', user.id);
    res.json({ message: 'Email verified successfully! You can now sign in.' });
  } catch (err) {
    console.error('Email verification error:', err);
    res.status(500).json({ message: 'Server error during email verification' });
  }
});

// @route   POST /api/auth/login
router.post('/login', async (req, res) => {
  const { email, password, rememberMe } = req.body;

  try {
    // Check if user exists
    const user = await User.findByEmail(email);
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Check email verification
    if (!user.is_verified) {
      return res.status(403).json({ 
        message: 'Please verify your email before logging in',
        email: user.email 
      });
    }  

    // Generate JWT token with optional longer expiration
    const tokenOptions = rememberMe 
      ? { expiresIn: '7d' }  // 7 days for "Remember Me"
      : { expiresIn: '1h' }; // 1 hour for regular login

    const token = jwt.sign(
      { user: { id: user.id } },
      process.env.JWT_SECRET, 
      tokenOptions
    );

    res.json({ token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// @route   GET /api/auth/me
router.get('/me', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Remove password from response
    const { password, ...userWithoutPassword } = user;
    res.json(userWithoutPassword);
  } catch (err) {
    console.error('Get user error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   PUT /api/auth/update-profile
router.put('/update-profile', auth, async (req, res) => {
  try {
    console.log('Request body:', req.body);
    
    const {
      name,
      phone,
      address,
      dateOfBirth,
      nationality,
      emergencyContact,
      emergencyPhone,
      bio,
      profilePhoto
    } = req.body;

    // Validate required fields
    if (!name || !name.trim()) {
      return res.status(400).json({ message: 'Name is required' });
    }

    // Prepare update data - handle empty strings and null values properly
    const updateData = {
      name: name.trim(),
      phone: phone && phone.trim() ? phone.trim() : null,
      address: address && address.trim() ? address.trim() : null,
      dateOfBirth: dateOfBirth || null,
      nationality: nationality && nationality.trim() ? nationality.trim() : null,
      emergencyContact: emergencyContact && emergencyContact.trim() ? emergencyContact.trim() : null,
      emergencyPhone: emergencyPhone && emergencyPhone.trim() ? emergencyPhone.trim() : null,
      bio: bio && bio.trim() ? bio.trim() : null,
      profilePhoto: profilePhoto || null
    };

    console.log('Update data:', updateData);

    // Update user profile
    const updatedUser = await User.updateProfile(req.user.id, updateData);
    
    if (!updatedUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    console.log('Updated user from DB:', updatedUser);

    // Remove password and sensitive data from response
    const { 
      password, 
      email_verification_token, 
      email_verification_token_expires, 
      reset_password_token, 
      reset_password_expires, 
      ...userWithoutSensitiveData 
    } = updatedUser;

    // Map database fields back to frontend field names
    const responseUser = {
      ...userWithoutSensitiveData,
      dateOfBirth: updatedUser.date_of_birth,
      emergencyContact: updatedUser.emergency_contact,
      emergencyPhone: updatedUser.emergency_phone,
      profilePhoto: updatedUser.profile_photo
    };

    console.log('Response user:', responseUser);

    res.json({
      message: 'Profile updated successfully',
      user: responseUser
    });
  } catch (err) {
    console.error('Profile update error:', err);
    res.status(500).json({ message: err.message || 'Server error' });
  }
});

// @route   PUT /api/auth/change-password
router.put('/change-password', auth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  try {
    // Validate input
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: 'Current password and new password are required' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ message: 'New password must be at least 6 characters long' });
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check current password
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Current password is incorrect' });
    }

    // Hash new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    await User.updatePassword(user.id, hashedPassword);

    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    console.error('Password change error:', err.message);
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   POST /api/auth/forgot-password
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;

  try {
    console.log('Password reset request for:', email);
    
    const user = await User.findByEmail(email);
    if (!user) {
      return res.status(404).json({ message: 'No user found with this email' });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpires = new Date(Date.now() + 3600000); // 1 hour from now

    await User.updateById(user.id, {
      reset_password_token: resetToken,
      reset_password_expires: resetTokenExpires
    });

    // Send reset email
    await sendPasswordResetEmail(email, resetToken);

    res.json({ message: 'Password reset link sent to your email' });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ message: err.message || 'Failed to send password reset email' });
  }
});

// @route   POST /api/auth/reset-password
router.post('/reset-password', async (req, res) => {
  const { token, password } = req.body;

  try {
    const user = await User.findByResetToken(token);

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired reset token' });
    }

    // Hash new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Update password and clear reset token
    await User.updatePassword(user.id, hashedPassword);

    res.json({ message: 'Password reset successful' });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   GET /api/auth/validate-reset-token
router.get('/validate-reset-token', async (req, res) => {
  const { token } = req.query;

  try {
    const user = await User.findByResetToken(token);

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired reset token' });
    }

    res.json({ message: 'Token is valid' });
  } catch (err) {
    console.error('Token validation error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;