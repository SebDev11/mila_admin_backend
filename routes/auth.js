const express = require('express');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { sendAdminNotification, generateVerificationCode } = require('../utils/emailService');
const router = express.Router();

// JWT Secret
const JWT_SECRET = process.env.SECRET_TOKEN || process.env.JWT_SECRET || 'fallback_secret_key';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';

// Generate JWT token
const generateToken = (userId) => {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
};

// @route   POST /api/auth/register
// @desc    Register a new admin user (requires admin approval)
// @access  Public
router.post('/register', [
  body('username')
    .trim()
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be between 3 and 30 characters'),
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Must be a valid email address'),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters long')
], async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { username, email, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ 
      $or: [{ email }, { username }] 
    });
    
    if (existingUser) {
      return res.status(400).json({
        message: 'User with this email or username already exists'
      });
    }

    // Generate verification code
    const verificationCode = generateVerificationCode();
    const codeExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Create new user with pending approval status
    const user = new User({
      username,
      email,
      password,
      role: 'admin',
      isVerified: false, // Requires admin approval
      verificationCode,
      codeExpires
    });

    await user.save();

    // Send notification to admin (email + console)
    const emailResult = await sendAdminNotification(
      { username, email },
      verificationCode
    );

    if (!emailResult.success) {
      console.error('Failed to send admin notification:', emailResult.error);
      // Continue with registration even if email fails
    }

    res.status(201).json({
      message: 'Registration request submitted successfully. Your account is pending admin approval. You will be able to login once approved.',
      status: 'pending_approval',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        isVerified: user.isVerified
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      message: 'Server error during registration'
    });
  }
});

// @route   POST /api/auth/login
// @desc    Login admin user
// @access  Public
router.post('/login', [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Must be a valid email address'),
  body('password')
    .notEmpty()
    .withMessage('Password is required')
], async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { email, password } = req.body;

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({
        message: 'Invalid credentials'
      });
    }

    // Check password
    const isPasswordValid = await user.matchPassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({
        message: 'Invalid credentials'
      });
    }

    // Check if user is verified
    if (!user.isVerified) {
      return res.status(403).json({
        message: 'Your account is pending admin approval. Please wait for approval before logging in.'
      });
    }

    // Check if user has admin role
    if (user.role !== 'admin') {
      return res.status(403).json({
        message: 'Access denied. Admin privileges required'
      });
    }

    // Generate token
    const token = generateToken(user._id);

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      message: 'Server error during login'
    });
  }
});

// @route   GET /api/auth/me
// @desc    Get current user profile
// @access  Private
router.get('/me', async (req, res) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ 
        message: 'No token, authorization denied!'
      });
    }

    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Get user from database
    const user = await User.findById(decoded.userId).select('-password');
    if (!user) {
      return res.status(401).json({ 
        message: 'Token is valid but user not found!'
      });
    }

    res.json({
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        isVerified: user.isVerified
      }
    });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({
      message: 'Server error while fetching profile'
    });
  }
});

// @route   POST /api/auth/verify-registration
// @desc    Verify and approve a registration using the verification code
// @access  Public (but requires verification code sent to admin)
router.post('/verify-registration', [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Must be a valid email address'),
  body('verificationCode')
    .trim()
    .isLength({ min: 6, max: 6 })
    .withMessage('Verification code must be 6 digits')
], async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { email, verificationCode } = req.body;

    // Find user by email
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(404).json({
        message: 'User not found'
      });
    }

    // Check if already verified
    if (user.isVerified) {
      return res.status(400).json({
        message: 'User is already verified'
      });
    }

    // Check if verification code matches
    if (user.verificationCode !== verificationCode) {
      return res.status(400).json({
        message: 'Invalid verification code'
      });
    }

    // Check if code has expired
    if (user.codeExpires && new Date() > user.codeExpires) {
      return res.status(400).json({
        message: 'Verification code has expired. Please request a new registration.'
      });
    }

    // Approve the user
    user.isVerified = true;
    user.verificationCode = undefined;
    user.codeExpires = undefined;
    await user.save();

    res.json({
      message: 'User registration approved successfully',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        isVerified: user.isVerified
      }
    });

  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).json({
      message: 'Server error during verification'
    });
  }
});

// @route   GET /api/auth/pending-registrations
// @desc    Get all pending registration requests (for admin review)
// @access  Private (admin only)
router.get('/pending-registrations', async (req, res) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ 
        message: 'No token, authorization denied!'
      });
    }

    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    const adminUser = await User.findById(decoded.userId);
    
    if (!adminUser || adminUser.role !== 'admin' || !adminUser.isVerified) {
      return res.status(403).json({ 
        message: 'Access denied. Admin privileges required.'
      });
    }

    // Get all pending registrations WITH verification codes
    const pendingUsers = await User.find({ 
      isVerified: false 
    }).select('-password').sort({ createdAt: -1 });

    res.json({
      count: pendingUsers.length,
      pendingUsers: pendingUsers.map(user => ({
        id: user._id,
        username: user.username,
        email: user.email,
        verificationCode: user.verificationCode,
        codeExpires: user.codeExpires,
        createdAt: user.createdAt,
        isVerified: user.isVerified
      }))
    });

  } catch (error) {
    console.error('Error fetching pending registrations:', error);
    res.status(500).json({
      message: 'Server error while fetching pending registrations'
    });
  }
});

// @route   POST /api/auth/forgot-password
// @desc    Request password reset
// @access  Public
router.post('/forgot-password', [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Must be a valid email address')
], async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { email } = req.body;

    // Find user by email
    const user = await User.findOne({ email });
    
    // Always return success message to prevent email enumeration
    // But only send email if user exists
    if (!user) {
      return res.json({
        message: 'If an account exists with this email, you will receive a password reset link.'
      });
    }

    // Generate reset token using crypto for better security
    const crypto = require('crypto');
    const resetToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');

    // Set reset token and expiry (1 hour)
    user.resetToken = hashedToken;
    user.resetTokenExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
    await user.save();

    // Send password reset email
    const { sendPasswordResetEmail } = require('../utils/emailService');
    const emailResult = await sendPasswordResetEmail(user, resetToken);

    if (!emailResult.success) {
      console.error('Failed to send password reset email:', emailResult.error);
      // Continue even if email fails - token is still generated
    }

    res.json({
      message: 'If an account exists with this email, you will receive a password reset link.'
    });

  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({
      message: 'Server error processing request'
    });
  }
});

// @route   POST /api/auth/reset-password
// @desc    Reset password using token
// @access  Public
router.post('/reset-password', [
  body('token')
    .trim()
    .notEmpty()
    .withMessage('Reset token is required'),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters long')
], async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { token, password } = req.body;

    // Hash the token to match stored version
    const crypto = require('crypto');
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    // Find user with valid reset token
    const user = await User.findOne({
      resetToken: hashedToken,
      resetTokenExpiry: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({
        message: 'Invalid or expired reset token'
      });
    }

    // Update password and clear reset token
    user.password = password;
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;
    await user.save();

    res.json({
      message: 'Password has been reset successfully. You can now login with your new password.'
    });

  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({
      message: 'Server error resetting password'
    });
  }
});

// @route   POST /api/auth/admin/generate-reset-token
// @desc    Admin generates reset token for a user (without email)
// @access  Private (admin only)
router.post('/admin/generate-reset-token', [
  body('userId')
    .notEmpty()
    .withMessage('User ID is required')
], async (req, res) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ 
        message: 'No token, authorization denied!'
      });
    }

    // Verify admin token
    const decoded = jwt.verify(token, JWT_SECRET);
    const adminUser = await User.findById(decoded.userId);
    
    if (!adminUser || adminUser.role !== 'admin' || !adminUser.isVerified) {
      return res.status(403).json({ 
        message: 'Access denied. Admin privileges required.'
      });
    }

    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { userId } = req.body;

    // Find target user
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        message: 'User not found'
      });
    }

    // Generate reset token
    const crypto = require('crypto');
    const resetToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');

    // Set reset token and expiry (24 hours for admin-generated tokens)
    user.resetToken = hashedToken;
    user.resetTokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);
    await user.save();

    // Generate reset URL
    const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
    const resetUrl = `${FRONTEND_URL}/reset-password?token=${resetToken}`;

    // Log to console
    console.log('\n' + '═'.repeat(60));
    console.log('🔑 ADMIN GENERATED PASSWORD RESET');
    console.log('═'.repeat(60));
    console.log(`👤 Admin: ${adminUser.username} (${adminUser.email})`);
    console.log(`🎯 Target User: ${user.username} (${user.email})`);
    console.log(`📅 Generated: ${new Date().toLocaleString()}`);
    console.log(`🔗 Reset URL: ${resetUrl}`);
    console.log(`🔑 Reset Token: ${resetToken}`);
    console.log(`⏰ Expires: ${new Date(Date.now() + 24 * 60 * 60 * 1000).toLocaleString()}`);
    console.log('═'.repeat(60) + '\n');

    res.json({
      message: 'Reset token generated successfully',
      resetUrl: resetUrl,
      resetToken: resetToken,
      expiresAt: user.resetTokenExpiry,
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });

  } catch (error) {
    console.error('Generate reset token error:', error);
    res.status(500).json({
      message: 'Server error generating reset token'
    });
  }
});

// @route   POST /api/auth/admin/reset-user-password
// @desc    Admin directly resets a user's password
// @access  Private (admin only)
router.post('/admin/reset-user-password', [
  body('userId')
    .notEmpty()
    .withMessage('User ID is required'),
  body('newPassword')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters long')
], async (req, res) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ 
        message: 'No token, authorization denied!'
      });
    }

    // Verify admin token
    const decoded = jwt.verify(token, JWT_SECRET);
    const adminUser = await User.findById(decoded.userId);
    
    if (!adminUser || adminUser.role !== 'admin' || !adminUser.isVerified) {
      return res.status(403).json({ 
        message: 'Access denied. Admin privileges required.'
      });
    }

    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { userId, newPassword } = req.body;

    // Find target user
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        message: 'User not found'
      });
    }

    // Update password and clear any existing reset tokens
    user.password = newPassword;
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;
    await user.save();

    // Log to console
    console.log('\n' + '═'.repeat(60));
    console.log('🔐 ADMIN PASSWORD RESET');
    console.log('═'.repeat(60));
    console.log(`👤 Admin: ${adminUser.username} (${adminUser.email})`);
    console.log(`🎯 Target User: ${user.username} (${user.email})`);
    console.log(`📅 Reset Date: ${new Date().toLocaleString()}`);
    console.log('═'.repeat(60) + '\n');

    res.json({
      message: 'Password has been reset successfully',
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });

  } catch (error) {
    console.error('Admin reset password error:', error);
    res.status(500).json({
      message: 'Server error resetting password'
    });
  }
});

module.exports = router;
