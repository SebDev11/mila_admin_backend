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

module.exports = router;
