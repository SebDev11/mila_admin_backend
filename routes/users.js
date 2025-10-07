const express = require('express');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const mongoose = require('mongoose');
const axios = require('axios');
const router = express.Router();

// Main backend URL for user restrictions
const MAIN_BACKEND_URL = process.env.MAIN_BACKEND_URL || 'http://localhost:8070';

// Validation middleware
const validateUser = [
  body('username').trim().isLength({ min: 3 }).withMessage('Username must be at least 3 characters'),
  body('email').isEmail().normalizeEmail().withMessage('Must be a valid email'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  body('role').isIn(['admin', 'regular']).withMessage('Role must be admin or regular'),
  body('plan').isIn(['Free', 'Pro']).withMessage('Plan must be Free or Pro')
];

// Get all users
router.get('/', async (req, res) => {
  try {
    const { email, role, plan, isVerified } = req.query;
    let filter = {};

    if (email) filter.email = { $regex: email, $options: 'i' };
    if (role) filter.role = role;
    if (plan) filter.plan = plan;
    if (isVerified !== undefined) filter.isVerified = isVerified === 'true';

    const users = await User.find(filter).select('-password').sort({ createdAt: -1 });
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching users', message: error.message });
  }
});

// Get user by ID (with ObjectId validation)
router.get('/:id', async (req, res) => {
  if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }
  try {
    const user = await User.findById(req.params.id).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching user', message: error.message });
  }
});

// Create new user
router.post('/', validateUser, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password, role, plan } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ error: 'User with this email or username already exists' });
    }

    const user = new User({
      username,
      email,
      password,
      role,
      plan
    });

    await user.save();
    res.status(201).json(user);
  } catch (error) {
    res.status(500).json({ error: 'Error creating user', message: error.message });
  }
});

// Update user
router.patch('/:id', async (req, res) => {
  try {
    const { role, plan, isVerified, username, email } = req.body;
    const updateData = {};

    if (role !== undefined) updateData.role = role;
    if (plan !== undefined) updateData.plan = plan;
    if (isVerified !== undefined) updateData.isVerified = isVerified;
    if (username !== undefined) updateData.username = username;
    if (email !== undefined) updateData.email = email;

    const user = await User.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true, runValidators: true }
    ).select('-password');

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Error updating user', message: error.message });
  }
});

// Restrict user
router.patch('/:id/restrict', async (req, res) => {
  try {
    // Update in admin database
    const adminUser = await User.findByIdAndUpdate(
      req.params.id,
      { role: 'restricted' },
      { new: true, runValidators: true }
    ).select('-password');

    if (!adminUser) {
      return res.status(404).json({ error: 'User not found in admin database' });
    }

    // Also update in main backend database (where restriction alerts are handled)
    try {
      const mainBackendResponse = await axios.patch(
        `${MAIN_BACKEND_URL}/api/users/${req.params.id}`,
        { role: 'restricted' },
        {
          headers: {
            'Content-Type': 'application/json',
          }
        }
      );

      console.log(`User ${adminUser.username} restricted in both databases`);
      res.json({ 
        message: 'User restricted successfully in both databases', 
        user: adminUser,
        mainBackendResponse: mainBackendResponse.data
      });
    } catch (mainBackendError) {
      console.error('Main backend restriction error:', mainBackendError.response?.data || mainBackendError.message);
      // Still return success for admin database update
      res.json({ 
        message: 'User restricted in admin database, but main backend update failed', 
        user: adminUser,
        warning: 'Restriction may not work properly - check main backend connection'
      });
    }
  } catch (error) {
    console.error('Admin restriction error:', error);
    res.status(500).json({ error: 'Error restricting user', message: error.message });
  }
});

// Suspend user
router.patch('/:id/suspend', async (req, res) => {
  try {
    // Update in admin database
    const adminUser = await User.findByIdAndUpdate(
      req.params.id,
      { isVerified: false },
      { new: true, runValidators: true }
    ).select('-password');

    if (!adminUser) {
      return res.status(404).json({ error: 'User not found in admin database' });
    }

    // Also update in main backend database (where suspension alerts are handled)
    try {
      const mainBackendResponse = await axios.patch(
        `${MAIN_BACKEND_URL}/api/users/${req.params.id}`,
        { isVerified: false },
        {
          headers: {
            'Content-Type': 'application/json',
          }
        }
      );

      console.log(`User ${adminUser.username} suspended in both databases`);
      res.json({ 
        message: 'User suspended successfully in both databases', 
        user: adminUser,
        mainBackendResponse: mainBackendResponse.data
      });
    } catch (mainBackendError) {
      console.error('Main backend suspension error:', mainBackendError.response?.data || mainBackendError.message);
      // Still return success for admin database update
      res.json({ 
        message: 'User suspended in admin database, but main backend update failed', 
        user: adminUser,
        warning: 'Suspension may not work properly - check main backend connection'
      });
    }
  } catch (error) {
    console.error('Admin suspension error:', error);
    res.status(500).json({ error: 'Error suspending user', message: error.message });
  }
});

// Activate user
router.patch('/:id/activate', async (req, res) => {
  try {
    // Update in admin database
    const adminUser = await User.findByIdAndUpdate(
      req.params.id,
      { role: 'active', isVerified: true },
      { new: true, runValidators: true }
    ).select('-password');

    if (!adminUser) {
      return res.status(404).json({ error: 'User not found in admin database' });
    }

    // Also update in main backend database
    try {
      const mainBackendResponse = await axios.patch(
        `${MAIN_BACKEND_URL}/api/users/${req.params.id}`,
        { role: 'active', isVerified: true },
        {
          headers: {
            'Content-Type': 'application/json',
          }
        }
      );

      console.log(`User ${adminUser.username} activated in both databases`);
      res.json({ 
        message: 'User activated successfully in both databases', 
        user: adminUser,
        mainBackendResponse: mainBackendResponse.data
      });
    } catch (mainBackendError) {
      console.error('Main backend activation error:', mainBackendError.response?.data || mainBackendError.message);
      // Still return success for admin database update
      res.json({ 
        message: 'User activated in admin database, but main backend update failed', 
        user: adminUser,
        warning: 'Activation may not work properly - check main backend connection'
      });
    }
  } catch (error) {
    console.error('Admin activation error:', error);
    res.status(500).json({ error: 'Error activating user', message: error.message });
  }
});

// Delete user
router.delete('/:id', async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Error deleting user', message: error.message });
  }
});

// Get user statistics
router.get('/stats/overview', async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const verifiedUsers = await User.countDocuments({ isVerified: true });
    const proUsers = await User.countDocuments({ plan: 'Pro' });
    const adminUsers = await User.countDocuments({ role: 'admin' });

    res.json({
      totalUsers,
      verifiedUsers,
      proUsers,
      adminUsers,
      verificationRate: totalUsers > 0 ? Math.round((verifiedUsers / totalUsers) * 100) : 0
    });
  } catch (error) {
    res.status(500).json({ error: 'Error fetching user stats', message: error.message });
  }
});

module.exports = router; 