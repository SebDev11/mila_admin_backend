const jwt = require('jsonwebtoken');
const User = require('../models/User');

const authMiddleware = async (req, res, next) => {
  try {
    // Get token from request header
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ 
        message: 'No token, authorization denied!'
      });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.SECRET_TOKEN || process.env.JWT_SECRET || 'fallback_secret_key');
    
    // Get user from database
    const user = await User.findById(decoded.userId).select('-password');
    if (!user) {
      return res.status(401).json({ 
        message: 'Token is valid but user not found!'
      });
    }

    // Check if user is verified
    if (!user.isVerified) {
      return res.status(403).json({ 
        message: 'Account is suspended!'
      });
    }

    // Check if user has admin role
    if (user.role !== 'admin') {
      return res.status(403).json({
        message: 'Access denied. Admin privileges required.'
      });
    }

    // Add user to request object
    req.user = user;
    next();
  } catch (err) {
    console.error('Auth middleware error:', err.message);
    
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ 
        message: 'Invalid token!'
      });
    }
    
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        message: 'Token expired!'
      });
    }
    
    return res.status(500).json({ 
      message: 'Server error during authentication!'
    });
  }
};

module.exports = authMiddleware;
