const express = require('express');
const User = require('../models/User');
const Campaign = require('../models/Campaign');
const Lead = require('../models/Lead');
const EmailActivity = require('../models/EmailActivity');
const Mail = require('../models/Mail');
const router = express.Router();

// Get overall dashboard stats
router.get('/', async (req, res) => {
  try {
    // User stats
    const totalUsers = await User.countDocuments();
    const verifiedUsers = await User.countDocuments({ isVerified: true });
    const proUsers = await User.countDocuments({ plan: 'Pro' });

    // Campaign stats
    const totalCampaigns = await Campaign.countDocuments();
    const activeCampaigns = await Campaign.countDocuments({ status: 'active' });

    // Lead stats
    const totalLeads = await Lead.countDocuments();

    // Email activity stats
    const totalEmailsSent = await EmailActivity.countDocuments({ type: 'sent' });
    const totalReplies = await EmailActivity.countDocuments({ type: { $in: ['reply', 'ai-reply', 'manual-reply'] } });

    const stats = {
      emailsSent: totalEmailsSent,
      activeCampaigns,
      engagedLeads: totalReplies,
      systemHealth: 'Healthy',
      totalUsers,
      verifiedUsers,
      proUsers,
      totalCampaigns,
      totalLeads,
      emailOpenRate: totalEmailsSent > 0 ? Math.round((totalReplies / totalEmailsSent) * 100) : 0,
      emailClickRate: 0 // Not tracked in current schema
    };

    res.json(stats);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching stats', message: error.message });
  }
});

// Get user-specific statistics
router.get('/user/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const { period = 'month' } = req.query; // day, week, month

    // Calculate date range based on period
    const now = new Date();
    let startDate;
    switch (period) {
      case 'day':
        startDate = new Date(now.getFullYear(), now.getMonth(), now.getDate());
        break;
      case 'week':
        startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        break;
      case 'month':
      default:
        startDate = new Date(now.getFullYear(), now.getMonth(), 1);
        break;
    }

    // Get user's sent emails count
    const sentEmailsCount = await EmailActivity.countDocuments({
      senderId: { $in: await Mail.find({ userId }).distinct('_id') },
      type: 'sent',
      timestamp: { $gte: startDate }
    });

    // Get user's created campaigns count
    const createdCampaignsCount = await Campaign.countDocuments({
      userId,
      createdAt: { $gte: startDate }
    });

    // Get user's activities by type
    const activitiesByType = await EmailActivity.aggregate([
      {
        $match: {
          senderId: { $in: await Mail.find({ userId }).distinct('_id') },
          timestamp: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: '$type',
          count: { $sum: 1 }
        }
      }
    ]);

    // Get user's activities by day for the period
    const activitiesByDay = await EmailActivity.aggregate([
      {
        $match: {
          senderId: { $in: await Mail.find({ userId }).distinct('_id') },
          timestamp: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: {
            $dateToString: { format: "%Y-%m-%d", date: "$timestamp" }
          },
          count: { $sum: 1 },
          types: { $addToSet: '$type' }
        }
      },
      {
        $sort: { _id: 1 }
      }
    ]);

    // Get user's campaigns by status
    const campaignsByStatus = await Campaign.aggregate([
      {
        $match: {
          userId,
          createdAt: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 }
        }
      }
    ]);

    const userStats = {
      period,
      sentEmailsCount,
      createdCampaignsCount,
      activitiesByType,
      activitiesByDay,
      campaignsByStatus,
      totalActivities: activitiesByDay.reduce((sum, day) => sum + day.count, 0)
    };

    res.json(userStats);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching user stats', message: error.message });
  }
});

// Get weekly email engagement data
router.get('/weekly-engagement', async (req, res) => {
  try {
    const chartData = [];
    const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    for (let i = 6; i >= 0; i--) {
      const dayStart = new Date();
      dayStart.setHours(0, 0, 0, 0);
      dayStart.setDate(dayStart.getDate() - i);
      const dayEnd = new Date(dayStart);
      dayEnd.setHours(23, 59, 59, 999);

      // Count sent emails for this day
      const sent = await EmailActivity.countDocuments({
        type: 'sent',
        timestamp: { $gte: dayStart, $lte: dayEnd }
      });
      // Count engaged emails (reply, ai-reply, manual-reply) for this day
      const engaged = await EmailActivity.countDocuments({
        type: { $in: ['reply', 'ai-reply', 'manual-reply'] },
        timestamp: { $gte: dayStart, $lte: dayEnd }
      });
      chartData.push({
        label: days[dayStart.getDay()],
        sent,
        engaged,
        date: dayStart.toISOString().split('T')[0]
      });
    }
    res.json(chartData);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching weekly engagement', message: error.message });
  }
});

// Get user growth stats
router.get('/user-growth', async (req, res) => {
  try {
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    const userGrowth = await User.aggregate([
      {
        $match: {
          createdAt: { $gte: thirtyDaysAgo }
        }
      },
      {
        $group: {
          _id: {
            $dateToString: { format: "%Y-%m-%d", date: "$createdAt" }
          },
          count: { $sum: 1 }
        }
      },
      {
        $sort: { _id: 1 }
      }
    ]);

    res.json(userGrowth);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching user growth', message: error.message });
  }
});

// Get campaign performance stats
router.get('/campaign-performance', async (req, res) => {
  try {
    const campaignStats = await Campaign.aggregate([
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 },
          avgEngagement: { $avg: '$engagement' },
          totalEmailsSent: { $sum: '$emailsSent' }
        }
      }
    ]);

    res.json(campaignStats);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching campaign performance', message: error.message });
  }
});

// Get lead conversion stats
router.get('/lead-conversion', async (req, res) => {
  try {
    const leadStats = await Lead.aggregate([
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 }
        }
      }
    ]);

    res.json(leadStats);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching lead conversion', message: error.message });
  }
});

// Get sent emails breakdown by campaign and by user for the last 7 days
router.get('/weekly-engagement-breakdown', async (req, res) => {
  try {
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 6);
    sevenDaysAgo.setHours(0, 0, 0, 0);

    // By campaign
    const byCampaign = await EmailActivity.aggregate([
      { $match: { type: 'sent', timestamp: { $gte: sevenDaysAgo } } },
      { $group: { _id: '$campaignId', count: { $sum: 1 } } },
      { $lookup: { from: 'campaigns', localField: '_id', foreignField: '_id', as: 'campaign' } },
      { $unwind: { path: '$campaign', preserveNullAndEmptyArrays: true } },
      { $project: { name: '$campaign.name', count: 1 } },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);

    // By user (senderId)
    const byUser = await EmailActivity.aggregate([
      { $match: { type: 'sent', timestamp: { $gte: sevenDaysAgo } } },
      { $group: { _id: '$senderId', count: { $sum: 1 } } },
      { $lookup: { from: 'mails', localField: '_id', foreignField: '_id', as: 'mail' } },
      { $unwind: { path: '$mail', preserveNullAndEmptyArrays: true } },
      { $project: { email: '$mail.email', count: 1 } },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);

    res.json({ byCampaign, byUser });
  } catch (error) {
    console.error('Error fetching engagement breakdown:', error);
    res.status(500).json({ error: 'Error fetching engagement breakdown', message: error.message });
  }
});

module.exports = router; 