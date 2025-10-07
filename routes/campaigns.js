const express = require('express');
const { body, validationResult } = require('express-validator');
const Campaign = require('../models/Campaign');
const Lead = require('../models/Lead');
const EmailActivity = require('../models/EmailActivity');
const Mail = require('../models/Mail');
const router = express.Router();

// Validation middleware
const validateCampaign = [
  body('name').trim().isLength({ min: 1 }).withMessage('Campaign name is required'),
  body('sender').isEmail().normalizeEmail().withMessage('Must be a valid sender email'),
  body('status').isIn(['active', 'paused', 'completed', 'draft']).withMessage('Invalid status'),
  body('subject').optional().trim(),
  body('content').optional()
];

// Get all campaigns with detailed statistics
router.get('/', async (req, res) => {
  try {
    const { status } = req.query;
    let filter = {};

    if (status) filter.status = status;

    const campaigns = await Campaign.find(filter)
      .populate('userId', 'username email')
      .populate('listId', 'name')
      .sort({ createdAt: -1 });

    // Get detailed statistics for each campaign
    const campaignsWithStats = await Promise.all(
      campaigns.map(async (campaign) => {
        // Get messages sent for this campaign
        const messagesSent = await EmailActivity.countDocuments({
          campaignId: campaign._id,
          type: 'sent'
        });

        // Get total leads in the list (messages to be sent)
        let messagesToSend = 0;
        if (campaign.listId) {
          messagesToSend = await Lead.countDocuments({ listId: campaign.listId });
        }

        // Get replies for this campaign
        const replies = await EmailActivity.countDocuments({
          campaignId: campaign._id,
          type: { $in: ['reply', 'ai-reply', 'manual-reply'] }
        });

        // Calculate engagement rate
        const engagementRate = messagesSent > 0 ? Math.round((replies / messagesSent) * 100) : 0;

        // Get campaign duration
        const duration = campaign.updatedAt ? 
          Math.ceil((new Date(campaign.updatedAt) - new Date(campaign.createdAt)) / (1000 * 60 * 60 * 24)) : 0;

        return {
          ...campaign.toObject(),
          messagesSent,
          messagesToSend,
          replies,
          engagementRate,
          duration
        };
      })
    );

    res.json(campaignsWithStats);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching campaigns', message: error.message });
  }
});

// Get campaign by ID with detailed statistics
router.get('/:id', async (req, res) => {
  try {
    const campaign = await Campaign.findById(req.params.id)
      .populate('userId', 'username email')
      .populate('listId', 'name');

    if (!campaign) {
      return res.status(404).json({ error: 'Campaign not found' });
    }

    // Get detailed statistics
    const messagesSent = await EmailActivity.countDocuments({
      campaignId: campaign._id,
      type: 'sent'
    });

    let messagesToSend = 0;
    if (campaign.listId) {
      messagesToSend = await Lead.countDocuments({ listId: campaign.listId });
    }

    const replies = await EmailActivity.countDocuments({
      campaignId: campaign._id,
      type: { $in: ['reply', 'ai-reply', 'manual-reply'] }
    });

    const engagementRate = messagesSent > 0 ? Math.round((replies / messagesSent) * 100) : 0;

    // Get recent activities
    const recentActivities = await EmailActivity.find({
      campaignId: campaign._id
    })
    .sort({ timestamp: -1 })
    .limit(10)
    .populate('leadId', 'email name');

    // Get daily activity breakdown
    const dailyActivity = await EmailActivity.aggregate([
      {
        $match: { campaignId: campaign._id }
      },
      {
        $group: {
          _id: {
            $dateToString: { format: "%Y-%m-%d", date: "$timestamp" }
          },
          sent: { $sum: { $cond: [{ $eq: ["$type", "sent"] }, 1, 0] } },
          replies: { $sum: { $cond: [{ $in: ["$type", ["reply", "ai-reply", "manual-reply"]] }, 1, 0] } }
        }
      },
      {
        $sort: { _id: 1 }
      }
    ]);

    const campaignWithStats = {
      ...campaign.toObject(),
      messagesSent,
      messagesToSend,
      replies,
      engagementRate,
      recentActivities,
      dailyActivity
    };

    res.json(campaignWithStats);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching campaign', message: error.message });
  }
});

// Create new campaign
router.post('/', validateCampaign, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, sender, status, language, toneOfVoice, showEmailAddress, unSubscribe, unSubscribeType, responseFrom, responseTo, userId, listId } = req.body;

    const campaign = new Campaign({
      name,
      sender,
      status,
      language,
      toneOfVoice,
      showEmailAddress,
      unSubscribe,
      unSubscribeType,
      responseFrom,
      responseTo,
      userId: userId || '507f1f77bcf86cd799439011', // Default user ID for demo
      listId
    });

    await campaign.save();
    
    const populatedCampaign = await Campaign.findById(campaign._id)
      .populate('userId', 'username email')
      .populate('listId', 'name');

    res.status(201).json(populatedCampaign);
  } catch (error) {
    res.status(500).json({ error: 'Error creating campaign', message: error.message });
  }
});

// Update campaign
router.patch('/:id', async (req, res) => {
  try {
    const { name, status, sender, language, toneOfVoice, showEmailAddress, unSubscribe, unSubscribeType, responseFrom, responseTo, listId } = req.body;
    const updateData = {};

    if (name !== undefined) updateData.name = name;
    if (status !== undefined) updateData.status = status;
    if (sender !== undefined) updateData.sender = sender;
    if (language !== undefined) updateData.language = language;
    if (toneOfVoice !== undefined) updateData.toneOfVoice = toneOfVoice;
    if (showEmailAddress !== undefined) updateData.showEmailAddress = showEmailAddress;
    if (unSubscribe !== undefined) updateData.unSubscribe = unSubscribe;
    if (unSubscribeType !== undefined) updateData.unSubscribeType = unSubscribeType;
    if (responseFrom !== undefined) updateData.responseFrom = responseFrom;
    if (responseTo !== undefined) updateData.responseTo = responseTo;
    if (listId !== undefined) updateData.listId = listId;

    const campaign = await Campaign.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true, runValidators: true }
    )
    .populate('userId', 'username email')
    .populate('listId', 'name');

    if (!campaign) {
      return res.status(404).json({ error: 'Campaign not found' });
    }

    res.json(campaign);
  } catch (error) {
    res.status(500).json({ error: 'Error updating campaign', message: error.message });
  }
});

// Delete campaign
router.delete('/:id', async (req, res) => {
  try {
    const campaign = await Campaign.findByIdAndDelete(req.params.id);
    if (!campaign) {
      return res.status(404).json({ error: 'Campaign not found' });
    }
    res.json({ message: 'Campaign deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Error deleting campaign', message: error.message });
  }
});

// Get campaign statistics overview
router.get('/stats/overview', async (req, res) => {
  try {
    const totalCampaigns = await Campaign.countDocuments();
    const activeCampaigns = await Campaign.countDocuments({ status: 'active' });
    const pausedCampaigns = await Campaign.countDocuments({ status: 'paused' });
    const completedCampaigns = await Campaign.countDocuments({ status: 'completed' });
    const draftCampaigns = await Campaign.countDocuments({ status: 'draft' });

    // Get total messages sent across all campaigns
    const totalMessagesSent = await EmailActivity.countDocuments({ type: 'sent' });
    const totalReplies = await EmailActivity.countDocuments({ 
      type: { $in: ['reply', 'ai-reply', 'manual-reply'] } 
    });

    res.json({
      totalCampaigns,
      activeCampaigns,
      pausedCampaigns,
      completedCampaigns,
      draftCampaigns,
      totalMessagesSent,
      totalReplies,
      overallEngagementRate: totalMessagesSent > 0 ? Math.round((totalReplies / totalMessagesSent) * 100) : 0
    });
  } catch (error) {
    res.status(500).json({ error: 'Error fetching campaign stats', message: error.message });
  }
});

module.exports = router; 