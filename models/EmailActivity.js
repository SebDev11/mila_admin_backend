const mongoose = require("mongoose");

const emailActivitySchema = new mongoose.Schema({
  leadId: { type: mongoose.Schema.Types.ObjectId, ref: "Lead", required: true },
  campaignId: { type: mongoose.Schema.Types.ObjectId, ref: "Campaign", required: true },
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: "Mail", required: true },
  type: { type: String, enum: ["sent", "reply", "ai-reply", "manual-reply"], required: true },
  subject: String,
  body: String,
  timestamp: { type: Date, default: Date.now },
  sequenceStep: Number,
  replyTo: { type: mongoose.Schema.Types.ObjectId, ref: "EmailActivity" },
  sentiment: String,
  intent: String,
  handledByAI: Boolean,
  canAIReply: { type: Boolean, default: false },
}, {
  timestamps: true
});

const EmailActivityModel = mongoose.model("EmailActivity", emailActivitySchema);
module.exports = EmailActivityModel; 