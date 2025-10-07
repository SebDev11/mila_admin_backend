const mongoose = require("mongoose");

const campaignSchema = new mongoose.Schema({
  name: {
    type: String,
  },
  status: {
    type: String,
    required: true,
  },
  language: String,
  toneOfVoice: String,
  showEmailAddress: Boolean,
  unSubscribe: Boolean,
  unSubscribeType: String,
  responseFrom: {
    time: { type: Number },
    unit: { type: String },
  },
  responseTo: {
    time: { type: Number },
    unit: { type: String },
  },
  sender: {
    type: String,
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  listId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "List",
  },
}, {
  timestamps: true
});

const CampaignModel = mongoose.model("Campaign", campaignSchema);
module.exports = CampaignModel; 