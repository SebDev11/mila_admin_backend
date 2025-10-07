const mongoose = require('mongoose');

const PlanSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true
  },
  price: {
    type: Number,
    required: true
  },
  emailLimit: {
    type: Number,
    required: true
  },
  stripePriceId: {
    type: String,
    default: ''
  },
  description: {
    type: String,
    default: ''
  }
}, {
  timestamps: true
});

const Plan = mongoose.model('Plan', PlanSchema);

module.exports = Plan; 