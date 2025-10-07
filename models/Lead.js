const mongoose = require("mongoose");

const leadSchema = new mongoose.Schema({
  name: String,
  firstName: String,
  lastName: String,
  title: String,
  seniority: String,
  email: {
    type: String,
    required: true,
  },
  phone: String,
  linkedin: String,
  website: String,
  job: String,
  company: String,
  companyClean: String,
  companyLocation: String,
  companyCity: String,
  companyCountry: String,
  companyDescription: String,
  companySite: String,
  companyIndustry: String,
  companyLinkdedin: String,
  companyLinkedinId: String,
  companyStaffCount: String,
  companyStaffRange: String,
  contactCountry: String,
  contactCity: String,
  listId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "List",
    required: true,
  },
}, {
  timestamps: true
});

// Index for email lookups
leadSchema.index({ email: 1 });

const LeadModel = mongoose.model("Lead", leadSchema);
module.exports = LeadModel; 