const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const mailSchema = new mongoose.Schema({
  provider: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  status: {
    type: Boolean,
    default: false,
  },
  warmUpStatus: {
    type: Boolean,
    default: false,
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  accessToken: String,
  refreshToken: String,
});

mailSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

const MailModel = mongoose.model("Mail", mailSchema);
module.exports = MailModel; 