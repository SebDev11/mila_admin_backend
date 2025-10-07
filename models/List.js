const mongoose = require("mongoose");

const ListSchema = new mongoose.Schema({
  name: {
    type: String,
  },
  status: {
    type: String,
    required: true,
  },
  source: [],
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
}, {
  timestamps: true
});

const ListModel = mongoose.model("List", ListSchema);
module.exports = ListModel; 