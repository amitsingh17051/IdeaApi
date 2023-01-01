const mongoose = require('mongoose');
const Schema = mongoose.Schema;

// create student schema & model
const UserSchema = new mongoose.Schema({
    email: {
      type: String,
      index: { unique: true }
    },
    password: String,
    name: String
  });
  


const User = mongoose.model('user',UserSchema);

module.exports = User;