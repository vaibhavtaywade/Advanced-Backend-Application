const mongoose = require('mongoose');

// User Schema for storing user information
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  hashedPassword: { type: String, required: true },
});

// AuthToken Schema for tracking active sessions
const AuthTokenSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  token: { type: String, required: true },
  expiresAt: { type: Date, required: true },
});

const User = mongoose.model('User', UserSchema);
const AuthToken = mongoose.model('AuthToken', AuthTokenSchema);

module.exports = { User, AuthToken };
