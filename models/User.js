const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: String, // optional for Google users
    name: String,
    provider: { type: String, default: 'local' }, // 'google' or 'local'
    googleId: String,
});

module.exports = mongoose.model('User', userSchema);
