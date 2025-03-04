const jwt = require('jsonwebtoken');
const crypto = require('crypto');

exports.generateToken = (user) => {
  return jwt.sign(
    { user: { id: user._id } },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN }
  );
};

exports.generateResetToken = () => {
  return crypto.randomBytes(32).toString('hex');
};