const jwt = require('jsonwebtoken');
const crypto = require('crypto');

exports.generateToken = (user) => {
  return jwt.sign(
    { 
      id: user._id,
      email: user.email,
      name: user.name
    },
    process.env.JWT_SECRET, 
    { expiresIn: '3d' } // Longer expiration for "remember me"
  );
};

exports.generateResetToken = () => {
  return crypto.randomBytes(32).toString('hex');
};
