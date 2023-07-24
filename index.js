const User = require('./lib/models/user');
const { hashPassword, comparePasswords, generateToken, authenticateToken } = require('./lib/auth');

module.exports = {
  User,
  hashPassword,
  comparePasswords,
  generateToken,
  authenticateToken,
};

