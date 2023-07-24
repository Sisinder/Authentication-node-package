const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const saltRounds = 10;
const secretKey = 'your_secret_key'; // Replace this with a strong secret key for JWT

// Function to hash the user's password
async function hashPassword(password) {
  try {
    const salt = await bcrypt.genSalt(saltRounds);
    return await bcrypt.hash(password, salt);
  } catch (error) {
    throw error;
  }
}

// Function to compare the provided password with the hashed password
async function comparePasswords(password, hashedPassword) {
  try {
    return await bcrypt.compare(password, hashedPassword);
  } catch (error) {
    throw error;
  }
}

// Function to generate a JWT token for a user with roles
function generateToken(user) {
  const payload = {
    id: user._id,
    username: user.username,
    roles: user.roles,
  };

  return jwt.sign(payload, secretKey, { expiresIn: '1h' }); // Token expires in 1 hour
}

// Middleware to authenticate incoming requests using JWT
function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1]; // Get token from Authorization header
  if (!token) {
    return res.sendStatus(401);
  }

  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }
    req.user = user;
    next();
  });
}

// Middleware to check if the user has the required role to access protected routes
function checkRole(role) {
  return (req, res, next) => {
    // Check if user is authenticated (JWT token present)
    const token = req.headers['authorization']?.split(' ')[1]; // Get token from Authorization header
    if (!token) {
      return res.sendStatus(401);
    }

    jwt.verify(token, secretKey, (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }

      // Check if the user has the required role
      if (!user.roles.includes(role)) {
        return res.sendStatus(403);
      }

      req.user = user;
      next();
    });
  };
}

module.exports = {
  hashPassword,
  comparePasswords,
  generateToken,
  authenticateToken,
  checkRole,
};
