const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const generateToken = (payload,your_secret_key, expiresIn) => {
  return jwt.sign(payload, your_secret_key, { expiresIn });
};

const verifyToken = (token,your_secret_key) => {
  try {
    return jwt.verify(token, your_secret_key);
  } catch (error) {
    return null;
  }
};

const hashPassword = async (password) => {
  const saltRounds = 10;
  return await bcrypt.hash(password, saltRounds);
};

const comparePassword = async (password, hashedPassword) => {
  return await bcrypt.compare(password, hashedPassword);
};

module.exports = {
  generateToken,
  verifyToken,
  hashPassword,
  comparePassword
};
