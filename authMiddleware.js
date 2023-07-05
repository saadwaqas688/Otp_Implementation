const jwtUtils = require('./jwtUtils');
require('dotenv').config();

const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY;

const verifyToken = (req, res, next) => {
    const publicRoutes = ['/login', '/register','/otp'];

  // Check if the current route is a public route
  if (publicRoutes.includes(req.path)) {
    return next();
  }
  const token = req.headers.token;
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const decoded = jwtUtils.verifyToken(token, JWT_SECRET_KEY);
  if (!decoded) {
    return res.status(401).json({ error: 'Invalid token' });
  }

  req.user = decoded;
  next();
};

module.exports = {
  verifyToken,
};
