const express = require('express');
const router = express.Router();
const db = require('./db');
const bcrypt = require('bcrypt');
const jwtUtils = require('./jwtUtils');
const nodemailer = require('nodemailer');
const session = require('express-session');

const JWT_SECRET_KEY = 'your-secret-key';

router.use(express.json());
router.use(express.urlencoded({ extended: true }));
router.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false,
}));

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'saadwaqas688@gmail.com',
    pass: 'uaooazfxtjrbvidx'
  }
});



// router.post('/register', async (req, res) => {
//   console.log("khan",req.body)
//   const { username, password } = req.body;

//   // Check if the username is already taken (query the database)
//   const usernameExistsQuery = 'SELECT * FROM users WHERE user_name = $1';
//   const usernameExistsValues = [username];
//   const usernameExistsResult = await db.query(usernameExistsQuery, usernameExistsValues);

//   if (usernameExistsResult.rowCount > 0) {
//     return res.status(400).json({ error: 'Username already exists' });
//   }

//   // Hash the password
//   const hashedPassword = await bcrypt.hash(password, 10);

//   // Insert the user into the database
//   const registerQuery = 'INSERT INTO users (user_name, password) VALUES ($1, $2)';
//   const registerValues = [username, hashedPassword];
//   await db.query(registerQuery, registerValues);

//   res.status(201).json({ message: 'User registered successfully' });
// });

router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Retrieve the user from the database based on the username
    const userQuery = 'SELECT * FROM users WHERE user_name = $1';
    const userValues = [username];
    const userResult = await db.query(userQuery, userValues);

    // Check if a user with the provided username exists
    if (userResult.rowCount === 0) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Verify the password
    const user = userResult.rows[0];
    const isPasswordValid = await jwtUtils.comparePassword(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Password is valid, authentication successful
    // Generate JWT token
    const token = jwtUtils.generateToken({ userId: user.id, username: user.username }, JWT_SECRET_KEY, '1h');

    res.status(200).json({ token });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/protected', (req, res) => {
  const token = req.headers.token;
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const decoded = jwtUtils.verifyToken(token,JWT_SECRET_KEY);
  if (!decoded) {
    return res.status(401).json({ error: 'Invalid token' });
  }

  // Access the user ID and other payload information from the decoded token
  const userId = decoded.userId;
  // Replace this code with your protected route logic

  res.json({ userId });
});

router.get('/users', (req, res) => {
  const query = `SELECT c.company_name, t.team_name, u.user_name
    FROM companies c
    LEFT JOIN teams t ON c.id = t.company_id
    LEFT JOIN user_team ut ON t.id = ut.team_id
    LEFT JOIN users u ON ut.user_id = u.id
    ORDER BY c.company_name, t.team_name, u.user_name`;
    db.query(query, (err, result) => {
    if (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch users' });
    } else {
    res.json(result.rows);
    }
    });
    });
    


    //  async function verifyOTP(req, res) {
    //   const { code } = req.query;
    //   const storedOTP = req.session.otp;
    
    //   if (parseInt(storedOTP) === parseInt(code)) {
    //     req.session.otp = null;
    //     req.session.resetSession = true;
    //     return res.status(201).send({ msg: 'Verification successful!' });
    //   }
    
    //   return res.status(400).send({ error: 'Invalid OTP' });
    // }
    


    router.post('/register', async (req, res) => {
      const { username, password } = req.body;
    
      // Generate OTP
      const otp = 123; // Replace this with your OTP generation logic
    
      // Store the OTP in session
      req.session.otp = otp;
    
      // Send OTP via email
      const mailOptions = {
        from: 'saadwaqas688@gmail.com',
        to: 'abdullah.akhlaq@ceative.co.uk',
        subject: 'OTP Verification',
        text: `Your OTP is: ${otp}`
      };
    
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error('Error sending email:', error);
          return res.status(500).json({ error: 'Failed to send OTP via email' });
        }
    
        res.status(201).json({ message: 'User registered successfully' });
      });
    });
    
    

    router.post('/otp', async (req, res) => {
      const { username, password, otp } = req.body;

      console.log(req.body)
      console.log(req.session.otp)
    
      // Verify the OTP
      if (req.session.otp !== otp) {
        return res.status(400).json({ error: 'Invalid OTP' });
      }
    
      // Check if the username is already taken (query the database)
      const usernameExistsQuery = 'SELECT * FROM users WHERE user_name = $1';
      const usernameExistsValues = [username];
      const usernameExistsResult = await db.query(usernameExistsQuery, usernameExistsValues);
    
      if (usernameExistsResult.rowCount > 0) {
        return res.status(400).json({ error: 'Username already exists' });
      }
    
      // Hash the password
      const hashedPassword = await jwtUtils.hashPassword(password);
    
      // Insert the user into the database
      const registerQuery = 'INSERT INTO users (user_name, password) VALUES ($1, $2)';
      const registerValues = [username, hashedPassword];
      await db.query(registerQuery, registerValues);
    
      // Clear the OTP from session
      delete req.session.otp;
    
      res.status(201).json({ message: 'User registered successfully' });
    });
    
    module.exports = router;
