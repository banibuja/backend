require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const cors = require('cors');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const flash = require('connect-flash');
const cookieParser = require('cookie-parser');
const sequelize = require('./db');
const User = require('./models/user');
const routes = require('./routes/routes-all'); 

const app = express();

// Rate limiter setup to prevent brute-force attacks
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Set security headers
app.use(helmet());

// CORS setup
const allowedOrigins = ['http://localhost:3000', 'https://travelapp-virid.vercel.app'];

app.use(cors({
  origin: function (origin, callback) {
    console.log('CORS Origin:', origin); // Log for debugging purposes
    if (allowedOrigins.includes(origin) || !origin) { // Allow undefined origin for non-browser tools like Postman
      callback(null, true);
    } else {
      callback(new Error('Forbidden: Invalid origin'));
    }
  },
  methods: 'GET,POST,PUT,DELETE',
  credentials: true,
}));

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin);
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  next();
});

// Middleware for parsing request bodies
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true, parameterLimit: 50000 }));

// Middleware for handling cookies, sessions, and flash messages
app.use(cookieParser());
app.use(session({
  secret: process.env.SESSION_SECRET || 'supersecret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
  },
}));
app.use(flash());

// Passport.js setup for authentication
passport.use(new LocalStrategy(async (username, password, done) => {
  try {
    const user = await User.findOne({ where: { username } });
    if (!user) {
      return done(null, false, { message: 'User not found.' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return done(null, false, { message: 'Incorrect password.' });
    }
    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findByPk(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

app.use(passport.initialize());
app.use(passport.session());

// Routes
app.use('/api', routes);

// JWT Authentication Middleware
const isAuthenticated = (req, res, next) => {
  const token = req.cookies['ubtsecured'];
  if (!token) {
    return res.status(401).json({ error: 'Authentication required.' });
  }
  jwt.verify(token, process.env.JWT_SECRET || 'supersecret', (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token.' });
    }
    req.user = decoded;
    next();
  });
};

// Example authenticated route
app.get('/user', isAuthenticated, (req, res) => {
  res.json({ user: req.user });
});

app.get('/', (req, res) => {
  res.json('Home');
});

// Logout route
app.post('/logout', (req, res) => {
  res.clearCookie('ubtsecured', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
  });
  req.logout((err) => {
    if (err) {
      console.error('Logout error:', err.message);
      return res.status(500).json({ error: 'Failed to log out.' });
    }
    res.status(200).json({ message: 'Logged out successfully.' });
  });
});

// Initialize Database and Start Server
const initializeDatabase = async () => {
  try {
    await sequelize.authenticate(); // Test DB connection
    await sequelize.sync(); // Sync models
    const PORT = process.env.PORT || 5000;
    app.listen(PORT, () => {
      console.log(`Server is running on port ${PORT}`);
    });
  } catch (error) {
    console.error('Error initializing the database or server:', error.message);
    process.exit(1); // Exit if DB connection or other critical errors occur
  }
};

// Start the application
initializeDatabase();

// Global error handling
process.on('uncaughtException', (error) => {
  console.error('Unhandled Exception:', error.message);
  process.exit(1); // Force server exit on uncaught exceptions
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection:', reason);
  process.exit(1); // Force server exit on unhandled promise rejections
});
