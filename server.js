const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
require('dotenv').config();

const app = express();

// ==================== DATABASE MODELS ====================

// User Model
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  balance: { type: Number, default: 0 },
  totalEarnings: { type: Number, default: 0 },
  role: { type: String, default: 'user' },
  isActive: { type: Boolean, default: true }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// Investment Plan Model
const investmentPlanSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  investmentAmount: { type: Number, required: true },
  durationDays: { type: Number, required: true },
  dailyReturn: { type: Number, required: true },
  rechargeBonus: { type: Number, required: true },
  totalReturn: { type: Number, required: true },
  isPopular: { type: Boolean, default: false },
  isActive: { type: Boolean, default: true }
}, { timestamps: true });

const InvestmentPlan = mongoose.model('InvestmentPlan', investmentPlanSchema);

// Investment Model
const investmentSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  planId: { type: mongoose.Schema.Types.ObjectId, ref: 'InvestmentPlan', required: true },
  amount: { type: Number, required: true },
  dailyReturn: { type: Number, required: true },
  totalReturn: { type: Number, required: true },
  startDate: { type: Date, default: Date.now },
  endDate: { type: Date, required: true },
  status: { type: String, enum: ['active', 'completed', 'cancelled'], default: 'active' }
}, { timestamps: true });

const Investment = mongoose.model('Investment', investmentSchema);

// ==================== MIDDLEWARE ====================

// Authentication Middleware
const auth = async (req, res, next) => {
  try {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      return res.status(401).json({ message: 'Please log in to get access' });
    }

    if (!process.env.JWT_SECRET) {
      return res.status(500).json({ message: 'Server configuration error' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) {
      return res.status(401).json({ message: 'User no longer exists' });
    }

    req.user = user;
    next();

  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ message: 'Invalid token' });
    } else if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token has expired' });
    }
    console.error('Authentication error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

// Admin Middleware
const adminAuth = async (req, res, next) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Access denied. Admin only.' });
    }
    next();
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

// ==================== UTILITY FUNCTIONS ====================

// Initialize Investment Plans
const initializePlans = async () => {
  try {
    const plans = [
      {
        name: 'VIP 1',
        description: 'Basic VIP Plan',
        investmentAmount: 5,
        durationDays: 10,
        dailyReturn: 1,
        rechargeBonus: 1,
        totalReturn: 11,
        isPopular: false
      },
      {
        name: 'VIP 2',
        description: 'Standard VIP Plan',
        investmentAmount: 10,
        durationDays: 10,
        dailyReturn: 2,
        rechargeBonus: 2,
        totalReturn: 22,
        isPopular: false
      },
      {
        name: 'VIP 3',
        description: 'Advanced VIP Plan',
        investmentAmount: 15,
        durationDays: 10,
        dailyReturn: 3,
        rechargeBonus: 3,
        totalReturn: 33,
        isPopular: false
      },
      {
        name: 'VIP 4',
        description: 'Premium VIP Plan - Most Popular',
        investmentAmount: 20,
        durationDays: 10,
        dailyReturn: 5,
        rechargeBonus: 5,
        totalReturn: 55,
        isPopular: true
      },
      {
        name: 'VIP 5',
        description: 'Ultimate VIP Plan',
        investmentAmount: 30,
        durationDays: 10,
        dailyReturn: 6,
        rechargeBonus: 5,
        totalReturn: 65,
        isPopular: false
      }
    ];

    for (const planData of plans) {
      await InvestmentPlan.findOneAndUpdate(
        { name: planData.name },
        planData,
        { upsert: true, new: true }
      );
    }

    console.log('VIP investment plans initialized successfully');
  } catch (error) {
    console.error('Error initializing investment plans:', error);
  }
};

// ==================== ROUTE HANDLERS ====================

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user
    const user = new User({
      name,
      email,
      password: hashedPassword
    });

    await user.save();

    // Generate token
    const token = jwt.sign(
      { id: user._id }, 
      process.env.JWT_SECRET, 
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    res.status(201).json({
      status: 'success',
      token,
      data: {
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          balance: user.balance,
          role: user.role
        }
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error during registration' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check for admin credentials
    if (email === 'admin@astraprofit.com' && password === 'Li2025y#') {
      const adminToken = jwt.sign(
        { id: 'admin', role: 'admin' },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN }
      );
      
      return res.json({
        status: 'success',
        token: adminToken,
        data: {
          user: {
            id: 'admin',
            name: 'Admin',
            email: 'admin@astraprofit.com',
            role: 'admin',
            balance: 0
          }
        }
      });
    }

    // Regular user login
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    res.json({
      status: 'success',
      token,
      data: {
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          balance: user.balance,
          role: user.role
        }
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error during login' });
  }
});

// User Routes
app.get('/api/user/profile', auth, async (req, res) => {
  try {
    res.json({
      status: 'success',
      data: {
        user: req.user
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Investment Plan Routes
app.get('/api/investment-plans', async (req, res) => {
  try {
    const plans = await InvestmentPlan.find({ isActive: true });
    res.json({
      status: 'success',
      data: {
        plans
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/investments', auth, async (req, res) => {
  try {
    const { planId, amount } = req.body;

    const plan = await InvestmentPlan.findById(planId);
    if (!plan) {
      return res.status(404).json({ message: 'Investment plan not found' });
    }

    if (req.user.balance < amount) {
      return res.status(400).json({ message: 'Insufficient balance' });
    }

    // Create investment
    const investment = new Investment({
      userId: req.user._id,
      planId: plan._id,
      amount,
      dailyReturn: plan.dailyReturn,
      totalReturn: plan.totalReturn,
      endDate: new Date(Date.now() + plan.durationDays * 24 * 60 * 60 * 1000)
    });

    // Deduct from user balance
    req.user.balance -= amount;
    await req.user.save();
    await investment.save();

    res.status(201).json({
      status: 'success',
      data: {
        investment
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error creating investment' });
  }
});

// Admin Routes
app.get('/api/admin/users', auth, adminAuth, async (req, res) => {
  try {
    const users = await User.find({ role: 'user' });
    res.json({
      status: 'success',
      data: {
        users
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/admin/plans', auth, adminAuth, async (req, res) => {
  try {
    const plan = new InvestmentPlan(req.body);
    await plan.save();
    
    res.status(201).json({
      status: 'success',
      data: {
        plan
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error creating plan' });
  }
});

// ==================== SERVER SETUP ====================

// Middleware
app.use(cors());
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan('combined'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'Astra Profit Hub API is running',
    timestamp: new Date().toISOString()
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ message: 'Route not found' });
});

// Database connection and server start
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/astra-profit-hub';

mongoose.connect(MONGODB_URI, { 
  useNewUrlParser: true, 
  useUnifiedTopology: true 
})
.then(() => {
  console.log('Connected to MongoDB');
  initializePlans();
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
})
.catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

// Graceful shutdown
process.on('SIGINT', () => {
  mongoose.connection.close(false, () => {
    console.log('MongoDB connection closed due to app termination');
    process.exit(0);
  });
});