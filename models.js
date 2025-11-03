const { User, Investment, Transaction } = require('./models');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// User Schema
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  balance: {
    type: Number,
    default: 0
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  }
}, {
  timestamps: true
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

userSchema.methods.correctPassword = async function(candidatePassword, userPassword) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

// Daily Signin Schema
const dailySigninSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true
  },
  streakCount: {
    type: Number,
    default: 0
  },
  lastSignin: {
    type: Date,
    default: Date.now
  },
  totalSignins: {
    type: Number,
    default: 0
  }
}, {
  timestamps: true
});

// Investment Plan Schema
const investmentPlanSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  description: String,
  investmentAmount: {
    type: Number,
    required: true
  },
  durationDays: {
    type: Number,
    required: true
  },
  dailyReturn: {
    type: Number,
    required: true
  },
  rechargeBonus: {
    type: Number,
    required: true
  },
  totalReturn: {
    type: Number,
    required: true
  },
  isPopular: {
    type: Boolean,
    default: false
  },
  isActive: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: true
});

// Transaction Schema
const transactionSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  type: {
    type: String,
    enum: ['deposit', 'withdrawal', 'investment'],
    required: true
  },
  amount: {
    type: Number,
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'approved', 'failed'],
    default: 'pending'
  },
  description: String
}, {
  timestamps: true
});

// Deposit Schema
const depositSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  amount: {
    type: Number,
    required: true,
    validate: {
      validator: (v) => v > 0,
      message: 'Amount must be a positive number'
    }
  },
  transaction: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Transaction',
    required: true
  },
  usdtWalletAddress: {
    type: String,
    default: '0x41ef699B7C10C04a6f7c47D0AB0f19CA8398583a'
  },
  txHash: {
    type: String,
    trim: true,
    validate: {
      validator: (v) => {
        return typeof v === 'string' && v.length <= 66;
      },
      message: 'Invalid txHash format'
    }
  },
  plan: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'InvestmentPlan'
  },
  transactionStatus: {
    type: String,
    enum: ['pending', 'completed', 'failed'],
    default: 'pending'
  }
}, {
  timestamps: true
});

depositSchema.index({ user: 1 });
depositSchema.index({ transaction: 1 });

// Investment Schema
const investmentSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  plan: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'InvestmentPlan',
    required: true
  },
  amount: {
    type: Number,
    required: true
  },
  startDate: {
    type: Date,
    default: Date.now
  },
  endDate: {
    type: Date,
    required: true
  },
  isActive: {
    type: Boolean,
    default: true
  },
  dailyReturnsCollected: {
    type: Number,
    default: 0
  },
  lastCollectionDate: Date
}, {
  timestamps: true
});

investmentSchema.index({ user: 1, isActive: 1 });

// Withdrawal Schema
const withdrawalSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  amount: {
    type: Number,
    required: true
  },
  transaction: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Transaction',
    required: true
  },
  walletAddress: {
    type: String,
    required: true,
    trim: true
  },
  status: {
    type: String,
    enum: ['pending', 'processed', 'failed'],
    default: 'pending'
  }
}, {
  timestamps: true
});

// Export all models
module.exports = {
  User: mongoose.model('User', userSchema),
  DailySignin: mongoose.model('DailySignin', dailySigninSchema),
  InvestmentPlan: mongoose.model('InvestmentPlan', investmentPlanSchema),
  Transaction: mongoose.model('Transaction', transactionSchema),
  Deposit: mongoose.model('Deposit', depositSchema),
  Investment: mongoose.model('Investment', investmentSchema),
  Withdrawal: mongoose.model('Withdrawal', withdrawalSchema)
};