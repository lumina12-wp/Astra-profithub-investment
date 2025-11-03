const express = require('express');
const jwt = require('jsonwebtoken');
const auth = require('../middleware/auth');
const User = require('../models/User');
const Transaction = require('../models/Transaction');
const Deposit = require('../models/Deposit');
const InvestmentPlan = require('../models/InvestmentPlan');
const Investment = require('../models/Investment');
const Withdrawal = require('../models/Withdrawal');
const DailySignin = require('../models/DailySignin');

const router = express.Router();

// Auth routes
const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN
  });
};

// Register
router.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Create user
    const user = await User.create({
      name,
      email,
      password
    });

    const token = signToken(user._id);

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
    res.status(400).json({ message: error.message });
  }
});

// Login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if email and password exist
    if (!email || !password) {
      return res.status(400).json({ message: 'Please provide email and password' });
    }

    // Check if user exists and password is correct
    const user = await User.findOne({ email }).select('+password');
    if (!user || !(await user.correctPassword(password, user.password))) {
      return res.status(401).json({ message: 'Incorrect email or password' });
    }

    const token = signToken(user._id);

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
    res.status(400).json({ message: error.message });
  }
});

// Logout
router.post('/logout', (req, res) => {
  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true
  });

  res.status(200).json({ status: 'success' });
});

// Protected route example
const protect = (req, res, next) => {
  let token;
  
  // Check header or body or cookie
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    return res.status(401).json({ message: 'You are not logged in! Please log in to get access.' });
  }

  // Verify token
  jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Token is invalid!' });
    }

    // Grant access to protected route
    req.user = await User.findById(decoded.id);
    next();
  });
};

// Get current user
router.get('/me', protect, (req, res) => {
  res.status(200).json({
    status: 'success',
    data: {
      user: {
        id: req.user._id,
        name: req.user.name,
        email: req.user.email,
        balance: req.user.balance,
        role: req.user.role
      }
    }
  });
});

// User routes
router.get('/profile', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.json({
      status: 'success',
      data: { user }
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Update user profile
router.put('/profile', auth, async (req, res) => {
  try {
    const { name, email } = req.body;
    const user = await User.findByIdAndUpdate(
      req.user.id,
      { name, email },
      { new: true, runValidators: true }
    ).select('-password');

    res.json({
      status: 'success',
      data: { user }
    });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

// Daily signin
router.post('/daily-signin', auth, async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    let signinRecord = await DailySignin.findOne({ user: req.user.id });

    if (!signinRecord) {
      // First time signing in
      signinRecord = await DailySignin.create({
        user: req.user.id,
        streakCount: 1,
        lastSignin: today,
        totalSignins: 1
      });

      // Add bonus for first signin
      await User.findByIdAndUpdate(req.user.id, {
        $inc: { balance: 1 } // 1 USDT bonus for first signin
      });

      return res.json({
        message: 'Daily signin successful! Streak: 1',
        bonus: 1,
        streak: 1
      });
    }

    const lastSignin = new Date(signinRecord.lastSignin);
    lastSignin.setHours(0, 0, 0, 0);

    const diffTime = today - lastSignin;
    const diffDays = Math.floor(diffTime / (1000 * 60 * 60 * 24));

    if (diffDays === 0) {
      return res.status(400).json({ message: 'Already signed in today' });
    }

    let bonus = 0;
    let newStreak = 1;

    if (diffDays === 1) {
      // Consecutive day
      newStreak = signinRecord.streakCount + 1;
      bonus = Math.min(newStreak, 5); // Max 5 USDT bonus per day
    }

    // Update signin record
    signinRecord.streakCount = newStreak;
    signinRecord.lastSignin = today;
    signinRecord.totalSignins += 1;
    await signinRecord.save();

    // Add bonus to balance
    if (bonus > 0) {
      await User.findByIdAndUpdate(req.user.id, {
        $inc: { balance: bonus }
      });
    }

    res.json({
      message: `Daily signin successful! Streak: ${newStreak}`,
      bonus,
      streak: newStreak
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Deposit routes
router.post('/deposits', auth, async (req, res) => {
  try {
    const { amount, planId } = req.body;

    // Validate amount against investment plans if planId is provided
    if (planId) {
      const plan = await InvestmentPlan.findById(planId);
      if (!plan) {
        return res.status(404).json({ message: 'Investment plan not found' });
      }
      if (amount !== plan.investmentAmount) {
        return res.status(400).json({ 
          message: `Amount must be exactly ${plan.investmentAmount} USDT for this plan` 
        });
      }
    }

    // Create transaction
    const transaction = await Transaction.create({
      user: req.user.id,
      type: 'deposit',
      amount,
      status: 'pending',
      description: `Deposit for ${planId ? 'investment' : 'wallet'}`
    });

    // Create deposit
    const deposit = await Deposit.create({
      user: req.user.id,
      amount,
      transaction: transaction._id,
      plan: planId || null
    });

    res.status(201).json({
      status: 'success',
      data: { 
        deposit,
        usdtWalletAddress: deposit.usdtWalletAddress,
        message: 'Please send exactly ' + amount + ' USDT to the address above'
      }
    });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

// Get user's deposits
router.get('/deposits', auth, async (req, res) => {
  try {
    const deposits = await Deposit.find({ user: req.user.id })
      .populate('transaction')
      .populate('plan')
      .sort({ createdAt: -1 });

    res.json({
      status: 'success',
      results: deposits.length,
      data: { deposits }
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Investment routes
router.get('/investment-plans', auth, async (req, res) => {
  try {
    const plans = await InvestmentPlan.find({ isActive: true }).sort({ investmentAmount: 1 });

    res.json({
      status: 'success',
      results: plans.length,
      data: { plans }
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Create investment
router.post('/investments', auth, async (req, res) => {
  try {
    const { planId } = req.body;

    const plan = await InvestmentPlan.findById(planId);
    if (!plan) {
      return res.status(404).json({ message: 'Investment plan not found' });
    }

    // Check if user has an approved deposit for this plan
    const deposit = await Deposit.findOne({
      user: req.user.id,
      plan: planId
    }).populate('transaction');

    if (!deposit || deposit.transaction.status !== 'approved') {
      return res.status(400).json({ 
        message: 'You need an approved deposit for this plan to start investing' 
      });
    }

    // Check if user already has an active investment for this plan
    const existingInvestment = await Investment.findOne({
      user: req.user.id,
      plan: planId,
      isActive: true
    });

    if (existingInvestment) {
      return res.status(400).json({ 
        message: 'You already have an active investment for this plan' 
      });
    }

    // Calculate end date
    const endDate = new Date();
    endDate.setDate(endDate.getDate() + plan.durationDays);

    const investment = await Investment.create({
      user: req.user.id,
      plan: planId,
      amount: plan.investmentAmount,
      endDate,
      isActive: true
    });

    // Create investment transaction
    await Transaction.create({
      user: req.user.id,
      type: 'investment',
      amount: plan.investmentAmount,
      status: 'approved',
      description: `Investment in ${plan.name}`
    });

    res.status(201).json({
      status: 'success',
      data: { investment }
    });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

// Get user's investments
router.get('/my-investments', auth, async (req, res) => {
  try {
    const investments = await Investment.find({ user: req.user.id })
      .populate('plan')
      .sort({ createdAt: -1 });

    res.json({
      status: 'success',
      results: investments.length,
      data: { investments }
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Withdrawal routes
router.post('/withdrawals', auth, async (req, res) => {
  try {
    const { amount, walletAddress } = req.body;

    if (!walletAddress) {
      return res.status(400).json({ message: 'Wallet address is required' });
    }

    if (amount < 5) {
      return res.status(400).json({ message: 'Minimum withdrawal amount is 5 USDT' });
    }

    // Check user balance
    const user = await User.findById(req.user.id);
    if (user.balance < amount) {
      return res.status(400).json({ message: 'Insufficient balance' });
    }

    // Create transaction
    const transaction = await Transaction.create({
      user: req.user.id,
      type: 'withdrawal',
      amount,
      status: 'pending',
      description: 'Withdrawal request'
    });

    // Create withdrawal
    const withdrawal = await Withdrawal.create({
      user: req.user.id,
      amount,
      transaction: transaction._id,
      walletAddress
    });

    // Deduct from user balance immediately
    user.balance -= amount;
    await user.save();

    res.status(201).json({
      status: 'success',
      data: { withdrawal },
      message: 'Withdrawal request submitted successfully'
    });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

// Get user's withdrawals
router.get('/withdrawals', auth, async (req, res) => {
  try {
    const withdrawals = await Withdrawal.find({ user: req.user.id })
      .populate('transaction')
      .sort({ createdAt: -1 });

    res.json({
      status: 'success',
      results: withdrawals.length,
      data: { withdrawals }
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Admin routes - Protect all admin routes with admin check
router.use('/admin', auth);
router.use('/admin', async (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Access denied. Admin only.' });
  }
  next();
});

// Get all transactions with user details
router.get('/admin/transactions', async (req, res) => {
  try {
    const transactions = await Transaction.find()
      .populate('user', 'name email')
      .sort({ createdAt: -1 });

    res.json({
      status: 'success',
      results: transactions.length,
      data: { transactions }
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Approve/deny transaction
router.post('/admin/transactions/action', async (req, res) => {
  try {
    const { transactionId, action } = req.body;

    if (!['approve', 'deny'].includes(action)) {
      return res.status(400).json({ message: 'Invalid action' });
    }

    const transaction = await Transaction.findById(transactionId)
      .populate('user');
    
    if (!transaction) {
      return res.status(404).json({ message: 'Transaction not found' });
    }

    if (action === 'approve') {
      transaction.status = 'approved';
      await transaction.save();

      // If it's a deposit, add balance to user with recharge bonus
      if (transaction.type === 'deposit') {
        const deposit = await Deposit.findOne({ transaction: transactionId })
          .populate('plan');
        
        if (deposit && deposit.plan) {
          const totalAmount = deposit.amount + deposit.plan.rechargeBonus;
          await User.findByIdAndUpdate(transaction.user._id, {
            $inc: { balance: totalAmount }
          });

          // Update transaction amount to include bonus
          transaction.amount = totalAmount;
          await transaction.save();
        } else {
          // Regular deposit without plan
          await User.findByIdAndUpdate(transaction.user._id, {
            $inc: { balance: transaction.amount }
          });
        }
      }

      res.json({ message: 'Transaction approved successfully' });
    } else {
      transaction.status = 'failed';
      await transaction.save();
      res.json({ message: 'Transaction denied' });
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get all users
router.get('/admin/users', async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ createdAt: -1 });

    res.json({
      status: 'success',
      results: users.length,
      data: { users }
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;