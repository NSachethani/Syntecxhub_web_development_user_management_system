const express = require('express');
const User = require('../models/User');
const { basicAuth, requireAdmin } = require('../middleware/auth');

const router = express.Router();

router.post('/register', async (req, res) => {
  try {
    const { username, email, password, role } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ 
        error: 'Validation failed',
        message: 'Username, email, and password are required' 
      });
    }

    const existingUser = await User.findOne({ 
      $or: [{ username }, { email }] 
    });
    if (existingUser) {
      return res.status(400).json({ 
        error: 'User exists',
        message: 'Username or email already registered' 
      });
    }

    const user = new User({ 
      username, 
      email, 
      password,
      role: role || 'user'
    });
    await user.save();

    res.status(201).json({
      message: 'User created successfully',
      user
    });
  } catch (error) {
    if (error.name === 'ValidationError') {
      return res.status(400).json({ 
        error: 'Validation failed',
        message: Object.values(error.errors).map(e => e.message).join(', ') 
      });
    }
    res.status(500).json({ error: 'Server error', message: error.message });
  }
});

router.get('/', basicAuth, requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, search, role, isActive } = req.query;
    const query = {};

    if (search) {
      query.$or = [
        { username: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ];
    }
    if (role) query.role = role;
    if (isActive !== undefined) query.isActive = isActive === 'true';

    const users = await User.find(query)
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await User.countDocuments(query);

    res.json({
      users,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error', message: error.message });
  }
});

router.get('/me', basicAuth, async (req, res) => {
  res.json({ user: req.user });
});

router.get('/:id', basicAuth, async (req, res) => {
  try {
    if (req.user.role !== 'admin' && req.user._id.toString() !== req.params.id) {
      return res.status(403).json({ 
        error: 'Forbidden',
        message: 'Not authorized to access this user' 
      });
    }

    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'Not found', message: 'User not found' });
    }

    res.json({ user });
  } catch (error) {
    if (error.name === 'CastError') {
      return res.status(400).json({ error: 'Invalid ID', message: 'Invalid user ID format' });
    }
    res.status(500).json({ error: 'Server error', message: error.message });
  }
});

router.put('/:id', basicAuth, async (req, res) => {
  try {
    if (req.user.role !== 'admin' && req.user._id.toString() !== req.params.id) {
      return res.status(403).json({ 
        error: 'Forbidden',
        message: 'Not authorized to update this user' 
      });
    }

    const { username, email, password, role, isActive } = req.body;
    const updateData = {};

    if (username) updateData.username = username;
    if (email) updateData.email = email;
    if (password) updateData.password = password;
    if (role && req.user.role === 'admin') updateData.role = role;
    if (isActive !== undefined && req.user.role === 'admin') updateData.isActive = isActive;

    const user = await User.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true, runValidators: true }
    );

    if (!user) {
      return res.status(404).json({ error: 'Not found', message: 'User not found' });
    }

    res.json({ message: 'User updated successfully', user });
  } catch (error) {
    if (error.name === 'ValidationError') {
      return res.status(400).json({ 
        error: 'Validation failed',
        message: Object.values(error.errors).map(e => e.message).join(', ') 
      });
    }
    if (error.name === 'CastError') {
      return res.status(400).json({ error: 'Invalid ID', message: 'Invalid user ID format' });
    }
    if (error.code === 11000) {
      return res.status(400).json({ 
        error: 'Duplicate entry',
        message: 'Username or email already exists' 
      });
    }
    res.status(500).json({ error: 'Server error', message: error.message });
  }
});

router.delete('/:id', basicAuth, requireAdmin, async (req, res) => {
  try {
    if (req.user._id.toString() === req.params.id) {
      return res.status(400).json({ 
        error: 'Bad request',
        message: 'Cannot delete your own account' 
      });
    }

    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'Not found', message: 'User not found' });
    }

    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    if (error.name === 'CastError') {
      return res.status(400).json({ error: 'Invalid ID', message: 'Invalid user ID format' });
    }
    res.status(500).json({ error: 'Server error', message: error.message });
  }
});

module.exports = router;