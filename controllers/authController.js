const User = require('../models/userModel');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const sendEmail = require('../utils/sendEmail');
const generateToken = require('../utils/generateToken');

exports.register = async (req, res) => {
  const { name, email, password, role, branch } = req.body;

  const userExists = await User.findOne({ email });
  if (userExists) return res.status(400).json({ message: "User already exists" });

  const user = await User.create({ name, email, password, role, branch });

  if (user) {
    res.status(201).json({
      _id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      token: generateToken(user._id, user.role),
    });
  } else {
    res.status(400).json({ message: "Invalid user data" });
  }
};

// Login user
exports.login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email }).select("+password"); 
    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const isMatch = await user.matchPassword(password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    res.status(200).json({
      message: "Login successful",
      token: generateToken(user._id, user.role),
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Get all users (only Super Admin & Branch Manager)
exports.getUsers = async (req, res) => {
  const users = await User.find();
  res.json(users);
};

// Update user role/branch
exports.updateUser = async (req, res) => {
  const user = await User.findById(req.params.id);
  if (!user) return res.status(404).json({ message: "User not found" });

  user.role = req.body.role || user.role;
  user.branch = req.body.branch || user.branch;
  user.isActive = req.body.isActive !== undefined ? req.body.isActive : user.isActive;

  await user.save();
  res.json({ message: "User updated successfully", user });
};

// Soft delete (deactivate)
exports.deactivateUser = async (req, res) => {
  const user = await User.findById(req.params.id);
  if (!user) return res.status(404).json({ message: "User not found" });

  user.isActive = false;
  await user.save();
  res.json({ message: "User deactivated" });
};

exports.forgotPassword = async (req, res) => {
    const user = await User.findOne({ email: req.body.email });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const resetToken = user.generateResetToken();
    await user.save({ validateBeforeSave: false });

    const resetUrl = `${req.protocol}://${req.get('host')}/api/auth/reset-password/${resetToken}`;
    const message = `<p>Click <a href="${resetUrl}">here</a> to reset your password. This link expires in 10 minutes.</p>`;

    try {
        await sendEmail(user.email, 'Password Reset', message);
        res.status(200).json({ message: 'Reset email sent' });
    } catch (err) {
        user.resetPasswordToken = undefined;
        user.resetPasswordExpire = undefined;
        await user.save({ validateBeforeSave: false });
        res.status(500).json({ error: 'Email failed to send' });
    }
};

exports.updateRole = async (req, res) => {
  try {
    const { id } = req.params;
    const updates = { ...req.body };

    // Prevent non-admin from updating role (extra safety)
    if (
      updates.role &&
      req.user.role !== "super_admin" &&
      req.user.role !== "admin"
    ) {
      delete updates.role; // remove role if unauthorized
    }

    const user = await User.findByIdAndUpdate(id, updates, {
      new: true,
      runValidators: true,
    }).select("-password");

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(user);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.resetPassword = async (req, res) => {
    try {
        if (!req.body.password) {
            return res.status(400).json({ error: 'Password is required' });
        }

        const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');
        const user = await User.findOne({
            resetPasswordToken: hashedToken,
            resetPasswordExpire: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ error: 'Token is invalid or has expired' });
        }

        user.password = await bcrypt.hash(req.body.password, 10);
        user.resetPasswordToken = undefined;
        user.resetPasswordExpire = undefined;
        await user.save();

        res.status(200).json({ message: 'Password reset successful' });
    } catch (error) {
        console.error('Reset error:', error);
        res.status(500).json({ error: 'Server error' });
    }
};


