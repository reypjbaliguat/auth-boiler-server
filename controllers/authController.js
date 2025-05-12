const User = require("../models/User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const verifyGoogleToken = require("../utils/verifyGoogleToken");

const generateToken = (user) =>
  jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });

exports.register = async (req, res) => {
  const { email, password, name } = req.body;

  try {
    if (await User.findOne({ email })) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({ email, password: hashedPassword, name });

    const token = generateToken(user);
    res.status(201).json({ token, user: { id: user._id, email: user.email } });
  } catch {
    res.status(500).json({ message: "Server error" });
  }
};

exports.login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = generateToken(user);
    res.json({ token, user: { id: user._id, email: user.email } });
  } catch {
    res.status(500).json({ message: "Server error" });
  }
};

exports.googleLogin = async (req, res) => {
  const { credential } = req.body;

  try {
    const payload = await verifyGoogleToken(credential);
    const { email, name, sub: googleId } = payload;

    let user = await User.findOne({ email });
    if (!user) {
      user = await User.create({ email, name, googleId, provider: "google" });
    }

    const token = generateToken(user);
    res.json({ token, user: { id: user._id, email: user.email } });
  } catch {
    res.status(400).json({ message: "Invalid Google token" });
  }
};
