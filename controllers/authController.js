const User = require('../models/User');
const Otp = require('../models/Otp');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const verifyGoogleToken = require('../utils/verifyGoogleToken');
const generateOtp = require('../utils/generateOtp');
const sendEmail = require('../utils/sendEmail');

const generateToken = (user) =>
    jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

exports.register = async (req, res) => {
    const { email, password } = req.body;

    try {
        const existingUser = await User.findOne({ email });

        // check if user exists and is verified or is google user
        if (
            existingUser &&
            (existingUser.provider === 'google' || existingUser.verified)
        ) {
            return res.status(400).send({ message: 'User already exists' });
        }
        // send otp to email
        const code = generateOtp();
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

        await Otp.create({ email, code, expiresAt });
        await sendEmail(email, 'OTP for verification', `Your OTP is ${code}`);

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await User.create({
            email,
            password: hashedPassword,
        });
        res.status(201).send({
            user: {
                id: user._id,
                email: user.email,
                verified: user.verified,
            },
            message: 'OTP sent to email',
        });
    } catch {
        res.status(500).send({ message: 'Server error' });
    }
};

exports.login = async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).send({ message: 'Invalid credentials' });
        }

        const token = generateToken(user);
        res.send({ token, user: { id: user._id, email: user.email } });
    } catch {
        res.status(500).send({ message: 'Server error' });
    }
};

exports.googleLogin = async (req, res) => {
    const { credential } = req.body;

    try {
        const payload = await verifyGoogleToken(credential);
        const { email, name, sub: googleId } = payload;
        console.log(payload);
        let user = await User.findOne({ email });
        if (!user) {
            user = await User.create({
                email,
                name,
                googleId,
                provider: 'google',
            });
        }

        const token = generateToken(user);
        res.send({ token, user: { id: user._id, email: user.email } });
    } catch {
        res.status(400).send({ message: 'Invalid Google token' });
    }
};
