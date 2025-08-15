const express = require('express');
const router = express.Router();
const auth = require('../middleware/authMiddleware');
const {
    register,
    login,
    googleLogin,
    verifyOtp,
} = require('../controllers/authController');

router.post('/register', register);
router.post('/verify-otp', verifyOtp);
router.post('/login', login);
router.post('/google', googleLogin);
router.get('/me', auth, (req, res) => {
    res.json({ message: 'Protected route', userId: req.user.id });
});

module.exports = router;
