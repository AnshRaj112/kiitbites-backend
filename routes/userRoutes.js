const express = require('express');
const authController = require('../Controllers/authController')


const router = express.Router();

router.post('/signup', authController.signup);
router.post('/login', authController.login);
router.post('/forgotpassword', authController.forgotPassword);
router.patch('/resetpassword/:token', authController.resetPassword);
router.patch('/updateMyPassword',authController.protect, authController.updatePassword);


module.exports = router;
