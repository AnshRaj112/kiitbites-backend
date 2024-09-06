const crypto = require('crypto')
const { promisify } = require('util')
const jwt = require('jsonwebtoken')
const User = require('./../models/userModal')
const catchAsync = require('./../utils/catchAsync')
const AppError = require('./../utils/appError')
const sendEmail = require('./../utils/email')

const signToken = id => {
    return jwt.sign({ id }, process.env.JSON_SECRET,{
        expiresIn: process.env.JWT_EXPIRES
    });
};

const createSendToken = (user, statusCode, res)=>{
    const token = signToken(user._id);
    const cookieOptions = {
      expires: new Date(
        Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
      ),
      httpOnly: true
    };
    if (process.env.NODE_ENV === 'production') cookieOptions.secure = true;
  
    res.cookie('jwt', token, cookieOptions);

    user.password = undefined;

    res.status(statusCode).json({
        status: 'success',
        token,
        data:{
            user
        }  
    })
}
exports.signup = catchAsync(async (req, res, next)=>{

    const newUser = await User.create({
        name: req.body.name,
        email: req.body.email,
        password: req.body.password,
        passwordConfirm: req.body.passwordConfirm
    });

    createSendToken(newUser, 201, res);
});

exports.login = catchAsync(async (req, res, next) => {
    const { email, password } = req.body;

    if(!email || !password){
       return next(new AppError('Please provide email and password!', 400))
    }

    const user = await User.findOne({ email }).select('+password');
 
    if(!user || !await user.correctPassword(password,user.password)){
        return next(new AppError('Incorrect email or password!!', 401))
    }

    createSendToken(user, 200, res);
});

exports.restricTo = (...roles) => {
    return (req,res,next) => {
        if(!roles.includes(req.user.role)){
            return next(
                new AppError("You do not have the permission to perform this. ",403)
            )
        }
        next();
    }
}

exports.forgotPassword = catchAsync(async (req, res, next) => {
    const user = await User.findOne({email: req.body.email});
    if(!user){
        return next(new AppError("There is no user with this email..",404));
    }

        const resetToken = user.createPassResetToken();
        await user.save({ validateBeforeSave: false });
    

    const resetURL = `${req.protocol}://${req.get('host')}/users/resetPassword/${resetToken}`;

    const message = `Forgot your password reset it!${resetURL}`
    try{
    await sendEmail({
        email: user.email,
        subject: 'Your password reset',
        message
    });

    res.status(200).json({
        status: 'success',
        message: 'Token reset'
    });

    }catch(err){
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        await user.save({ validateBeforeSave: false });

        return next(new AppError("Couldn't send the emails(Problem)!!",500));
    }
    
})

exports.resetPassword = catchAsync(async(req,res,next) => {
    const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');
    const user = await User.findOne({passwordResetToken: hashedToken,passwordResetExpires: {$gt: Date.now()}});

    if(!user){
        return next(new AppError("Reset token is invalid or expired",400));
    }
    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();


    createSendToken(user, 200, res);
});

exports.updatePassword = catchAsync(async(req,res,next)=>{
    const user = await User.findById(req.user.id).select('+password');

    if (!await user.correctPassword(req.body.passwordCurrent, user.password)) {
        return next(new AppError('Your current password is wrong.', 401));
    }

    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    await user.save();

    createSendToken(user, 200, res);
});

exports.protect = catchAsync(async (req, res, next) => {
    let token;
    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith('Bearer')
    ) {
      token = req.headers.authorization.split(' ')[1];
    }
  
    if (!token) {
      return next(
        new AppError('You are not logged in! Please log in to get access.', 401)
      );
    }

    const decoded = await promisify(jwt.verify)(token, process.env.JSON_SECRET);

    const currentUser = await User.findById(decoded.id);
    if (!currentUser) {
      return next(
        new AppError(
          'The user belonging to this token does no longer exist.',
          401
        )
      );
    }
  
    if (currentUser.changedPasswordAfter(decoded.iat)) {
      return next(
        new AppError('User recently changed password! Please log in again.', 401)
      );
    }

    req.user = currentUser;
    next();
  });