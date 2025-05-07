import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModels from '../../models/userModels.js'
import transporter from '../nodemailer.js';
import { body, validationResult } from 'express-validator';

// Utility function for consistent error responses
const sendErrorResponse = (res, status, message) => {
    return res.status(status).json({ success: false, message });
};

export const register = async (req, res) =>{

    const validationRules = [
        body('firstName').notEmpty().withMessage('First name is required').isString(),
        body('lastName').notEmpty().withMessage('Last name is required').isString(),
        body('dateOfBirth').notEmpty().withMessage('Date of birth is required').isISO8601(),
        body('age').notEmpty().withMessage('Age is required').isInt({ min: 8 }).withMessage('Age must be at least 8 years old'),
        body('email').notEmpty().withMessage('Email is required').isEmail().withMessage('Invalid email format'),
        body('password').notEmpty().withMessage('Password is required')
        .isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
        .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
        .matches(/[!@#$%^&*()\-+_=<>?]/).withMessage('Password must contain at least one special character'),
        body('confirmPassword')
            .notEmpty().withMessage('Confirm password is required')
            .custom((value, { req }) => {
                if (value !== req.body.password) {
                    throw new Error('Confirm password does not match password');
                }
                return true;
            }),
    ];

    await Promise.all(validationRules.map(rule => rule.run(req)));

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return sendErrorResponse(res, 400, errors.array()[0].msg); // Return the first error
    }

    const {firstName, lastName, dateOfBirth, age, email, password} = req.body;

    try{
        const existingUser = await userModels.findOne({email});

        if(existingUser){
            return sendErrorResponse(res, 409, 'User already exists');
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new userModels({firstName, lastName, dateOfBirth, age,  email, password: hashedPassword});
        await user.save();

        const token = jwt.sign({id: user.id},process.env.JWT_SECRET, {expiresIn: '7d'});

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 1000
        });
        
        return res.status(201).json({success: true, message: "Successfully Registered"});
    }
    catch(error){
        console.error("Registration error:", error);
        return sendErrorResponse(res, 500, 'Internal server error');
    }

};

export const login = async (req, res) => {

    const validationRules = [
        body().custom(value => {
            if (!value.email && !value.password) {
                throw new Error('Email and Password are required');
            }
            return true;
        }),
        body('email').notEmpty().withMessage('Email is required').isEmail().withMessage('Invalid email format'),
        body('password').notEmpty().withMessage('Password is required'),
    ];

    await Promise.all(validationRules.map(rule => rule.run(req)));

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return sendErrorResponse(res, 400, errors.array()[0].msg);
    }

    const {email, password} = req.body;

    if(!email || !password){
        return res.json({success: false, message: 'Email and password are required'})
    }

    try{
        const user = await userModels.findOne({email});

        if(!user){
            return sendErrorResponse(res, 401, 'Invalid Email');
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if(!isMatch){
            return sendErrorResponse(res, 401, 'Invalid Password');
        }

        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: '7d'});

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 1000
        });

        return res.json({success: true, message: "Successfully Login"})        
    }
    catch(error){
        console.error("Login error:", error);
        return sendErrorResponse(res, 500, 'Internal server error');
    }
};

export const logout = async (req, res) => {
    try{
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        });

        return res.json({success: true, message: 'Logged Out'})

    }
    catch(error){
        console.error("Logout error:", error);
        return sendErrorResponse(res, 500, 'Internal server error');
    }
};

export const sendVerifyOtp = async (req, res) =>{

    const validationRules = [
        body('userId').notEmpty().withMessage('User ID is required').isString(),
    ];

    await Promise.all(validationRules.map(rule => rule.run(req)));

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return sendErrorResponse(res, 400, errors.array()[0].msg);
    }

    try{
        const {userId} = req.body;

        const user = await userModels.findById(userId);

        if (!user) {
            return sendErrorResponse(res, 404, 'User not found');
        }

        if(user.isAccountVerified){
            return sendErrorResponse(res, 400, 'Account is Already verified');
        }

        const otp = String(Math.floor( 100000 + Math.random() * 900000));   

        user.verifyOTP = otp;
        user.verifyOTPExpireAt = Date.now() + 2 * 60 * 1000

        await user.save();

        const mailOption = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: "CAFEBARA, Account Verification OTP",
            text: `Your otp ${otp} verify your account using this OTP.`
        }
        await transporter.sendMail(mailOption);

        res.json({success: true, message: 'Verification OTP sent on Email'});
    }
    catch(error){
        console.error("Send OTP error:", error);
        return sendErrorResponse(res, 500, 'Internal server error');
    }
};

export const verifyEmail = async (req, res) =>{

    const validationRules = [
        body('userId').notEmpty().withMessage('User ID is required').isString(),
        body('otp').notEmpty().withMessage('OTP is required').isString(),
    ];

    await Promise.all(validationRules.map(rule => rule.run(req)));

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return sendErrorResponse(res, 400, errors.array()[0].msg);
    };

    const {userId, otp} = req.body;

    try{
        const user = await userModels.findById(userId);

        if (!user) {
            return sendErrorResponse(res, 404, 'User not found');
        };

        if(user.verifyOTP === '' || user.verifyOTP !== otp){
            return sendErrorResponse(res, 400, 'Invalid OTP');
        }

        if(user.verifyOTPExpireAt < Date.now()){
            return sendErrorResponse(res, 400, 'OTP Expired');   
        }

        user.isAccountVerified = true;
        user.verifyOTP = '';
        user.verifyOTPExpireAt = undefined;

        await user.save();
        
        return res.json({success: true, message: 'Email Verified Successfully'});
    }
    catch(error){
        console.error("Verify Email error:", error);
        return sendErrorResponse(res, 500, 'Internal server error');
    }
};

export const isAuthenticated = async (req, res) => {

    const validationRules = [
        body('userId').notEmpty().withMessage('User ID is required').isString(),
    ];

    await Promise.all(validationRules.map(rule => rule.run(req)));

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return sendErrorResponse(res, 400, errors.array()[0].msg);
    }

    const { userId } = req.body; 

    try {
        const user = await userModels.findById(userId);

        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        if (!user.isAccountVerified) { 
            return res.status(401).json({ success: false, message: 'Account not verified' });
        }

        //  *Optional:* You might also want to check for things like:
        //  -  Account being active/enabled
        //  -  Session validity
        //  -  Token expiration

        return res.json({ success: true, message: 'Account is authenticated' });

    } catch (error) {
        console.error("Is Authenticated error:", error);
        return sendErrorResponse(res, 500, 'Internal server error');
    }
};

export const sendResetOtp = async (req, res) =>{

    const validationRules = [
        body('email').notEmpty().withMessage('Email is required').isEmail().withMessage('Invalid email format'),
     ];

     await Promise.all(validationRules.map(rule => rule.run(req)));

     const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return sendErrorResponse(res, 400, errors.array()[0].msg);
    };

    const {email} = req.body;

    try {
        const user = await userModels.findOne({email});

        if (!user) {
            return sendErrorResponse(res, 404, 'User not found');
        }

        const otp = String(Math.floor( 100000 + Math.random() * 900000 ));

        user.resetOTP = otp;
        user.resetOTPExpireAt = Date.now() + 2 * 60 * 1000;

        await user.save();

        const mailOption = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: "CAFEBARA, Password Reset OTP",
            text: `Your OTP for resetting your password is ${otp}.
            Use this OTP to proceed with resetting your password.`
        }
        await transporter.sendMail(mailOption);

        res.json({success: true, message: "OTP sent to your email"});

    } 
    catch(error) {
        console.error("Send Reset OTP error:", error);
        return sendErrorResponse(res, 500, 'Internal server error');
    }
};

export const resetPassword = async (req, res) =>{

    const validationRules = [
        body('email').notEmpty().withMessage('Email is required').isEmail().withMessage('Invalid email format'),
        body('otp').notEmpty().withMessage('OTP is required').isString(),
        body('newPassword')
        .notEmpty().withMessage('New Password is required')
        .isLength({min: 8}).withMessage('Password must be at least 8 characters long')
        .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
        .matches(/[!@#$%^&*()\-+_=<>?]/).withMessage('Password must contain at least one special character')
        .custom((value, { req }) => {
            if (value !== req.body.newPassword) {
                throw new Error('Confirm new password does not match new password');
            }
            return true;
        }),
    ];

    await Promise.all(validationRules.map(rule => rule.run(req)));

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
       return sendErrorResponse(res, 400, errors.array()[0].msg);
    }

    const {email, otp, newPassword} = req.body;

    try{
        const user = await userModels.findOne({email});

        if (!user) {
            return sendErrorResponse(res, 404, 'User not found');
        };
        
        if(user.resetOTP === "" || user.resetOTP !== otp){
            return sendErrorResponse(res, 400, 'Invalid OTP');
        };

        if(user.resetOTPExpireAt < Date.now()){
            return sendErrorResponse(res, 400, 'OTP Expired');
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        
        user.password = hashedPassword;
        user.resetOTP = '';
        user.resetOTPExpireAt = 0;

        await user.save();

        return res.json({success: true, message: "Password has been reset successfully"});
    }
    catch(error){
        console.error("Reset Password error:", error);
        return sendErrorResponse(res, 500, 'Internal server error');
    }
}