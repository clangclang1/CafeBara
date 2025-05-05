import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModels from '../../models/userModels.js'
import transporter from '../nodemailer.js';

export const register = async (req, res) =>{

    const {firstName, lastName, dateOfBirth, age, email, password} = req.body;

    if(!firstName || !lastName || !dateOfBirth || !age || !email || !password){
        return res.json({success: false, message: 'Missing Details'})
    }

    try{
        const existingUser = await userModels.findOne({email});

        if(existingUser){
            return res.json({success: false, message: 'User already exists'})
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
        })
        
        return res.json({success: true, message: "Successfully Registered"})

    }
    catch(error){
        res.json({success: false, message: error.message});
    }

}

export const login = async (req, res) => {
    const {name, email, password} = req.body;

    if(!email || !password){
        return res.json({success: false, message: 'Email and password are required'})
    }

    try{
        const user = await userModels.findOne({email});

        if(!user){
            return res.json({success: false, message: 'Invalid Email'})
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if(!isMatch){
            return res.json({success: false, message: 'Invalid Password'})
        }

        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: '7d'});

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 1000
        })

        return res.json({success: true, message: "Successfully Login"})        
    }
    catch(error){
        res.json({success: false, message: error.message});
    }
}

export const logout = async (req, res) => {
    try{
        res.cookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 1000
        })

        return res.json({success: false, message: 'Logged Out'})

    }
    catch(error){
        res.json({success: false, message: error.message});
    }
}

export const sendVerifyOtp = async (req, res) =>{
    try{
        const {userId} = req.body;

        const user = await userModels.findById(userId);

        if(user.isAccountVerified){
            return res.json({success: false, message: "Account is Already verified"});
        }

        const otp = String(Math.floor( 100000 + Math.random() * 900000));   

        user.verifyOTP = otp;
        user.verifyOTPExpireAt = Date.now() + 24 * 60 * 60 * 1000

        await user.save();

        const mailOption = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: "Account Verification OTP",
            text: `Your otp ${otp} verify your account using this OTP.`
        }
        await transporter.sendMail(mailOption);

        res.json({success: true, message: 'Verification OTP sent on Email'});
    }
    catch(error){
        res.json({success: false, message: error.message});
    }
}

export const verifyEmail = async (req, res) =>{
    const {userId, otp} = req.body;

    if(!userId || !otp){
        res.json({success: false, message: 'Missing Details'});
    }

    try{
        const user = await userModels.findById(userId);

        if(!user){
           return res.json({success: false, message: 'User not found'});
        }

        if(user.verifyOTP === '' || user.verifyOTP !== otp){
            return res.json({success: false, message: 'Invalid OTP'});
        }

        if(user.verifyOTPExpireAt < Date.now()){
            return res.json({success: false, message: 'OTP Expired'});   
        }

        user.isAccountVerified = true;
        user.verifyOTP = '';
        user.verifyOTPExpireAt;

        await user.save();
        
        return res.json({success: true, message: 'Email Verified Successfully'});
    }
    catch(error){
        res.json({success: false, message: error.message})
    }
}

export const isAuthenticated = async (req, res) => {
    const { userId } = req.body; // Or however you're getting the user's identity

    if (!userId) {
        return res.status(400).json({ success: false, message: 'Missing user ID' }); 
    }

    try {
        const user = await userModels.findById(userId);

        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        //  *Important:* Check the appropriate field for authentication status
        if (!user.isAccountVerified) { 
            return res.status(401).json({ success: false, message: 'Account not verified' });
        }

        //  *Optional:* You might also want to check for things like:
        //  -  Account being active/enabled
        //  -  Session validity
        //  -  Token expiration

        return res.json({ success: true, message: 'Account is authenticated' });

    } catch (error) {
        res.json({success: false, message: error.message}); //  Important:  Handle errors!
    }
};

export const sendResetOtp = async (req, res) =>{
    const {email} = req.body;

    if(!email){
        return res.json({success: false, message: 'Email is required'});
    }

    try {
        const user = await userModels.findOne({email});

        if(!user){
            return res.json({success: false, message: 'User not found'});
        }

        const otp = String(Math.floor( 100000 + Math.random() * 900000 ));

        user.resetOTP = otp;
        user.resetOTPExpireAt = Date.now() + 15 * 60 * 60 * 1000;

        await user.save();

        const mailOption = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: "Password Reset OTP",
            text: `Your OTP for resetting your password is ${otp}.
            Use this OTP to proceed with resetting your password.`
        }
        await transporter.sendMail(mailOption);

        res.json({success: true, message: "OTP sent to your email"});

    } 
    catch(error) {
        res.json({success: false, message: error.message});
    }
}

export const resetPassword = async (req, res) =>{
    const {email, otp, newPassword} = req.body;

    if(!email || !otp || !newPassword){
        return res.json({success: false, message: "Email, OTP and New Password are required"});
    }

    try{
        const user = await userModels.findOne({email});

        if(!user){
            return res.json({success: false, message: "User not found"});
        }
        
        if(user.resetOTP === "" || user.resetOTP !== otp){
            return res.json({success: false, message: "Invalid OTP"});
        }

        if(user.resetOTPExpireAt < Date.now()){
            return res.json({success: false, message: "OTP Expired"});
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        
        user.password = hashedPassword;
        user.resetOTP = '';
        user.resetOTPExpireAt = 0;

        await user.save();

        return res.json({success: true, message: "Password has been reset successfully"});
    }
    catch(error){
        res.json({success: false, message: error.message});
    }
}