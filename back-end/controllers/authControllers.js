import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModels from '../models/userModels.js'

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

