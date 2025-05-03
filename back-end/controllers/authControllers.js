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