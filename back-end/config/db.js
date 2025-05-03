import mongoose from "mongoose";

const connectDB = async () =>{
    try {
        const con = await mongoose.connect(process.env.MONGO_URI);
        console.log("DB CONNECTED");
    } catch (error) {
        console.log(error);
    }
}

export default connectDB;