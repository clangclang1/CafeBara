import cors from "cors";
import cookieParser from "cookie-parser";
import express from "express";
import 'dotenv/config';
import connectDB from "../back-end/config/db.js";
import authRouter from "./routes/authRoutes.js";


const app = express();
const port = process.env.PORT;

app.use(express.json());
app.use(cookieParser());
app.use(cors({credentials: true}));

//API ENDPOINTS
app.get('/', (req, res) => res.send('SERVER WORKING'));
app.use('/api/auth', authRouter);

app.listen(port, ()=>{
    connectDB();
    console.log("CLARECE STARTING TO CODE @5000");
})