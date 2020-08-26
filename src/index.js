import 'dotenv/config';
import express from 'express';
import cookieParser from 'cookie-parser';
import authRouter from './routes/auth';
import userRouter from './routes/user';
import './database';

const app = express();

app.use(express.json());
app.use(cookieParser());
app.use('/auth', authRouter);
app.use('/user', userRouter);

app.listen(8080, console.log('Server is listening 🎉'));
