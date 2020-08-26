import express from 'express';
import UserController from '../controllers/user';
import checkAuth from '../middlewares/check-auth';

const userRouter = express.Router();

userRouter.get('/:id', checkAuth, UserController.getById);

export default userRouter;
