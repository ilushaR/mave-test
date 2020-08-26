import express from 'express';
import AuthController from '../controllers/auth';
import checkAuth from '../middlewares/check-auth';

const authRouter = express.Router();

authRouter.post('/register', AuthController.register);

authRouter.post('/login', AuthController.login);

authRouter.post('/logout', checkAuth, AuthController.logout);

authRouter.post('/activate', AuthController.activate);

authRouter.post('/forgot-password', AuthController.forgotPassword);

authRouter.post('/reset-password', AuthController.resetPassword);

authRouter.post('/refresh-tokens', checkAuth, AuthController.refreshTokens);

export default authRouter;
