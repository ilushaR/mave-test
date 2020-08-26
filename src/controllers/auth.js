import bcrypt from 'bcrypt';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import User from '../database/models/user';
import Session from '../database/models/session';
import Validator from '../utils/validator';
import SMTPProvider from '../email';

export default class AuthController {
  static async register(req, res) {
    const { name, email, password } = req.body;

    if (!Validator.email(email)) {
      return res.status(400).json({
        message: 'Email is not valid',
      });
    }

    if (!Validator.password(password)) {
      return res.status(400).json({
        message: 'Password must be not shorter than 8 symbols',
      });
    }

    const user = await User.findOne({ email });

    if (user) {
      return res.status(422).json({
        message: 'You are already authorized',
      });
    }

    try {
      const hashed_password = await bcrypt.hash(password, 10);
      const id = (await User.find()).length + 1;
      const activation_code = uuidv4();

      const new_user = new User({
        id,
        name,
        email,
        password: hashed_password,
        is_activated: false,
        activation_code,
      });

      await new_user.save();

      const link = `http://localhost:8080/auth/activate?code=${activation_code}`;

      await SMTPProvider.send(email, 'Account verification', `Click link to get verified ${link}`);

      return res.status(201).json({
        message: 'User created',
        id,
        name,
        email,
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        message: error,
      });
    }
  }

  static async login(req, res) {
    const { email, password, fingerprint } = req.body;

    if (!Validator.email(email)) {
      return res.status(409).json({
        message: 'Email is not valid',
      });
    }

    if (!Validator.password(password)) {
      return res.status(422).json({
        message: 'Password must be not shorter than 8 symbols',
      });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({
        message: 'Authorization failed',
      });
    }

    const is_valid_password = await bcrypt.compare(password, user.password);

    if (!is_valid_password) {
      return res.status(401).json({
        message: 'Authorization failed',
      });
    }

    const id = (await Session.find()).length + 1;
    const access_token = jwt.sign({ id: user.id, name: user.name, email }, process.env.JWT_ACCESS_TOKEN, { expiresIn: '15m' });
    const refresh_token = uuidv4();
    const millisecondsInMonth = 1000 * 60 * 60 * 24 * 30;
    const expires_in = new Date(Date.now() + millisecondsInMonth);

    const new_session = new Session({
      id,
      access_token,
      refresh_token,
      fingerprint,
      expires_in,
      created_at: new Date(),
      user_id: user.id,
    });

    await new_session.save();

    res.cookie('refresh_token', refresh_token, {
      path: '/auth',
      maxAge: millisecondsInMonth,
      httpOnly: true,
      secure: true,
    });

    return res.json({
      message: 'Authorization successful',
      access_token,
      refresh_token,
    });
  }

  static async logout(req, res) {
    const { refresh_token } = req.cookies;
    const { user } = req;

    const session = await Session.findOne({ refresh_token, user_id: user.id });

    if (!session) {
      return res.status(403).json({
        message: 'Session error',
      });
    }

    await session.deleteOne();

    return res.json({
      message: 'Session delete',
    });
  }

  static async activate(req, res) {
    const activation_code = req.query.code;
    const activated_user = await User.findOne({ activation_code });

    if (!activated_user) {
      return res.status(400).json({
        message: 'Bad request',
      });
    }

    if (activated_user.is_activated) {
      return res.json({
        message: 'User is already activated',
      });
    }

    const is_activated = true;

    await activated_user.updateOne({
      is_activated,
      $unset: { activation_code: 1 },
    });

    return res.json({
      message: 'User is activated',
    });
  }

  static async forgotPassword(req, res) {
    const { email } = req.body;

    if (!Validator.email(email)) {
      return res.status(409).json({
        message: 'Email is not valid',
      });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({
        message: 'User is not found',
      });
    }

    const reset_code = crypto.randomBytes(3).toString('hex');
    const millisecondsInMinute = 1000 * 60;
    const reset_code_expires_in = new Date(Date.now() + 5 * millisecondsInMinute);

    await user.updateOne({
      reset_code,
      reset_code_expires_in,
    });

    await SMTPProvider.send(email, 'Reset password', `Reset code ${reset_code}`);

    return res.json({
      message: 'Reset password',
    });
  }

  static async resetPassword(req, res) {
    const { reset_code, new_password, email } = req.body;

    if (!Validator.password(new_password)) {
      return res.status(422).json({
        message: 'Password must be not shorter than 8 symbols',
      });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({
        message: 'User is not found',
      });
    }

    if (reset_code !== user.reset_code) {
      return res.status(422).json({
        message: 'Wrong code',
      });
    }

    if (Date.now() > user.reset_code_expires_in) {
      return res.status(410).json({
        message: 'Code expires',
      });
    }

    const sessions = await Session.find({ user_id: user.id });
    sessions.forEach(session => session.deleteOne());

    const hashed_password = await bcrypt.hash(new_password, 10);

    await user.updateOne({
      password: hashed_password,
      $unset: { reset_code: 1, reset_code_expires_in: 1 },
    });

    return res.json({
      message: 'Reset password',
    });
  }

  static async refreshTokens(req, res) {
    const { refresh_token } = req.cookies;
    const { fingerprint } = req.body;
    const { user } = req;

    const session = await Session.findOne({ refresh_token });

    if (!session || user.id !== session.user_id || fingerprint !== session.fingerprint) {
      return res.status(403).json({
        message: 'Refresh tokens error',
      });
    }

    const new_access_token = jwt.sign({ id: user.id, name: user.name, email: user.email }, process.env.JWT_ACCESS_TOKEN, { expiresIn: '15m' });
    const new_refresh_token = Date.now() < session.expires_in ? session.refresh_token : uuidv4();

    const millisecondsInMonth = 1000 * 60 * 60 * 24 * 30;
    const expires_in = new Date(Date.now() + millisecondsInMonth);

    await session.updateOne({
      access_token: new_access_token,
      refreshTokens: new_refresh_token,
      created_at: new Date(),
      expires_in,
    });

    res.cookie('refresh_token', new_refresh_token, {
      path: '/auth',
      maxAge: millisecondsInMonth,
      httpOnly: true,
      secure: true,
    });

    return res.json({
      message: 'Refresh tokens',
      access_token: new_access_token,
      refresh_token: new_refresh_token,
    });
  }
}
