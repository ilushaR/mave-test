import jwt from 'jsonwebtoken';
import User from '../database/models/user';

export default async function checkAuth(req, res, next) {
  const authHeaders = req.headers.authorization;
  const token = authHeaders && authHeaders.split(' ')[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_TOKEN);
    const user = await User.findOne({ id: decoded.id });

    if (!user) {
      return res.status(401).json({
        message: 'Authorization failed',
      });
    }

    if (!user.is_activated) {
      return res.status(403).json({
        message: 'User is not activated',
      });
    }

    req.user = user;
    return next();
  } catch (error) {
    console.error(error);

    return res.status(401).json({
      message: 'Authorization failed',
    });
  }
}
