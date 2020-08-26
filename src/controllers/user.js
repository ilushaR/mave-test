import User from '../database/models/user';

export default class UserController {
  static async getById(req, res) {
    const { id } = req.params;
    const user = await User.findOne({ id });

    if (!user) {
      return res.status(404).json({
        message: 'User is not found',
      });
    }

    return res.json({
      message: 'User info',
      id,
      name: user.name,
      email: user.email,
    });
  }
}
