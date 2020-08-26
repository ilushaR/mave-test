import mongoose from '..';

const userSchema = mongoose.Schema({
  id: Number,
  name: String,
  email: String,
  password: String,
  is_activated: Boolean,
  activation_code: String,
  reset_code: String,
  reset_code_expires_in: Date,
});

const User = mongoose.model('User', userSchema);

export default User;
