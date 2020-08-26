import mongoose from '..';

const sessionSchema = mongoose.Schema({
  id: Number,
  access_token: String,
  refresh_token: String,
  fingerprint: Number,
  expires_in: Date,
  created_at: Date,
  user_id: Number,
});

const Session = mongoose.model('Session', sessionSchema);

export default Session;
