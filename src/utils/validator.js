export default class Validator {
  static email(email) {
    const emailRegExp = /\S+@\S+\.\S+/;

    return emailRegExp.test(email.toLowerCase());
  }

  static password(pass) {
    const minLength = 8;

    return pass.trim().length >= minLength;
  }
}
