import nodemailer from 'nodemailer';

export default class SMTPProvider {
  constructor() {
    this.config = {
      host: 'smtp.ethereal.email',
      port: 587,
      auth: {
        user: 'devante.cassin23@ethereal.email',
        pass: 'fwaw5S6akzdNSPTthq',
      },
    };

    this.transporter = nodemailer.createTransport(this.config);
  }

  async send(to, subject, text) {
    const mailOptions = {
      from: this.config.auth.user,
      to,
      subject,
      text,
    };

    await this.transporter.sendMail(mailOptions);
  }
}
