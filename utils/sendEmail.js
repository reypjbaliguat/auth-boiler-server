const nodemailer = require('nodemailer');

const sendEmail = async (to, subject, text) => {
    const transporter = nodemailer.createTransport({
        service: 'Gmail',
        auth: {
            user: process.env.SMTP_EMAIL,
            pass: process.env.SMTP_PASS,
        },
    });
    console.log({ to, subject, text });
    const res = await transporter.sendMail({
        from: process.env.SMTP_EMAIL,
        to,
        subject,
        text,
    });
    console.log('Email sent:', res);
};

module.exports = sendEmail;
