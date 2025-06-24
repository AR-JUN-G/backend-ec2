const nodemailer = require('nodemailer');

exports.sendLowStockEmail = async (productName, stockCount) => {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.ADMIN_EMAIL,
      pass: process.env.ADMIN_PASSWORD
    }
  });

  await transporter.sendMail({
    from: '"Derma Shop" <admin@example.com>',
    to: process.env.ADMIN_EMAIL,
    subject: 'Low Stock Alert',
    text: `Product "${productName}" is low on stock. Remaining: ${stockCount}`,
  });
};
