const Order = require('../models/Order');

const cleanOldOrders = async () => {
  const cutoff = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  await Order.deleteMany({ createdAt: { $lt: cutoff } });
  console.log('🧹 Old orders cleaned');
};

module.exports = cleanOldOrders;
