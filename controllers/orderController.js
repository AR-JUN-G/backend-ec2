const Order = require('../models/Order');

//const Order = require('../models/Order');

const Product = require('../models/Product'); // Make sure you import Product
// const { sendLowStockEmail } = require('../utils/mailer'); // Optional email alerts

exports.placeOrder = async (req, res) => {
  try {
    const { items, totalAmount, shippingAddress } = req.body;

    // ✅ Check user authentication
    if (!req.user || !req.user._id) {
      return res.status(401).json({ msg: "Unauthorized. Please login again." });
    }

    // ✅ Basic validation
    if (!items || items.length === 0) {
      return res.status(400).json({ msg: "No items in order" });
    }

    const formattedItems = [];

    for (const item of items) {
      const product = await Product.findById(item.productId);
      if (!product) return res.status(404).json({ msg: "Product not found" });

      if (product.stock < item.quantity) {
        return res.status(400).json({ msg: `Not enough stock for ${product.name}` });
      }

      // ✅ Deduct stock
      product.stock -= item.quantity;

      if (product.stock <= 2) {
        console.warn(`⚠️ Low stock for ${product.name}: ${product.stock}`);
        // Optionally send email alert:
        // await sendLowStockEmail(product.name, product.stock);
      }

      await product.save();

      formattedItems.push({
        product: item.productId,
        quantity: item.quantity
      });
    }

    const newOrder = new Order({
      user: req.user._id,
      items: formattedItems,
      totalAmount,
      shippingAddress,
    });

    await newOrder.save();

    console.log("✅ Order saved successfully");
    console.log("📦 Items:", items);
    console.log("📍 Shipping Address:", shippingAddress);
    console.log("💰 Total Amount:", totalAmount);
    console.log("👤 User ID:", req.user._id);

    res.status(201).json({ msg: 'Order placed', order: newOrder });
  } catch (err) {
    console.error("❌ Error placing order:", err);
    res.status(500).json({ msg: "Failed to place order" });
  }
};


exports.getMyOrders = async (req, res) => {
  try {
    const orders = await Order.find({ user: req.user._id }).sort({ createdAt: -1 });
    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get orders' });
  }
};


exports.getAllOrders = async (req, res) => {
  try {
    const last30Days = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

    const orders = await Order.find({
      createdAt: { $gte: last30Days }
    })
      .populate('user', 'name email')         // ✅ Get user name and email
      .populate('items.product', 'name price') // ✅ Get product name and price
      .sort({ createdAt: -1 });

    res.json(orders);
  } catch (err) {
    res.status(500).json({ msg: 'Failed to fetch orders', error: err.message });
  }
};

// controllers/orderController.js

exports.requestOrderCancel = async (req, res) => {
  try {
    const order = await Order.findById(req.params.id);

    if (!order) return res.status(404).json({ msg: "Order not found" });

    if (order.user.toString() !== req.user._id.toString()) {
      return res.status(403).json({ msg: "Not authorized to cancel this order" });
    }

    order.cancelRequest = true;
    await order.save();

    res.json({ msg: "Cancellation requested" });
  } catch (err) {
    res.status(500).json({ msg: err.message });
  }
};

exports.approveCancel = async (req, res) => {
  try {
    const order = await Order.findById(req.params.id);
    if (!order || !order.cancelRequest) return res.status(404).json({ msg: "No cancel request" });

    order.cancelApproved = true;
    order.status = "Cancelled";
    await order.save();

    res.json({ msg: "Order cancelled by admin" });
  } catch (err) {
    res.status(500).json({ msg: err.message });
  }
};

