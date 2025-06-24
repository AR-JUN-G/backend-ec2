const mongoose = require('mongoose');

const productSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  price: {
    type: Number,
    required: true,
  },
  description: String,
  image: String,
  stock: {
    type: Number,
    required: true,
    default: 10, // You can adjust the default as needed
  },
}, { timestamps: true }); // Optional: adds createdAt and updatedAt

module.exports = mongoose.model('Product', productSchema);
