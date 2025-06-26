const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const connectDB = require('./config');
const cleanOldOrders = require('./utils/cleanOldOrders');

dotenv.config();
connectDB();

const app = express();
app.use(cors({
  origin: 'https://dermasolutionclient-1.onrender.com', 
  credentials: true
}));

// Routes
app.use('/api/auth', require('./routes/authRoutes'));
app.use('/api/products', require('./routes/productRoutes'));
app.use('/api/orders', require('./routes/orderRoutes'));

setInterval(cleanOldOrders, 24 * 60 * 60 * 1000); // run daily

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
