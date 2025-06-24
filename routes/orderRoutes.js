const express = require('express');
const { placeOrder, getMyOrders, getAllOrders, updateOrderStatus,
  requestOrderCancel, 
  approveCancel  } = require('../controllers/orderController');
const { protect, admin } = require('../middleware/authMiddleware');
const router = express.Router();

router.post('/', protect, placeOrder);
router.get('/my', protect, getMyOrders);
router.get('/', protect, admin, getAllOrders);
router.put("/:id/cancel-request", protect, requestOrderCancel);
router.put("/:id/cancel-approve", protect, admin, approveCancel);


module.exports = router;
