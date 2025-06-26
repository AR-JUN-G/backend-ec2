const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

exports.register = async (req, res) => {
  const { name, email, password, role } = req.body;
  try {
    const exist = await User.findOne({ email });
    if (exist){
      console.log("User Already exists");
      return res.status(400).json({ msg: 'User already exists' });
    } 

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, email, password: hashedPassword, role: role || 'user' });
    await newUser.save();
    console.log("User Added Successfully");
    res.status(201).json({ msg: 'Registered successfully' });
  } catch (err) {
    res.status(500).json({ msg: err.message });
  }
};

exports.login = async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      console.log("Invalid User");
      return res.status(400).json({ msg: 'User not found' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch){
      console.log("Login Failed MisMatched Password");
      return res.status(400).json({ msg: 'Invalid password' });
    } 

    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    res.status(500).json({ msg: err.message });
  }
};
