const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/User");

router.post("/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);

    const newUser = new User({ username, email, password: hash });
    await newUser.save();
    res.status(201).json("User created");
  } catch (err) {
    res.status(500).json(err.message);
  }
});

router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json("Invalid email or password");

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json("Invalid email or password");

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });

    res.status(200).json({ user: { id: user._id, username: user.username }, token });
  } catch (err) {
    res.status(500).json(err.message);
  }
});

module.exports = router;
