require("dotenv").config({ path: "workout.env" });
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");   //  make sure this is imported
const bcrypt = require("bcrypt");

const app = express();

// ------------------------
// MIDDLEWARE
// ------------------------

// Parse JSON bodies
app.use(express.json());

// Enable CORS for your frontend
app.use(cors());

// ------------------------
// DATABASE CONNECTION
// ------------------------
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.error(err));

// ------------------------
// USER SCHEMA & MODEL
// ------------------------
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  verificationCode: { type: String },
  isVerified: { type: Boolean, default: false }
});

const User = mongoose.model("User_Info", UserSchema);

// ------------------------
// SIGNUP ROUTE
// ------------------------

app.post("/api/verify", async (req, res) => {
  const { username, password, email } = req.body;

  if (!username || !password || !email) {
    return res.status(400).json({ error: "Missing fields" });
  }

  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(409).json({ error: "Username already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username,
      email,
      password: hashedPassword
    });

    await newUser.save();
    res.status(201).json({ message: "User created successfully" });

  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});
//
// LOGIN ROUTE
// ------------------------
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Missing fields" });
  }

  try {
    //check username
    const existingUser = await User.findOne({ username });
    if (!existingUser) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    //check password
    const isMatch = await bcrypt.compare(password, existingUser.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    res.status(200).json({ message: "Login successful" });

    } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});



// ------------------------
// START SERVER
// ------------------------
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});