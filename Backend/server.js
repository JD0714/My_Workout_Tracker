require("dotenv").config({ path: "workout.env" });
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const Brevo = require("sib-api-v3-sdk"); // Brevo SDK

const app = express();

// ------------------------
// MIDDLEWARE
// ------------------------
app.use(express.json());
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
// SETUP BREVO EMAIL
// ------------------------
const brevoClient = Brevo.ApiClient.instance;
brevoClient.authentications['api-key'].apiKey = process.env.BREVO_API_KEY;
const emailApi = new Brevo.TransactionalEmailsApi();
const FROM_EMAIL = process.env.FROM_EMAIL;

// ------------------------
// SIGNUP ROUTE
// ------------------------
app.post("/api/verify", async (req, res) => {
  const { username, password, email } = req.body;
  if (!username || !password || !email)
    return res.status(400).json({ error: "Missing fields" });

  try {
    const existingUser = await User.findOne({ username });
    if (existingUser)
      return res.status(409).json({ error: "Username already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationCode = crypto.randomInt(0, 999999).toString().padStart(6, "0");

    const newUser = new User({ username, email, password: hashedPassword, verificationCode });
    await newUser.save();

    // Send verification email via Brevo
    await emailApi.sendTransacEmail({
      sender: { email: FROM_EMAIL },
      to: [{ email }],
      subject: "Workout Tracker Verification Code",
      textContent: `Your verification code is: ${verificationCode}`
    });

    res.status(201).json({ message: "User created successfully" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ------------------------
// AUTHENTICATION ROUTE
// ------------------------
app.post("/api/authentication", async (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) return res.status(400).json({ error: "Missing fields" });

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "User not found" });
    if (user.isVerified) return res.status(400).json({ error: "User already verified" });
    if (user.verificationCode !== code) return res.status(400).json({ error: "Invalid code" });

    user.isVerified = true;
    user.verificationCode = null;
    await user.save();

    res.status(200).json({ message: "Email verified successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ------------------------
// RESEND CODE ROUTE
// ------------------------
app.post("/api/resend-code", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Missing email" });

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "User not found" });
    if (user.isVerified) return res.status(400).json({ error: "User already verified" });

    const newCode = crypto.randomInt(0, 999999).toString().padStart(6, "0");
    user.verificationCode = newCode;
    await user.save();

    await emailApi.sendTransacEmail({
      sender: { email: FROM_EMAIL },
      to: [{ email }],
      subject: "Workout Tracker Verification Code",
      textContent: `Your verification code is: ${newCode}`
    });

    res.status(200).json({ message: "New verification code sent to your email." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ------------------------
// LOGIN ROUTE
// ------------------------
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Missing fields" });

  try {
    const existingUser = await User.findOne({ username });
    if (!existingUser) return res.status(401).json({ error: "Invalid username or password" });

    const isMatch = await bcrypt.compare(password, existingUser.password);
    if (!isMatch) return res.status(401).json({ error: "Invalid username or password" });

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
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));