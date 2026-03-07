require("dotenv").config({ path: "workout.env" });
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const Brevo = require("sib-api-v3-sdk");

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
// PENDING USER SCHEMA & MODEL
// ------------------------
const PendingUserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  verificationCode: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, expires: 300 } // expires in 5 minutes
});

const PendingUser = mongoose.model("PendingUser", PendingUserSchema);

// ------------------------
// SETUP BREVO EMAIL
// ------------------------
const brevoClient = Brevo.ApiClient.instance;
brevoClient.authentications['api-key'].apiKey = process.env.BREVO_API_KEY;
const emailApi = new Brevo.TransactionalEmailsApi();

// ------------------------
// SIGNUP ROUTE
// ------------------------
app.post("/api/verify", async (req, res) => { // takes email, username, and password, sends verification email, but does NOT save to main DB yet
  const { username, password, email } = req.body;

  if (!username || !password || !email) { // checks if the user has entered a username, password, and email
    return res.status(400).json({ error: "Missing fields" });
  }

  try {
    const existingUser = await User.findOne({ $or: [{ username }, { email }] }); // check if username/email exists in main DB
    if (existingUser) {
      return res.status(409).json({ error: "Username or email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10); // hashes password so we can put it into the database
    const verificationCode = crypto.randomInt(0, 999999).toString().padStart(6, "0"); // makes a random verification code that is 6 digits long

    // Upsert into PendingUser collection to replace any previous pending entry for the same email or username
    await PendingUser.findOneAndUpdate(
      { $or: [{ email }, { username }] },
      { username, email, password: hashedPassword, verificationCode, createdAt: new Date() },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );
    
    // ---- SEND VERIFICATION EMAIL VIA BREVO ----
    await emailApi.sendTransacEmail({ // specifies contents of email being sent
      sender: { email: process.env.FROM_EMAIL },
      to: [{ email }],
      subject: "Workout Tracker Verification Code",
      textContent: `Your verification code is: ${verificationCode}`
    });

    res.status(201).json({ message: "Verification email sent" });

  } catch (err) {
    console.error(err);

    // handle duplicate key error in PendingUser unique indexes
    if (err.code === 11000) {
      return res.status(409).json({ error: "Username or email already pending verification" });
    }

    res.status(500).json({ error: "Server error" });
  }
});

// ------------------------
// AUTHENTICATION ROUTE
// ------------------------
app.post("/api/authentication", async (req, res) => { // verifies code and then creates the real user in the main DB
  const { email, code } = req.body;
  if (!email || !code) return res.status(400).json({ error: "Missing fields" });

  try {
    const pendingUser = await PendingUser.findOne({ email }); // find the pending user by email
    if (!pendingUser) return res.status(404).json({ error: "Pending user not found" });
    if (pendingUser.verificationCode !== code) return res.status(400).json({ error: "Invalid code" });

    // ---- CREATE REAL USER AFTER VERIFICATION ----
    const newUser = new User({ // moves verified pending user into main User collection
      username: pendingUser.username,
      email: pendingUser.email,
      password: pendingUser.password,
      isVerified: true
    });

    await newUser.save();        // saves the verified user to the main DB
    await PendingUser.deleteOne({ email });  // removes the pending user record

    return res.status(200).json({ message: "Email verified and user created successfully" });
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
      sender: { email: process.env.FROM_EMAIL },
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

  if (!username || !password) {
    return res.status(400).json({ error: "Missing fields" });
  }

  try {
    const existingUser = await User.findOne({ username });
    if (!existingUser) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

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