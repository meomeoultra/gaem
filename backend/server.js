/*
 server.js - Express backend cho game Tài Xỉu
*/
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const { port, mongoUri, jwtSecret, startBalance } = require("./config");

const User = require("./models/User");
const Bet = require("./models/Bet");

const app = express();
app.use(express.json());
app.use(cors());

// Basic rate limit
const limiter = rateLimit({
  windowMs: 5 * 1000, // 5s
  max: 10, // max 10 requests per window per IP
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// connect DB
mongoose.connect(mongoUri, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(()=> console.log("MongoDB connected"))
  .catch(err => {
    console.error("Mongo connect err:", err);
    process.exit(1);
  });

// helper
function signToken(user) {
  return jwt.sign({ id: user._id, username: user.username }, jwtSecret, { expiresIn: "7d" });
}

async function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: "Unauthorized" });
  const token = auth.split(" ")[1];
  try {
    const payload = jwt.verify(token, jwtSecret);
    const user = await User.findById(payload.id);
    if (!user) return res.status(401).json({ error: "Unauthorized" });
    req.user = user;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Unauthorized" });
  }
}

// Routes
app.post("/api/auth/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "username & password required" });
  try {
    const existing = await User.findOne({ username });
    if (existing) return res.status(400).json({ error: "username taken" });
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);
    const user = new User({ username, passwordHash: hash, balance: startBalance });
    await user.save();
    const token = signToken(user);
    return res.json({ token, username: user.username, balance: user.balance });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "username & password required" });
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: "invalid credentials" });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(400).json({ error: "invalid credentials" });
    const token = signToken(user);
    return res.json({ token, username: user.username, balance: user.balance });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});

// Get profile + last bets
app.get("/api/me", authMiddleware, async (req, res) => {
  const user = req.user;
  const lastBets = await Bet.find({ userId: user._id }).sort({ createdAt: -1 }).limit(20);
  res.json({ username: user.username, balance: user.balance, lastBets });
});

// Core: place bet
app.post("/api/game/bet", authMiddleware, async (req, res) => {
  const { choice, amount } = req.body;
  const user = req.user;
  if (!choice || !["tai","xiu"].includes(choice)) return res.status(400).json({ error: "invalid choice" });
  const betAmount = parseInt(amount, 10);
  if (!Number.isInteger(betAmount) || betAmount <= 0) return res.status(400).json({ error: "invalid amount" });
  if (user.balance < betAmount) return res.status(400).json({ error: "insufficient balance" });

  // server-side RNG: crypto.randomInt
  const dice = [
    crypto.randomInt(1, 7),
    crypto.randomInt(1, 7),
    crypto.randomInt(1, 7)
  ];
  const total = dice[0] + dice[1] + dice[2];
  const triple = (dice[0] === dice[1] && dice[1] === dice[2]);

  let resultType = "UNKNOWN";
  if (triple) resultType = "TRIPLE";
  else if (total >= 11 && total <= 17) resultType = "TAI";
  else if (total >= 4 && total <= 10) resultType = "XIU";

  let won = false;
  // triple always house wins on Tài/Xỉu bets
  if (resultType === "TRIPLE") {
    won = false;
  } else {
    if ((resultType === "TAI" && choice === "tai") || (resultType === "XIU" && choice === "xiu")) {
      won = true;
    } else won = false;
  }

  // payout 1:1 (win: +amount, lose: -amount)
  const delta = won ? betAmount : -betAmount;
  user.balance = Math.max(0, user.balance + delta);
  await user.save();

  const betRecord = new Bet({
    userId: user._id,
    username: user.username,
    amount: betAmount,
    choice,
    dice,
    total,
    triple,
    result: resultType,
    won
  });
  await betRecord.save();

  return res.json({
    dice,
    total,
    triple,
    result: resultType,
    won,
    balance: user.balance,
    betId: betRecord._id
  });
});

// Admin/test endpoint: top up (for dev only) — remove or protect in prod
app.post("/api/dev/topup", authMiddleware, async (req, res) => {
  const { amount } = req.body;
  const v = parseInt(amount, 10) || 0;
  req.user.balance += v;
  await req.user.save();
  res.json({ balance: req.user.balance });
});

app.listen(port, () => {
  console.log(\`Server running on port \${port}\`);
});
