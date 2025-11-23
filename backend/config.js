require('dotenv').config();

module.exports = {
  port: process.env.PORT || 3000,
  mongoUri: process.env.MONGO_URI,
  jwtSecret: process.env.JWT_SECRET || "change_this",
  startBalance: parseInt(process.env.START_BALANCE || "1000", 10)
};
