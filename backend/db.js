const { Sequelize } = require('sequelize');
require('dotenv').config(); // Load environment variables

// Load environment variables
const dbName = process.env.DB_NAME || 'defaultdb';
const dbUser = process.env.DB_USER || 'avnadmin';
const dbPassword = process.env.DB_PASSWORD || 'AVNS_IMCbwml3zGByOJWl11U';
const dbHost = process.env.DB_HOST || 'localhost';
const dbPort = process.env.DB_PORT || 3306;

// Initialize Sequelize
const sequelize = new Sequelize(dbName, dbUser, dbPassword, {
  host: dbHost,
  port: dbPort,
  dialect: 'mysql',
  logging: false, // Disable logging for cleaner output
  pool: {
    max: 10,
    min: 0,
    acquire: 30000,
    idle: 10000,
  },
  dialectOptions: {
    ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : undefined,
  },
});

// Test the database connection
(async () => {
  try {
    await sequelize.authenticate();
    console.log('Database connection established successfully.');
  } catch (error) {
    console.error('Unable to connect to the database:', error.message);
  }
})();

module.exports = sequelize;
