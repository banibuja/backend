const { Sequelize } = require('sequelize');
require('dotenv').config(); // Ngarkon variablat nga .env në `process.env`

// Parametrat e konfigurimit me vlera të paracaktuara
const dbName = process.env.DB_NAME || 'defaultdb';
const dbUser = process.env.DB_USER || 'avnadmin';
const dbPassword = process.env.DB_PASSWORD || 'AVNS_IMCbwml3zGByOJWl11U';
const dbHost = process.env.DB_HOST || 'localhost';
const dbPort = process.env.PORT || 3306; // Porti standard i MySQL

const sequelize = new Sequelize(dbName, dbUser, dbPassword, {
  host: dbHost,
  dialect: 'mysql',
  port: dbPort,
  logging: false,
  pool: {
    max: 10,
    min: 0,
    acquire: 30000,
    idle: 10000,
  },
  dialectOptions: {
    ssl: process.env.DB_SSL === 'true' ? {
      rejectUnauthorized: false,
    } : undefined, // Aktivizo SSL vetëm nëse është konfiguruar
  },
});

(async () => {
  try {
    await sequelize.authenticate();
    console.log('Connection has been established successfully.');

    await sequelize.sync();
    console.log('Tabela(t) janë krijuar në MySQL.');
  } catch (error) {
    console.error('Unable to connect to the database:', error.message);
  }
})();

module.exports = sequelize;
