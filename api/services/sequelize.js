const { DATABASE_URL } = require('./constants');
const Sequelize = require('sequelize');
const sequelize = new Sequelize(DATABASE_URL, {
  logging: process.env.POSTGRES_LOGGING === 'true'
});
module.exports = sequelize;
