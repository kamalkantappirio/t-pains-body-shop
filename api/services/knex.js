const knex = require('knex');
const pg = require('pg');
const { DATABASE_URL } = require('./constants');

pg.defaults.ssl =
  DATABASE_URL.indexOf('127.0.0.1') < 0 &&
  DATABASE_URL.indexOf('app_postgres') < 0;

module.exports = knex({
  client: 'pg',
  connection: DATABASE_URL,
  searchPath: process.env.POSTGRES_SCHEMA || 'public'
});
