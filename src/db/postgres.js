const { Pool } = require('pg');
const config = require('../config/config');

const pool = new Pool({
  host: config.dbHost,
  port: config.dbPort,
  user: config.dbUser,
  password: config.dbPassword,
  database: config.dbName
});

module.exports = pool;



  
