const Redis = require('ioredis');
const config = require('../config/config');

// Crea instancia de ioredis
const redis = new Redis({
  host: config.redisHost,
  port: config.redisPort,
  password: config.redisPassword
  // Puedes añadir más opciones si necesitas SSL, etc.
});

module.exports = redis;
