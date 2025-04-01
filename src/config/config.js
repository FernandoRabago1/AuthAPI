require('dotenv').config();

module.exports = {
  accessTokenSecret: process.env.ACCESS_TOKEN_SECRET || 'myAccessTokenSecret',
  accessTokenExpiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN || '15m', 
  refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET || 'myRefreshTokenSecret',
  refreshTokenExpiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || '7d', 

  cacheTemporaryTokenPrefix: process.env.CACHE_TEMPORARY_TOKEN_PREFIX || 'temp_token:',
  cacheTemporaryTokenExpiresInSeconds: parseInt(process.env.CACHE_TEMPORARY_TOKEN_EXPIRES_IN_SECONDS, 10) || 180,

  port: parseInt(process.env.PORT, 10) || 3000,
  frontendOrigin: process.env.FRONTEND_ORIGIN || 'http://localhost:3000',

  // Redis Config
  redisHost: process.env.REDIS_HOST || 'localhost',
  redisPort: parseInt(process.env.REDIS_PORT, 10) || 6379,
  redisPassword: process.env.REDIS_PASSWORD || '',

  // Variables para PostgreSQL
  dbHost: process.env.DB_HOST || 'localhost',
  dbPort: process.env.DB_PORT || 5432,
  dbUser: process.env.DB_USER || 'myuser',
  dbPassword: process.env.DB_PASSWORD || 'mypassword',
  dbName: process.env.DB_NAME || 'mydatabase'
};
