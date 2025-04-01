// src/middlewares/ensureAuthenticated.js
const jwt = require('jsonwebtoken');
const config = require('../config/config');
const redis = require('../db/redis'); // Importamos Redis
// Eliminamos userInvalidTokens

async function ensureAuthenticated(req, res, next) {
  // Tomamos el token de la cookie
  const accessToken = req.cookies?.accessToken;
  if (!accessToken) {
    return res.status(401).json({ message: 'Access token not found in cookies' });
  }

  // Verificamos en Redis si está invalidado
  const invalid = await redis.get(`invalid:access:${accessToken}`);
  if (invalid) {
    return res.status(401).json({ message: 'Access token invalid (revoked)', code: 'AccessTokenInvalid' });
  }

  // Verifica la firma y la expiración
  try {
    const decodedAccessToken = jwt.verify(accessToken, config.accessTokenSecret);
    req.accessToken = { value: accessToken, exp: decodedAccessToken.exp };
    req.user = { id: decodedAccessToken.userId };

    next();
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      return res.status(401).json({ message: 'Access token expired', code: 'AccessTokenExpired' });
    } else if (error instanceof jwt.JsonWebTokenError) {
      return res.status(401).json({ message: 'Access token invalid', code: 'AccessTokenInvalid' });
    } else {
      return res.status(500).json({ message: error.message });
    }
  }
}

module.exports = ensureAuthenticated;
