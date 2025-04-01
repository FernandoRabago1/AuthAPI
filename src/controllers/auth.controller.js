// src/controllers/auth.controller.js
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { authenticator } = require('otplib');
const qrcode = require('qrcode');
const crypto = require('crypto');
const NodeCache = require('node-cache');

const config = require('../config/config');
const cache = require('../utils/cache');  // Solo para 2FA tempToken
const redis = require('../db/redis');      // Usamos Redis para refresh tokens
const {
  findOneByEmail,
  findOneById,
  insertUser,
  updateUser
} = require('../models/user.model');

// Este baseCookieOptions sigue igual
const baseCookieOptions = {
  httpOnly: true,
  secure: false, // true en prod con HTTPS
  sameSite: 'lax'
};

// Función para convertir '7d' a segundos, '30m' a segundos, etc.
function parseExpiresIn(expiresInString) {
  const match = expiresInString.match(/^(\d+)([smhdw])$/);
  if (!match) return 0;  // fallback
  const amount = parseInt(match[1], 10);
  const unit = match[2];
  switch (unit) {
    case 's': return amount;
    case 'm': return amount * 60;
    case 'h': return amount * 3600;
    case 'd': return amount * 86400;
    case 'w': return amount * 604800;
    default: return 0;
  }
}

// Obtenemos en segundos la validez de accessToken y refreshToken
const accessTokenSeconds = parseExpiresIn(config.accessTokenExpiresIn); 
const refreshTokenSeconds = parseExpiresIn(config.refreshTokenExpiresIn); 

function validatePasswordPolicy(password) {
  if (password.length < 8) {
    return 'Password must be at least 8 characters long.';
  }
  // Al menos 1 dígito, 1 mayúscula, 1 minúscula, 1 símbolo
  const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).+$/;
  if (!regex.test(password)) {
    return 'Password must include uppercase, lowercase, digit, and special character.';
  }
  return null; // null si cumple
}

// ========================
// REGISTRO
// ========================
async function register(req, res) {
  try {
    const { name, email, password, role } = req.body;
    const policyError = validatePasswordPolicy(password);
    if (policyError) {
      return res.status(422).json({ message: policyError });
    }
    if (!name || !email || !password) {
      return res.status(422).json({ message: 'Please fill in all fields (name, email and password)' });
    }

    // Chequea si ya existe
    const existing = await findOneByEmail(email);
    if (existing) {
      return res.status(409).json({ message: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await insertUser({
      name,
      email,
      password: hashedPassword,
      role: role ?? 'member',
      twofaEnable: false,
      twofaSecret: null
    });

    return res.status(201).json({
      message: 'User registered successfully',
      id: newUser.id  // en PostgreSQL, la columna es "id"
    });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
}

// ========================
// LOGIN
// ========================
async function login(req, res) {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(422).json({ message: 'Please fill in all fields (email and password)' });
    }

    const user = await findOneByEmail(email);
    if (!user) {
      return res.status(401).json({ message: 'Email or password is invalid' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: 'Email or password is invalid' });
    }

    // 2FA habilitado => devolver tempToken
    if (user["2faEnable"]) {
      const tempToken = crypto.randomUUID();
      cache.set(
        config.cacheTemporaryTokenPrefix + tempToken,
        user.id,
        config.cacheTemporaryTokenExpiresInSeconds
      );
      return res.status(200).json({
        tempToken,
        expiresInSeconds: config.cacheTemporaryTokenExpiresInSeconds
      });
    } else {
      // Generamos el accessToken y refreshToken
      const accessToken = jwt.sign(
        { userId: user.id },
        config.accessTokenSecret,
        { subject: 'accessApi', expiresIn: config.accessTokenExpiresIn }
      );
      const refreshToken = jwt.sign(
        { userId: user.id },
        config.refreshTokenSecret,
        { subject: 'refreshToken', expiresIn: config.refreshTokenExpiresIn }
      );

      // Guardamos en Redis la validez del refresh token
      await redis.setex(`refresh:${refreshToken}`, refreshTokenSeconds, user.id.toString());

      // Seteamos las cookies
      res.cookie('accessToken', accessToken, {
        ...baseCookieOptions,
        maxAge: accessTokenSeconds * 1000
      });
      res.cookie('refreshToken', refreshToken, {
        ...baseCookieOptions,
        maxAge: refreshTokenSeconds * 1000
      });

      // No devolvemos refreshToken en body para mayor seguridad
      return res.status(200).json({
        id: user.id,
        name: user.name,
        email: user.email
      });
    }
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
}

// ========================
// LOGIN 2FA
// ========================
async function login2FA(req, res) {
  try {
    const { tempToken, totp } = req.body;
    if (!tempToken || !totp) {
      return res.status(422).json({ message: 'Please fill in all fields (tempToken and totp)' });
    }

    const userId = cache.get(config.cacheTemporaryTokenPrefix + tempToken);
    if (!userId) {
      return res.status(401).json({ message: 'The provided temporary token is incorrect or expired' });
    }

    const user = await findOneById(userId);
    if (!user) {
      return res.status(401).json({ message: 'User not found or invalid' });
    }

    const verified = authenticator.check(totp, user["2faSecret"]);
    if (!verified) {
      return res.status(401).json({ message: 'The provided TOTP is incorrect or expired' });
    }

    // Generamos tokens definitivos
    const accessToken = jwt.sign(
      { userId: user.id },
      config.accessTokenSecret,
      { subject: 'accessApi', expiresIn: config.accessTokenExpiresIn }
    );
    const refreshToken = jwt.sign(
      { userId: user.id },
      config.refreshTokenSecret,
      { subject: 'refreshToken', expiresIn: config.refreshTokenExpiresIn }
    );

    await redis.setex(`refresh:${refreshToken}`, refreshTokenSeconds, user.id.toString());

    res.cookie('accessToken', accessToken, {
      ...baseCookieOptions,
      maxAge: accessTokenSeconds * 1000
    });
    res.cookie('refreshToken', refreshToken, {
      ...baseCookieOptions,
      maxAge: refreshTokenSeconds * 1000
    });

    return res.status(200).json({
      id: user.id,
      name: user.name,
      email: user.email
    });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
}

// ========================
// REFRESH TOKEN
// ========================
async function refreshToken(req, res) {
  try {
    const storedRefresh = req.cookies?.refreshToken;
    if (!storedRefresh) {
      return res.status(401).json({ message: 'No refresh token cookie found' });
    }

    const decodedRefresh = jwt.verify(storedRefresh, config.refreshTokenSecret);
    const redisKey = `refresh:${storedRefresh}`;
    const redisValue = await redis.get(redisKey);
    if (!redisValue) {
      return res.status(401).json({ message: 'Refresh token invalid or expired' });
    }

    await redis.del(redisKey);

    const newAccessToken = jwt.sign(
      { userId: decodedRefresh.userId },
      config.accessTokenSecret,
      { subject: 'accessApi', expiresIn: config.accessTokenExpiresIn }
    );
    const newRefreshToken = jwt.sign(
      { userId: decodedRefresh.userId },
      config.refreshTokenSecret,
      { subject: 'refreshToken', expiresIn: config.refreshTokenExpiresIn }
    );

    await redis.setex(`refresh:${newRefreshToken}`, refreshTokenSeconds, decodedRefresh.userId.toString());

    res.cookie('accessToken', newAccessToken, {
      ...baseCookieOptions,
      maxAge: accessTokenSeconds * 1000
    });
    res.cookie('refreshToken', newRefreshToken, {
      ...baseCookieOptions,
      maxAge: refreshTokenSeconds * 1000
    });

    return res.status(200).json({
      message: 'Access token refreshed successfully'
    });
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError || error instanceof jwt.JsonWebTokenError) {
      return res.status(401).json({ message: 'Refresh token invalid or expired' });
    }
    return res.status(500).json({ message: error.message });
  }
}

// ========================
// GENERATE 2FA
// ========================
async function generate2FA(req, res) {
  try {
    const user = await findOneById(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    const secret = authenticator.generateSecret();
    const uri = authenticator.keyuri(user.email, 'manfra.io', secret);

    // Actualizamos el usuario usando updateUser; aquí se utiliza $set en NeDB, en Postgres usaremos updateUser
    await updateUser(user.id, { "2faSecret": secret });
    // No es necesario compactDatafile, ya que Postgres no lo usa

    const qrCode = await qrcode.toBuffer(uri, { type: 'image/png', margin: 1 });
    res.setHeader('Content-Disposition', 'attachment; filename=qrcode.png');
    return res.status(200).type('image/png').send(qrCode);
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
}

// ========================
// VALIDATE 2FA
// ========================
async function validate2FA(req, res) {
  try {
    const { totp } = req.body;
    if (!totp) {
      return res.status(422).json({ message: 'TOTP is required' });
    }

    const user = await findOneById(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    const verified = authenticator.check(totp, user["2faSecret"]);
    if (!verified) {
      return res.status(400).json({ message: 'TOTP is not correct or expired' });
    }

    await updateUser(user.id, { "2faEnable": true });
    return res.status(200).json({ message: 'TOTP validated successfully' });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
}

// ========================
// LOGOUT
// ========================
async function logout(req, res) {
  try {
    if (req.accessToken) {
      const ttl = req.accessToken.exp - Math.floor(Date.now() / 1000);
      if (ttl > 0) {
        await redis.setex(`invalid:access:${req.accessToken.value}`, ttl, 'true');
      }
    }

    const existingRefresh = req.cookies?.refreshToken;
    if (existingRefresh) {
      const decoded = jwt.verify(existingRefresh, config.refreshTokenSecret);
      const refreshttl = decoded.exp - Math.floor(Date.now() / 1000);
      if (refreshttl > 0) {
        await redis.setex(`invalid:refresh:${existingRefresh}`, refreshttl, 'true');
      }
      await redis.del(`refresh:${existingRefresh}`);
    }

    res.clearCookie('accessToken', baseCookieOptions);
    res.clearCookie('refreshToken', baseCookieOptions);

    return res.status(204).send();
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
}

module.exports = {
  register,
  login,
  login2FA,
  refreshToken,
  generate2FA,
  validate2FA,
  logout
};
