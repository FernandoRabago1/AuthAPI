const express = require('express');
const {
  register,
  login,
  login2FA,
  refreshToken,
  generate2FA,
  validate2FA,
  logout
} = require('../controllers/auth.controller');
const ensureAuthenticated = require('../middlewares/ensureAuthenticated');

const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.post('/login/2fa', login2FA);
router.post('/refresh-token', refreshToken);
router.get('/2fa/generate', ensureAuthenticated, generate2FA);
router.post('/2fa/validate', ensureAuthenticated, validate2FA);
router.get('/logout', ensureAuthenticated, logout);

module.exports = router;
