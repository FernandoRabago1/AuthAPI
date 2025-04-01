const express = require('express');
const ensureAuthenticated = require('../middlewares/ensureAuthenticated');
const { authorize } = require('../middlewares/authorize');
const {
  getCurrent,
  getAdmin,
  getModerator
} = require('../controllers/user.controller');

const router = express.Router();

router.get('/current', ensureAuthenticated, getCurrent);
router.get('/admin', ensureAuthenticated, authorize(['admin']), getAdmin);
router.get('/moderator', ensureAuthenticated, authorize(['admin','moderator']), getModerator);

module.exports = router;
