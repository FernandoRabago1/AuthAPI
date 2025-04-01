const users = require('../models/user.model');

// GET /api/users/current
async function getCurrent(req, res) {
  try {
    const user = await users.findOneById(req.user.id);

    return res.status(200).json({
      id: user._id,
      name: user.name,
      email: user.email
    });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
}

function getAdmin(req, res) {
  return res.status(200).json({ message: 'Only admins can access this route!' });
}

function getModerator(req, res) {
  return res.status(200).json({ message: 'Only admins and moderators can access this route!' });
}

module.exports = {
  getCurrent,
  getAdmin,
  getModerator
};
