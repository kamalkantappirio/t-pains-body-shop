const withAuth = require('../middleware/withAuth');
const models = require('../models');

module.exports = {
  profile: withAuth(profile),
  permissions: withAuth(permissions)
};

async function profile(req, res) {
  return res.json({
    message:
      'TODO: Implement /user/profile. Note, adding req.user object just for posterity.',
    ...req.user
  });
}

async function permissions(req, res) {
  return res.json({ ...req.user });
}
