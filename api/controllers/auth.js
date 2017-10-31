const bcrypt = require('bcrypt');
const { promisify } = require('util');
const redisService = require('../services/redis');
const jwtService = require('../services/jwt');
const compare = promisify(bcrypt.compare);
const { User, UserEmail } = require('../models').Models;
const { REDIS } = require('../services/constants');

module.exports = {
  login,
  refresh
};

async function login(req, res) {
  let userEmail = await UserEmail.findOne({
    where: { email: req.body.email, is_primary: true }
  });

  if (!userEmail) {
    return res.status(401).json({ message: `Unauthorized access` });
  }

  let user = await User.findOne({
    where: { id: userEmail.user_id }
  });

  let validPassword = await compare(req.body.password, user.password);
  if (!validPassword) {
    return res.status(401).json({ message: `Unauthorized access` });
  }

  // Note: A JWT is *signed* not *encrypted*. The best approach is to sign an object with the *minimally needed* information to identify a person
  let { accessToken, refreshToken, expiresIn } = await jwtService.sign({
    userId: user.id
  });

  return res.json({
    access_token: accessToken,
    refresh_token: refreshToken,
    expires_in: expiresIn,
    token_type: 'Bearer'
  });
}

async function refresh(req, res) {
  try {
    let decoded = await jwtService.verifyToken(req.body.refresh_token);
    let issuedToken = await redisService.get(
      REDIS.REFRESH_TOKENS_DB,
      req.body.refresh_token
    );
    if (!issuedToken) {
      throw new Error(`Invalid token`);
    }

    let accessTokenPayload = Object.assign({}, decoded);
    delete accessTokenPayload.refresh_token;
    let { accessToken, refreshToken } = await jwtService.sign(
      accessTokenPayload
    );
    await redisService.del(REDIS.REFRESH_TOKENS_DB, req.body.refresh_token);

    return res.json({
      access_token: accessToken,
      refresh_token: refreshToken,
      token_type: 'Bearer'
    });
  } catch (error) {
    return res
      .status(401)
      .json({ message: error.message || `Unauthorized access detected` });
  }
}
