const bcrypt = require('bcrypt');
const {promisify} = require('util');
const redisService = require('../services/redis');
const jwtService = require('../services/jwt');
const compare = promisify(bcrypt.compare);
const hash = promisify(bcrypt.hash);
const {User, UserEmail, UserProfile} = require('../models').Models;
const {REDIS} = require('../services/constants');

const saltRounds = 10;

module.exports = {
  login,
  refresh,
  register
};

async function login(req, res) {
  let userEmail = await UserEmail.findOne({
    where: {email: req.body.email, is_primary: true}
  });

  if (!userEmail) {
    return res.status(401).json({message: `Unauthorized access1`});
  }

  let user = await User.findOne({
    where: {id: userEmail.user_id}
  });

  let validPassword = await compare(req.body.password, user.password);
  if (!validPassword) {
    return res.status(401).json({message: `Unauthorized access`});
  }

  // Note: A JWT is *signed* not *encrypted*. The best approach is to sign an object with the *minimally needed* information to identify a person
  let {accessToken, refreshToken, expiresIn} = await jwtService.sign({
    userId: user.id
  });

  return res.json({
    access_token: accessToken,
    refresh_token: refreshToken,
    expires_in: expiresIn,
    token_type: 'Bearer'
  });
}

async function register(req, res) {
  try{
    let userEmail = await UserEmail.findOne({
      where: {email: req.body.email, is_primary: true}
    });

    if (userEmail) {
      return res.status(401).json({message: `Email already register with us.`});
    }

    let hashPassword = await hash(req.body.password, saltRounds);

    let profile = await UserProfile.create({ first_name: req.body.first_name,  last_name: req.body.last_name, city: req.body.city,  state: req.body.state }, {fields: ['first_name', 'last_name', 'city', 'state']});

    let user = await User.create({  password: hashPassword, user_profile_id: profile.get({plain: true}).id}, {fields: ['password', 'user_profile_id']});

    let email = await UserEmail.create({user_id: user.get({plain: true}).id, email: req.body.email, is_primary: true}, {fields: ['user_id', 'email', 'is_primary']});

    let {accessToken, refreshToken, expiresIn} = await jwtService.sign({
      userId: user.get({plain: true}).id
    });

    return res.json({
      access_token: accessToken,
      refresh_token: refreshToken,
      first_name: profile.get({plain: true}).first_name,
      last_name: profile.get({plain: true}).last_name,
      email: email.get({plain: true}).email
    });
  }catch (err){
    return res.status(401).json(err);
  }

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
    let {accessToken, refreshToken} = await jwtService.sign(
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
      .json({message: error.message || `Unauthorized access detected`});
  }
}
