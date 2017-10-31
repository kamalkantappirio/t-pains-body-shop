const bluebird = require('bluebird');
const jwt = require('jsonwebtoken');
const redisService = require('../services/redis');
const { promisify } = require('util');
const verify = promisify(jwt.verify);
const { REDIS } = require('./constants');
const ms = require('ms');
const moment = require('moment');

module.exports = {
  sign,
  verifyToken
};

async function sign(payload) {
  let expiresIn = process.env.JWT_EXPIRES_IN || `1d`;
  let expiresInMs = ms(expiresIn);
  let expiresInDate = moment().add('ms', expiresInMs);
  let accessToken = jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: expiresIn
  });

  // Persist the refresh token to redis
  // This allows for a quick mechanism to verify that we issued it and also
  // a way to quickly expire all refresh tokens in the event of a breach
  let refreshTokenPayload = { ...payload, created_at: new Date() };
  let refreshToken = jwt.sign(refreshTokenPayload, process.env.JWT_SECRET);
  let redisResult = await redisService.set(
    REDIS.REFRESH_TOKENS_DB,
    refreshToken,
    true
  );
  return {
    accessToken,
    refreshToken,
    expiresIn: expiresInDate.toDate().getTime()
  };
}

async function verifyToken(token) {
  let decoded = await jwt.verify(token, process.env.JWT_SECRET);
  return decoded;
}
