const winston = require('winston');
const SwaggerExpress = require('swagger-express-mw');
const bodyParser = require('body-parser');
const yaml = require('js-yaml');
const Promise = require('bluebird');
const path = require('path');
const connectToPassport = require('./middleware/passport');
const cors = require('cors');
const models = require('./models');
const helmet = require('helmet');

// Promisify Swagger
Promise.promisifyAll(SwaggerExpress);

module.exports = api;

let config = {
  appRoot: path.join(__dirname, '..'),
  configDir: path.join(__dirname, './config')
};

async function api(app) {
  app.use(helmet());
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(bodyParser.json());
  app.use(cors());
  app = connectToPassport(app);

  const swaggerExpress = await SwaggerExpress.createAsync(config);
  swaggerExpress.register(app);

  await models.Migrations.MigratePermission();
  await models.Migrations.MigrateUser();
  return app;
}
