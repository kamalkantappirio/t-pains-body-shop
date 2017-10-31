require('dotenv/config');
const express = require('express');
const winston = require('winston');
const api = require('./api');
const path = require('path');
const helmet = require('helmet');

// Server-wide settings
winston.level = process.env.WINSTON_LEVEL || 'debug';
const dev = process.env.NODE_ENV !== 'production';
const port = process.env.PORT || 3001;
const serverRoutes = ['/api', '/auth'];

// Scaffold the server
async function startServer() {
  const app = await api(express());
  app.use(express.static('build'));
  app.use(helmet());
  app.get('*', function(req, res, next) {
    if (serverRoutes.indexOf(req.url) < 0) {
      return res
        .set('Content-Type', 'text/html')
        .sendFile(__dirname + '/build/index.html');
    }
    return next();
  });

  app.listen(port, err => {
    if (err) throw err;
    winston.info(`> Ready on http://localhost:${port}`);
  });
}

// Start the server
startServer();
