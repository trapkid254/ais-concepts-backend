'use strict';

const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
const { API_VERSION } = require('../config/env');

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'AIS Concepts API',
      version: API_VERSION,
      description: 'REST API for AIS Concepts platform'
    },
    servers: [{ url: '/api/' + API_VERSION }],
    components: {
      securitySchemes: {
        bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' }
      }
    }
  },
  apis: []
};

const spec = swaggerJsdoc(options);

function mountSwagger(app) {
  app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(spec, { explorer: true }));
  app.get('/api/docs.json', (req, res) => res.json(spec));
}

module.exports = { mountSwagger, spec };
