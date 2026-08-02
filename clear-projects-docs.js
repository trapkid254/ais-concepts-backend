require('dotenv').config();
const mongoose = require('mongoose');
const { EnhancedProject, PortalState } = require('./models');
const logger = require('./logger');

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/ais_concepts';

async function run() {
  await mongoose.connect(MONGODB_URI);
  logger.info('Connected to MongoDB');

  // Clear all enhanced projects
  const projectCount = await EnhancedProject.countDocuments();
  logger.info(`Found ${projectCount} projects in database`);
  
  await EnhancedProject.deleteMany({});
  logger.info('Cleared all projects from database');

  // Clear portal state projects, documents, invoices, and other data
  await PortalState.findOneAndUpdate(
    { key: 'main' },
    {
      portalProjects: [],
      clientDocuments: [],
      portalInvoices: [],
      clientInvoices: [],
      portalUsers: [],
      assignments: []
    }
  );
  logger.info('Cleared portal state projects, documents, invoices, users, and assignments');

  await mongoose.disconnect();
  logger.info('Done.');
}

run().catch((e) => {
  logger.error('Error in clear-projects-docs', { error: e.message, stack: e.stack });
  process.exit(1);
});
