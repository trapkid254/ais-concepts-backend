require('dotenv').config();
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const {
  User,
  WebsiteProject,
  WebsiteService,
  BlogPost,
  PortalState,
  SiteContent
} = require('./models');
const logger = require('./logger');

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/ais_concepts';

const defaultProjects = [];

const defaultServices = [];

const defaultBlog = [];

async function run() {
  await mongoose.connect(MONGODB_URI);
  logger.info('Connected to MongoDB');

  const hash = (p) => bcrypt.hashSync(p, 10);

  // Clear existing admin accounts first
  await User.deleteMany({ role: 'admin' });
  
  // Create new admin account with updated credentials
  await User.create({
    email: 'admin@aisconcepts.com',
    username: 'aisconcepts',
    passwordHash: hash('#Aisconcepts16'),
    role: 'admin',
    name: 'AIS Concepts Administrator',
    approvalStatus: 'approved'
  });
  logger.info('Created new admin account', { username: 'aisconcepts' });

  await WebsiteProject.deleteMany({});
  await WebsiteProject.insertMany(defaultProjects);
  logger.info('Seeded website projects');

  await WebsiteService.deleteMany({});
  await WebsiteService.insertMany(defaultServices);
  logger.info('Seeded services');

  await BlogPost.deleteMany({});
  await BlogPost.insertMany(defaultBlog);
  logger.info('Seeded blog posts');

  await PortalState.findOneAndUpdate(
    { key: 'main' },
    {
      key: 'main',
      portalUsers: [],
      portalProjects: [],
      assignments: [],
      portalInvoices: [],
      portalMessages: [],
      clientProjects: [],
      clientDocuments: [],
      clientInvoices: [],
      employeeTasks: [],
      employeeTaskUpdates: [],
      employeeTimeEntries: [],
      employeeProgress: [],
      employeeAssignmentStatus: {},
      careerApplications: [],
      clientSupportTickets: []
    },
    { upsert: true }
  );
  logger.info('Seeded portal state');

  await SiteContent.findOneAndUpdate(
    { key: 'home' },
    {
      key: 'home',
      partners: [],
      testimonials: []
    },
    { upsert: true }
  );
  logger.info('Seeded site content (partners + testimonials)');

  await mongoose.disconnect();
  logger.info('Done.');
}

run().catch((e) => {
  logger.error('Error in seed.js', { error: e.message, stack: e.stack });
  process.exit(1);
});
