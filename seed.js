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

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/ais_concepts';

const defaultProjects = [];

const defaultServices = [];

const defaultBlog = [];

async function run() {
  await mongoose.connect(MONGODB_URI);
  console.log('Connected to MongoDB');

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
  console.log('Created new admin account (username: aisconcepts, password: #Aisconcepts16).');

  await WebsiteProject.deleteMany({});
  await WebsiteProject.insertMany(defaultProjects);
  console.log('Seeded website projects');

  await WebsiteService.deleteMany({});
  await WebsiteService.insertMany(defaultServices);
  console.log('Seeded services');

  await BlogPost.deleteMany({});
  await BlogPost.insertMany(defaultBlog);
  console.log('Seeded blog posts');

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
  console.log('Seeded portal state');

  await SiteContent.findOneAndUpdate(
    { key: 'home' },
    {
      key: 'home',
      partners: [],
      testimonials: []
    },
    { upsert: true }
  );
  console.log('Seeded site content (partners + testimonials)');

  await mongoose.disconnect();
  console.log('Done.');
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
