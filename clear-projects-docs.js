require('dotenv').config();
const mongoose = require('mongoose');
const { EnhancedProject, PortalState } = require('./models');

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/ais_concepts';

async function run() {
  await mongoose.connect(MONGODB_URI);
  console.log('Connected to MongoDB');

  // Clear all enhanced projects
  const projectCount = await EnhancedProject.countDocuments();
  console.log(`Found ${projectCount} projects in database`);
  
  await EnhancedProject.deleteMany({});
  console.log('Cleared all projects from database');

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
  console.log('Cleared portal state projects, documents, invoices, users, and assignments');

  await mongoose.disconnect();
  console.log('Done.');
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
