require('dotenv').config();
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const { User } = require('./models');
const logger = require('./logger');

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/ais_concepts';

async function resetAllCredentials() {
  try {
    await mongoose.connect(MONGODB_URI);
    logger.info('Connected to MongoDB');

    // Delete ALL existing users (admin, client, employee)
    const deleteResult = await User.deleteMany({});
    logger.info(`Deleted ${deleteResult.deletedCount} existing users`);

    // Create the new admin account
    const hash = (p) => bcrypt.hashSync(p, 10);
    
    const newAdmin = await User.create({
      email: 'admin@aisconcepts.com',
      username: 'aisconcepts',
      passwordHash: hash('#Aisconcepts16'),
      role: 'admin',
      name: 'AIS Concepts Administrator',
      approvalStatus: 'approved',
      lastLogin: null
    });

    logger.info('Successfully created new admin account', { 
      username: 'aisconcepts',
      email: 'admin@aisconcepts.com',
      role: 'admin',
      status: 'approved',
      id: newAdmin._id
    });

    // Verify the admin was created
    const verifyAdmin = await User.findOne({ username: 'aisconcepts' });
    if (verifyAdmin) {
      logger.info('Admin account verified in database');
    } else {
      logger.error('Admin account not found after creation');
    }

    await mongoose.disconnect();
    logger.info('Credential reset completed successfully');
    
  } catch (error) {
    logger.error('Error during credential reset', { error: error.message, stack: error.stack });
    process.exit(1);
  }
}

// Run the reset
resetAllCredentials();
