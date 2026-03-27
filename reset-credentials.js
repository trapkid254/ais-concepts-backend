require('dotenv').config();
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const { User } = require('./models');

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/ais_concepts';

async function resetAllCredentials() {
  try {
    await mongoose.connect(MONGODB_URI);
    console.log('Connected to MongoDB');

    // Delete ALL existing users (admin, client, employee)
    const deleteResult = await User.deleteMany({});
    console.log(`Deleted ${deleteResult.deletedCount} existing users`);

    // Create the new admin account
    const hash = (p) => bcrypt.hashSync(p, 10);
    
    const newAdmin = await User.create({
      email: 'admin@aisconcepts.com',
      username: 'Aisconcepts61',
      passwordHash: hash('#Aisconcepts16'),
      role: 'admin',
      name: 'AIS Concepts Administrator',
      approvalStatus: 'approved',
      lastLogin: null
    });

    console.log('✅ Successfully created new admin account:');
    console.log('   Username: Aisconcepts61');
    console.log('   Email: admin@aisconcepts.com');
    console.log('   Password: #Aisconcepts16');
    console.log('   Role: admin');
    console.log('   Status: approved');
    console.log('   ID:', newAdmin._id);

    // Verify the admin was created
    const verifyAdmin = await User.findOne({ username: 'Aisconcepts61' });
    if (verifyAdmin) {
      console.log('✅ Admin account verified in database');
    } else {
      console.log('❌ ERROR: Admin account not found after creation');
    }

    await mongoose.disconnect();
    console.log('✅ Credential reset completed successfully!');
    
  } catch (error) {
    console.error('❌ Error during credential reset:', error);
    process.exit(1);
  }
}

// Run the reset
resetAllCredentials();
