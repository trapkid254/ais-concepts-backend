// Script to add a sample vlog to the PRODUCTION database
// This will connect to your Render/production MongoDB
const mongoose = require('mongoose');

// Production MongoDB URI (same as used in Render)
const PRODUCTION_MONGODB_URI = 'mongodb+srv://aisconcepts:%23Okwonkwo254@ais-concepts.mpxcyjb.mongodb.net/ais-concepts?retryWrites=true&w=majority&appName=AiS-Concepts';

// Connect to PRODUCTION MongoDB
mongoose.connect(PRODUCTION_MONGODB_URI);

const vlogSchema = new mongoose.Schema({
  title: { type: String, required: true },
  youtubeUrl: { type: String, required: true },
  thumbnail: { type: String, default: '' },
  description: { type: String, default: '' },
  category: { type: String, default: '' },
  sortOrder: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const Vlog = mongoose.model('Vlog', vlogSchema);

async function addSampleVlog() {
  try {
    console.log('Connecting to PRODUCTION MongoDB...');
    await mongoose.connection;
    console.log('Connected to PRODUCTION MongoDB');

    // Show existing vlogs
    const existingVlogs = await Vlog.find().sort({ sortOrder: 1, createdAt: -1 });
    console.log('\nExisting vlogs in PRODUCTION database:');
    if (existingVlogs.length === 0) {
      console.log('No vlogs found.');
    } else {
      existingVlogs.forEach((vlog, index) => {
        console.log(`${index + 1}. ${vlog.title} (${vlog.youtubeUrl})`);
      });
    }

    // Create sample vlog
    const sampleVlog = await Vlog.create({
      title: 'AIS Concepts - Creating Spaces with Purpose',
      youtubeUrl: 'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
      thumbnail: 'https://img.youtube.com/vi/dQw4w9WgXcQ/maxresdefault.jpg',
      description: 'A glimpse into our architectural design process and philosophy.',
      category: 'Architecture',
      sortOrder: existingVlogs.length
    });

    console.log('\nSample vlog created successfully in PRODUCTION database:', sampleVlog.title);
    console.log('VLog ID:', sampleVlog._id);
    console.log('\nThe admin can now delete this vlog through the admin portal.');

    process.exit(0);
  } catch (error) {
    console.error('Error adding sample vlog to PRODUCTION database:', error);
    console.error('\nMake sure to set your PRODUCTION_MONGODB_URI in this script or as an environment variable.');
    process.exit(1);
  }
}

addSampleVlog();
