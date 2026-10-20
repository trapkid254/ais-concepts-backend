// Script to add a sample vlog to the database
const mongoose = require('mongoose');
require('dotenv').config();

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/ais-concepts', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

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
    console.log('Connecting to MongoDB...');
    await mongoose.connection;
    console.log('Connected to MongoDB');

    // Show existing vlogs
    const existingVlogs = await Vlog.find().sort({ sortOrder: 1, createdAt: -1 });
    console.log('\nExisting vlogs in database:');
    if (existingVlogs.length === 0) {
      console.log('No vlogs found.');
    } else {
      existingVlogs.forEach((vlog, index) => {
        console.log(`${index + 1}. ${vlog.title} (${vlog.youtubeUrl})`);
      });
    }

    // Create sample vlog regardless
    const sampleVlog = await Vlog.create({
      title: 'AIS Concepts - Creating Spaces with Purpose',
      youtubeUrl: 'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
      thumbnail: 'https://img.youtube.com/vi/dQw4w9WgXcQ/maxresdefault.jpg',
      description: 'A glimpse into our architectural design process and philosophy.',
      category: 'Architecture',
      sortOrder: existingVlogs.length
    });

    console.log('\nSample vlog created successfully:', sampleVlog.title);
    console.log('VLog ID:', sampleVlog._id);
    console.log('\nThe admin can now delete this vlog through the admin portal.');

    process.exit(0);
  } catch (error) {
    console.error('Error adding sample vlog:', error);
    process.exit(1);
  }
}

addSampleVlog();
