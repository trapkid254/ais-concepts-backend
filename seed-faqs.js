require('dotenv').config();
const mongoose = require('mongoose');
const models = require('./models');

async function seedFAQs() {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/ais-concepts');
    console.log('Connected to MongoDB');

    // Clear existing FAQs
    await models.FAQ.deleteMany({});
    console.log('Cleared existing FAQs');

    // Sample FAQs
    const sampleFAQs = [
      // General FAQs
      {
        category: 'general',
        question: 'What services does AIS Concepts offer?',
        answer: 'AIS Concepts offers comprehensive architectural services including architectural design, interior design, urban planning, sustainable concepts, project management, and construction supervision.',
        sortOrder: 1
      },
      {
        category: 'general',
        question: 'How long has AIS Concepts been in business?',
        answer: 'AIS Concepts has been providing innovative architectural solutions for over a decade, establishing ourselves as a leading firm in the region.',
        sortOrder: 2
      },
      {
        category: 'general',
        question: 'What makes AIS Concepts different from other architectural firms?',
        answer: 'We combine cutting-edge technology with sustainable design principles, delivering innovative solutions that are both aesthetically pleasing and environmentally responsible.',
        sortOrder: 3
      },

      // Services FAQs
      {
        category: 'services',
        question: 'Do you provide residential architectural services?',
        answer: 'Yes, we specialize in residential architecture including custom homes, renovations, extensions, and multi-family housing projects.',
        sortOrder: 1
      },
      {
        category: 'services',
        question: 'Can you handle commercial projects?',
        answer: 'Absolutely! We have extensive experience with commercial projects including office buildings, retail spaces, hospitality, and mixed-use developments.',
        sortOrder: 2
      },
      {
        category: 'services',
        question: 'Do you offer 3D visualization and rendering services?',
        answer: 'Yes, we provide advanced 3D modeling, rendering, and virtual reality walkthroughs to help clients visualize their projects before construction.',
        sortOrder: 3
      },

      // Process FAQs
      {
        category: 'process',
        question: 'What is your typical project timeline?',
        answer: 'Project timelines vary depending on scope and complexity. Typically, residential projects take 6-12 months from concept to completion, while commercial projects may take 12-24 months.',
        sortOrder: 1
      },
      {
        category: 'process',
        question: 'How do you determine project costs?',
        answer: 'We provide detailed cost estimates based on project scope, materials, location, and complexity. Our transparent pricing ensures no hidden costs.',
        sortOrder: 2
      },
      {
        category: 'process',
        question: 'What is your design process?',
        answer: 'Our process includes: 1) Initial consultation and requirements gathering, 2) Concept development, 3) Design refinement, 4) Technical documentation, 5) Permit acquisition, 6) Construction supervision.',
        sortOrder: 3
      },

      // Style FAQs
      {
        category: 'style',
        question: 'What is your architectural style?',
        answer: 'Our architectural style is a blend of modern contemporary design with sustainable principles. We create spaces that are functional, aesthetically pleasing, and environmentally responsible.',
        sortOrder: 1
      },
      {
        category: 'style',
        question: 'Do you follow a specific design philosophy?',
        answer: 'Yes, we believe in designing with purpose. Our philosophy centers on creating spaces that enhance human experience while respecting the environment and local context.',
        sortOrder: 2
      },
      {
        category: 'style',
        question: 'How do you incorporate sustainability into your designs?',
        answer: 'Sustainability is at the core of our design approach. We use energy-efficient materials, passive design strategies, renewable energy integration, and locally sourced materials to minimize environmental impact.',
        sortOrder: 3
      }
    ];

    // Insert sample FAQs
    await models.FAQ.insertMany(sampleFAQs);
    console.log('Sample FAQs created successfully');

    // Count created FAQs
    const count = await models.FAQ.countDocuments();
    console.log(`Total FAQs in database: ${count}`);

  } catch (error) {
    console.error('Error seeding FAQs:', error);
  } finally {
    await mongoose.disconnect();
    console.log('Disconnected from MongoDB');
  }
}

// Run the seed function
seedFAQs();
