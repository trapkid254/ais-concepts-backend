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

const defaultProjects = [
  {
    slug: 'horizon-tower',
    title: 'Horizon Tower',
    category: 'Commercial',
    categorySecondary: 'Urban',
    image: 'images/project1.jpg',
    heroImage: 'images/project1.jpg',
    description:
      'A 45-story landmark featuring a dynamic facade that responds to solar patterns, reducing energy consumption by 30%.',
    conceptSketches: ['images/project1.jpg'],
    siteAnalysis: ['images/service1.jpg'],
    floorPlans: ['images/service2.jpg'],
    renderings: ['images/project1.jpg'],
    constructionPhotos: ['images/project2.jpeg'],
    completedPhotos: ['images/project3.jpg'],
    metrics: { costEfficiency: 88, sustainability: 82, innovation: 91 },
    sortOrder: 1
  },
  {
    slug: 'eco-sphere-residence',
    title: 'Eco-Sphere Residence',
    category: 'Residential',
    categorySecondary: 'Sustainable',
    image: 'images/project2.jpeg',
    heroImage: 'images/project2.jpeg',
    description:
      'Net-zero carbon home integrating living walls and geothermal systems within a minimalist concrete shell.',
    conceptSketches: ['images/project2.jpeg'],
    siteAnalysis: ['images/service3.jpg'],
    floorPlans: ['images/service4.jpg'],
    renderings: ['images/project2.jpeg'],
    constructionPhotos: ['images/project1.jpg'],
    completedPhotos: ['images/project3.jpg'],
    metrics: { costEfficiency: 92, sustainability: 96, innovation: 85 },
    sortOrder: 2
  },
  {
    slug: 'nexus-cultural-center',
    title: 'Nexus Cultural Center',
    category: 'Urban',
    categorySecondary: 'Cultural',
    image: 'images/project3.jpg',
    heroImage: 'images/project3.jpg',
    description:
      'Floating volumes and translucent stone create a dialogue between heritage and contemporary form.',
    conceptSketches: ['images/project3.jpg'],
    siteAnalysis: ['images/service1.jpg'],
    floorPlans: ['images/service2.jpg'],
    renderings: ['images/project3.jpg'],
    constructionPhotos: ['images/project2.jpeg'],
    completedPhotos: ['images/project1.jpg'],
    metrics: { costEfficiency: 80, sustainability: 78, innovation: 94 },
    sortOrder: 3
  },
  {
    slug: 'riverside-mixed-use',
    title: 'Riverside Mixed-Use',
    category: 'Commercial',
    categorySecondary: 'Interior',
    image: 'https://via.placeholder.com/600x400?text=Riverside+Mixed-Use',
    heroImage: 'https://via.placeholder.com/1200x600?text=Riverside',
    description: 'Integrated retail, office, and residential with public plazas and green corridors.',
    conceptSketches: ['https://via.placeholder.com/800x500?text=Sketches'],
    siteAnalysis: ['https://via.placeholder.com/800x500?text=Site+Analysis'],
    floorPlans: ['https://via.placeholder.com/800x500?text=Floor+Plans'],
    renderings: ['https://via.placeholder.com/800x500?text=Renderings'],
    constructionPhotos: ['https://via.placeholder.com/800x500?text=Construction'],
    completedPhotos: ['https://via.placeholder.com/800x500?text=Completed'],
    metrics: { costEfficiency: 85, sustainability: 88, innovation: 80 },
    sortOrder: 4
  },
  {
    slug: 'concept-atelier',
    title: 'Concept Atelier',
    category: 'Conceptual',
    categorySecondary: 'Research',
    image: 'images/service1.jpg',
    heroImage: 'images/service1.jpg',
    description: 'Experimental pavilion exploring tensile structures and daylight as primary material.',
    conceptSketches: ['images/service2.jpg'],
    siteAnalysis: ['images/service3.jpg'],
    floorPlans: ['images/service4.jpg'],
    renderings: ['images/service1.jpg'],
    constructionPhotos: ['images/service2.jpg'],
    completedPhotos: ['images/service3.jpg'],
    metrics: { costEfficiency: 70, sustainability: 90, innovation: 98 },
    sortOrder: 5
  }
];

const defaultServices = [
  {
    title: 'Architectural Design',
    category: 'Architectural Design',
    image: 'images/service1.jpg',
    description:
      'From concept to construction, we create spaces that inspire and function. Our designs respond to context, climate, and culture.',
    sortOrder: 1
  },
  {
    title: 'Interior Architecture',
    category: 'Interior Architecture',
    image: 'images/service2.jpg',
    description:
      'Seamless integration of structure and interior experience, focusing on materiality, light, and spatial flow.',
    sortOrder: 2
  },
  {
    title: 'Urban Planning',
    category: 'Urban Planning',
    image: 'images/service3.jpg',
    description:
      'Master planning for resilient communities, balancing density, green space, and infrastructure for future cities.',
    sortOrder: 3
  },
  {
    title: 'Sustainable Design',
    category: 'Sustainable Design',
    image: 'images/service4.jpg',
    description:
      'Passive strategies, renewable materials, and energy modeling to achieve carbon-neutral architecture.',
    sortOrder: 4
  }
];

const defaultBlog = [
  {
    title: 'Designing the Sustainable High-Rise',
    date: '2026-03-01',
    excerpt:
      'How façade strategies, daylight modeling, and smart systems can reduce energy loads while keeping towers expressive and human.',
    image: 'images/blog1.jpg',
    sortOrder: 1
  },
  {
    title: 'African Modernism, Reimagined',
    date: '2026-02-12',
    excerpt:
      'Blending local materials, craft, and climate intelligence to create contemporary spaces rooted in place.',
    image: 'images/blog2.jpg',
    sortOrder: 2
  },
  {
    title: 'Designing for Experience',
    date: '2026-01-25',
    excerpt:
      'Why light, acoustics, and material tactility matter as much as the floor plan when crafting memorable interiors.',
    image: 'images/blog3.jpg',
    sortOrder: 3
  }
];

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
      partners: [
        { name: 'Structura Engineers', role: 'Structural engineers', icon: 'fa-drafting-compass' },
        { name: 'QuantEast', role: 'Quantity surveyors', icon: 'fa-calculator' },
        { name: 'BuildRight Contractors', role: 'Main contractors', icon: 'fa-hard-hat' },
        { name: 'EcoConsult Africa', role: 'MEP & sustainability', icon: 'fa-leaf' },
        { name: 'UrbanGrid Developers', role: 'Development partners', icon: 'fa-city' }
      ],
      testimonials: [
        {
          projectTitle: 'Horizon Tower',
          category: 'Commercial',
          image: 'images/project1.jpg',
          clientProblem: 'Tight budget and aggressive programme for a signature tower.',
          designImpact: 'Solar-responsive façade reduced operational load while strengthening identity.',
          financialImpact: 'Targeted value engineering saved roughly 12% on envelope scope.',
          emotionalExperience: 'Tenants describe the lobby as calm and memorable — exactly the brief.',
          quote: 'AIS Concepts delivered beyond expectations. Clear communication, strong detailing, and a design that feels iconic and efficient.',
          videoUrl: '',
          ownerName: 'Client Owner',
          ownerAvatar: 'https://ui-avatars.com/api/?name=Client+Owner&background=20c4b4&color=fff&size=128'
        },
        {
          projectTitle: 'Eco‑Sphere Residence',
          category: 'Residential',
          image: 'images/project2.jpeg',
          clientProblem: 'We wanted net‑zero performance without a cold, technical feel.',
          designImpact: 'Living walls and daylighting made sustainability feel human.',
          financialImpact: 'Lower long‑term energy bills and durable material choices.',
          emotionalExperience: 'Our home feels like a sanctuary — warm, quiet, and connected to the garden.',
          quote: 'They captured our lifestyle perfectly. The sustainable features were practical and beautifully integrated.',
          videoUrl: '',
          ownerName: 'Eco Client',
          ownerAvatar: 'https://ui-avatars.com/api/?name=Eco+Client&background=20c4b4&color=fff&size=128'
        },
        {
          projectTitle: 'Nexus Cultural Center',
          category: 'Urban',
          image: 'images/project3.jpg',
          clientProblem: 'Balance heritage sensitivity with a bold contemporary public presence.',
          designImpact: 'Translucent stone and floating volumes created a civic landmark.',
          financialImpact: 'Phased delivery aligned grants and construction cashflow.',
          emotionalExperience: 'Visitors linger — the space feels generous and dignified.',
          quote: 'A thoughtful public space. The team balanced heritage and modern expression with confidence.',
          videoUrl: '',
          ownerName: 'City Partner',
          ownerAvatar: 'https://ui-avatars.com/api/?name=City+Council&background=20c4b4&color=fff&size=128'
        }
      ]
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
