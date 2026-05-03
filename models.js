const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true },
  username: { type: String, sparse: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ['client', 'employee', 'foreman', 'admin'], required: true },
  approvalStatus: {
    type: String,
    enum: ['pending', 'approved']
  },
  name: { type: String, default: '' },
  phone: { type: String, default: '' },
  avatar: { type: String, default: '' },
  lastLogin: { type: Date },
  // Foreman specific fields
  assignedProjects: [{ type: mongoose.Schema.Types.ObjectId, ref: 'EnhancedProject' }],
  workerAssignments: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Worker' }]
}, { timestamps: true });

const websiteProjectSchema = new mongoose.Schema({
  slug: { type: String, unique: true, sparse: true },
  title: { type: String, required: true },
  category: { type: String, required: true },
  categorySecondary: { type: String, default: '' },
  image: { type: String, default: '' },
  heroImage: { type: String, default: '' },
  description: { type: String, default: '' },
  conceptSketches: [{ type: String }],
  siteAnalysis: [{ type: String }],
  floorPlans: [{ type: String }],
  renderings: [{ type: String }],
  constructionPhotos: [{ type: String }],
  completedPhotos: [{ type: String }],
  metrics: {
    costEfficiency: { type: Number, min: 0, max: 100 },
    sustainability: { type: Number, min: 0, max: 100 },
    innovation: { type: Number, min: 0, max: 100 }
  },
  sortOrder: { type: Number, default: 0 }
});

const websiteServiceSchema = new mongoose.Schema({
  title: { type: String, required: true },
  category: { type: String, default: '' },
  image: { type: String, default: '' },
  description: { type: String, default: '' },
  sortOrder: { type: Number, default: 0 }
});

const blogPostSchema = new mongoose.Schema({
  title: { type: String, required: true },
  date: { type: String, default: '' },
  author: { type: String, default: '' },
  excerpt: { type: String, default: '' },
  image: { type: String, default: '' },
  sortOrder: { type: Number, default: 0 }
});

// Worker Management Schemas
const workerSchema = new mongoose.Schema({
  nationalId: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  phone: { type: String, required: true },
  email: { type: String, lowercase: true, unique: true },
  dailyRate: { type: Number, required: true },
  faceData: {
    faceImage: { type: String, required: true },
    faceEncoding: { type: String, required: true },
    livenessImages: [{ type: String }],
    registrationDate: { type: Date, default: Date.now }
  },
  assignedProjects: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Project' }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { timestamps: true });

// Enhanced Project Schema with GPS and Foreman
const enhancedProjectSchema = new mongoose.Schema({
  name: { type: String, required: true },
  location: {
    latitude: { type: Number, required: true },
    longitude: { type: Number, required: true },
    address: { type: String, required: true }
  },
  radius: { type: Number, default: 100 }, // meters
  foremanId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // Changed to User model for foreman accounts
  foremanName: { type: String, default: '' }, // Store foreman name for display
  startDate: { type: Date, required: true },
  endDate: { type: Date, required: true },
  status: { 
    type: String, 
    enum: ['planning', 'active', 'completed', 'on-hold'], 
    default: 'planning' 
  },
  budget: { type: Number, required: true },
  workers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Worker' }],
  // Project creation workflow tracking
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { timestamps: true });

// Attendance Schema with GPS and Face Recognition
const attendanceSchema = new mongoose.Schema({
  workerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Worker', required: true },
  projectId: { type: mongoose.Schema.Types.ObjectId, ref: 'Project', required: true },
  date: { type: Date, required: true },
  time: { type: String, required: true }, // Check-in time
  status: { 
    type: String, 
    enum: ['present', 'absent', 'late'], 
    required: true 
  },
  gpsCoordinates: {
    latitude: { type: Number },
    longitude: { type: Number }
  },
  faceImage: { type: String }, // Proof of presence
  livenessScore: { type: Number }, // Anti-spoofing score
  checkOutTime: { type: Date }
}, { timestamps: true });

// Payroll Schema
const payrollSchema = new mongoose.Schema({
  workerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Worker', required: true },
  projectId: { type: mongoose.Schema.Types.ObjectId, ref: 'Project', required: true },
  payPeriod: {
    startDate: { type: Date, required: true },
    endDate: { type: Date, required: true }
  },
  daysPresent: { type: Number, required: true },
  daysAbsent: { type: Number, required: true },
  daysLate: { type: Number, required: true },
  hourlyRate: { type: Number, required: true },
  overtimeHours: { type: Number, default: 0 },
  totalSalary: { type: Number, required: true },
  deductions: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
}, { timestamps: true });

// Face Recognition Session Schema
const faceSessionSchema = new mongoose.Schema({
  workerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Worker', required: true },
  images: [{ type: String }], // Multiple face angles
  livenessPassed: { type: Boolean, required: true },
  confidence: { type: Number, required: true },
  sessionStart: { type: Date, required: true },
  sessionEnd: { type: Date },
  ipAddress: { type: String },
  userAgent: { type: String }
}, { timestamps: true });

const newsletterSubscriberSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true },
  createdAt: { type: Date, default: Date.now }
});

const contactMessageSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  message: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const projectEnquirySchema = new mongoose.Schema({
  name: String,
  type: String,
  contact: String,
  location: String,
  timeline: String,
  budget: String,
  fileName: String,
  fileData: String,
  createdAt: { type: Date, default: Date.now }
});

const careerApplicationSchema = new mongoose.Schema({
  fields: mongoose.Schema.Types.Mixed,
  createdAt: { type: Date, default: Date.now }
});

/** Mirrors previous localStorage portal blob */
const portalStateSchema = new mongoose.Schema({
  key: { type: String, unique: true, default: 'main' },
  assignments: { type: [mongoose.Schema.Types.Mixed], default: [] },
  portalInvoices: { type: [mongoose.Schema.Types.Mixed], default: [] },
  portalMessages: { type: [mongoose.Schema.Types.Mixed], default: [] },
  clientSupportTickets: { type: [mongoose.Schema.Types.Mixed], default: [] },
  portalUsers: { type: [mongoose.Schema.Types.Mixed], default: [] },
  portalProjects: { type: [mongoose.Schema.Types.Mixed], default: [] },
  clientProjects: { type: [mongoose.Schema.Types.Mixed], default: [] },
  clientDocuments: { type: [mongoose.Schema.Types.Mixed], default: [] },
  clientInvoices: { type: [mongoose.Schema.Types.Mixed], default: [] },
  careerApplications: { type: [mongoose.Schema.Types.Mixed], default: [] },
  employeeTasks: { type: [mongoose.Schema.Types.Mixed], default: [] },
  employeeTaskUpdates: { type: [mongoose.Schema.Types.Mixed], default: [] },
  employeeTimeEntries: { type: [mongoose.Schema.Types.Mixed], default: [] },
  employeeProgress: { type: [mongoose.Schema.Types.Mixed], default: [] },
  employeeAssignmentStatus: { type: mongoose.Schema.Types.Mixed, default: {} },
  adminClientProgressUpdates: { type: [mongoose.Schema.Types.Mixed], default: [] },
  notifications: { type: [mongoose.Schema.Types.Mixed], default: [] },
  adminSettings: {
    invoiceDueDays: { type: String, default: '30' },
    emailNotif: { type: String, default: '1' },
    invoiceReminders: { type: String, default: '1' }
  }
});

const userProfileSchema = new mongoose.Schema({
  emailKey: { type: String, unique: true },
  name: String,
  email: String,
  phone: String,
  avatar: String,
  password: String
});

const siteContentSchema = new mongoose.Schema({
  key: { type: String, unique: true, default: 'home' },
  testimonials: { type: [mongoose.Schema.Types.Mixed], default: [] },
  partners: { type: [mongoose.Schema.Types.Mixed], default: [] }
});

const faqSchema = new mongoose.Schema({
  category: { 
    type: String, 
    enum: ['general', 'services', 'process', 'style'], 
    required: true 
  },
  question: { type: String, required: true },
  answer: { type: String, required: true },
  sortOrder: { type: Number, default: 0 },
  isActive: { type: Boolean, default: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { timestamps: true });

const inquirySchema = new mongoose.Schema({
  projectId: { type: String, required: true },
  projectName: { type: String, required: true },
  clientEmail: { type: String, required: true },
  clientName: { type: String, required: true },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  priority: { type: String, enum: ['low', 'medium', 'high', 'urgent'], default: 'medium' },
  status: { type: String, enum: ['pending', 'in-progress', 'resolved'], default: 'pending' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { timestamps: true });

const siteStatisticsSchema = new mongoose.Schema({
  key: { type: String, unique: true, default: 'main' },
  projectsDone: { type: Number, default: 150 },
  happyClients: { type: Number, default: 80 },
  yearsExperience: { type: Number, default: 15 },
  teamMembers: { type: Number, default: 25 },
  updatedAt: { type: Date, default: Date.now }
}, { timestamps: true });

const invoiceSchema = new mongoose.Schema({
  invoiceNumber: { type: String, required: true, unique: true },
  project: { type: mongoose.Schema.Types.ObjectId, ref: 'EnhancedProject' },
  client: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  dueDate: { type: Date, required: true },
  status: { 
    type: String, 
    enum: ['pending', 'paid', 'overdue', 'cancelled'], 
    default: 'pending' 
  },
  description: { type: String, default: '' },
  items: [{
    description: { type: String, required: true },
    quantity: { type: Number, required: true, default: 1 },
    unitPrice: { type: Number, required: true },
    total: { type: Number, required: true }
  }],
  createdAt: { type: Date, default: Date.now },
  paidAt: { type: Date }
}, { timestamps: true });

const documentSchema = new mongoose.Schema({
  title: { type: String, required: true },
  fileName: { type: String, required: true },
  filePath: { type: String, required: true },
  fileSize: { type: Number, required: true },
  mimeType: { type: String, required: true },
  project: { type: mongoose.Schema.Types.ObjectId, ref: 'EnhancedProject' },
  uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  category: { 
    type: String, 
    enum: ['contract', 'blueprint', 'permit', 'invoice', 'report', 'other'], 
    default: 'other' 
  },
  description: { type: String, default: '' },
  isPublic: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
}, { timestamps: true });

module.exports = {
  User: mongoose.model('User', userSchema),
  WebsiteProject: mongoose.model('WebsiteProject', websiteProjectSchema),
  WebsiteService: mongoose.model('WebsiteService', websiteServiceSchema),
  BlogPost: mongoose.model('BlogPost', blogPostSchema),
  NewsletterSubscriber: mongoose.model('NewsletterSubscriber', newsletterSubscriberSchema),
  ContactMessage: mongoose.model('ContactMessage', contactMessageSchema),
  ProjectEnquiry: mongoose.model('ProjectEnquiry', projectEnquirySchema),
  CareerApplication: mongoose.model('CareerApplication', careerApplicationSchema),
  PortalState: mongoose.model('PortalState', portalStateSchema),
  UserProfile: mongoose.model('UserProfile', userProfileSchema),
  SiteContent: mongoose.model('SiteContent', siteContentSchema),
  FAQ: mongoose.model('FAQ', faqSchema),
  Worker: mongoose.model('Worker', workerSchema),
  EnhancedProject: mongoose.model('EnhancedProject', enhancedProjectSchema),
  Attendance: mongoose.model('Attendance', attendanceSchema),
  Payroll: mongoose.model('Payroll', payrollSchema),
  FaceSession: mongoose.model('FaceSession', faceSessionSchema),
  Inquiry: mongoose.model('Inquiry', inquirySchema),
  SiteStatistics: mongoose.model('SiteStatistics', siteStatisticsSchema),
  Invoice: mongoose.model('Invoice', invoiceSchema),
  Document: mongoose.model('Document', documentSchema)
};
