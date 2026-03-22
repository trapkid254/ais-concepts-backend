const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true },
  username: { type: String, sparse: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ['client', 'employee', 'admin'], required: true },
  approvalStatus: {
    type: String,
    enum: ['pending', 'approved']
  },
  name: { type: String, default: '' },
  phone: { type: String, default: '' },
  avatar: { type: String, default: '' },
  lastLogin: { type: Date }
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
  excerpt: { type: String, default: '' },
  image: { type: String, default: '' },
  sortOrder: { type: Number, default: 0 }
});

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
  SiteContent: mongoose.model('SiteContent', siteContentSchema)
};
