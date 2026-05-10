require('dotenv').config();
const path = require('path');
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const fs = require('fs');
const multer = require('multer');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const { Server } = require('socket.io');

const { signToken, authMiddleware } = require('./auth');
const models = require('./models');
const { validatePasswordPolicy } = require('./passwordPolicy');

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 12 * 1024 * 1024 } });

const app = express();

function resolveCorsOrigin() {
  const raw = process.env.CLIENT_ORIGIN;
  console.log('CLIENT_ORIGIN raw:', raw);

  // Always allow localhost origins for development and production
  const allowedOrigins = [
    'http://localhost:5502',
    'http://127.0.0.1:5502',
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'https://aisconcepts.com'
  ];

  if (!raw || raw === 'true') {
    // In development, allow localhost origins
    console.log('Using default allowedOrigins:', allowedOrigins);
    return allowedOrigins;
  }

  const parts = raw.split(',').map((s) => s.trim()).filter(Boolean);
  if (parts.length === 0) {
    // If no specific origins configured, allow localhost
    console.log('Using default allowedOrigins (no parts):', allowedOrigins);
    return allowedOrigins;
  }

  // Combine configured origins with localhost
  const combined = [...parts, ...allowedOrigins];
  console.log('Combined allowed origins:', combined);
  return combined;
}

app.use(
  cors({
    origin: resolveCorsOrigin(),
    credentials: true
  })
);
app.use(cookieParser());
app.use(express.json({ limit: '12mb' }));

const root = path.join(__dirname, '../frontend');
app.use(express.static(root));

function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
}

async function appendPortalNotification({ title, message, targets }) {
  const id = crypto.randomUUID();
  const notif = {
    id,
    createdAt: new Date().toISOString(),
    title: title || 'Notification',
    message: message || '',
    targets: Array.isArray(targets) ? targets : [],
    readBy: []
  };
  await models.PortalState.findOneAndUpdate(
    { key: 'main' },
    { $push: { notifications: notif } },
    { upsert: true }
  );
  return notif;
}

function notificationVisibleForUser(user, n) {
  const email = (user.email || '').toLowerCase();
  const role = user.role;
  const targets = n.targets || [];
  if (targets.includes('*') && role === 'admin') return true;
  if (targets.includes(email)) return true;
  return false;
}

async function findUserForLogin(identifier) {
  const raw = (identifier || '').trim();
  if (!raw) return null;
  const lower = raw.toLowerCase();
  return models.User.findOne({
    $or: [{ email: lower }, { username: lower }]
  });
}

async function requireApprovedAccount(req, res, next) {
  try {
    const u = await models.User.findById(req.user.sub);
    if (!u) return res.status(401).json({ error: 'Unauthorized' });
    if (u.role !== 'admin' && u.approvalStatus === 'pending') {
      return res.status(403).json({
        error: 'account_pending',
        message: 'Your account is pending administrator approval.'
      });
    }
    next();
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
}

/* ——— User Management ——— */
app.get('/api/users', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { role } = req.query;
    const filter = role ? { role } : {};
    const users = await models.User.find(filter)
      .select('-passwordHash')
      .sort({ createdAt: -1 });
    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ——— Auth ——— */
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const policyErr = validatePasswordPolicy(password);
    if (policyErr) return res.status(400).json({ error: policyErr });

    const exists = await models.User.findOne({ email: email.toLowerCase() });
    if (exists) return res.status(400).json({ error: 'Email already registered' });

    const passwordHash = await bcrypt.hash(password, 10);
    await models.User.create({
      email: email.toLowerCase(),
      passwordHash,
      role: 'client',
      name: name || email.split('@')[0],
      approvalStatus: 'pending'
    });

    res.json({
      ok: true,
      message:
        'Registration received. An administrator will approve your account before you can sign in.'
    });
    try {
      await broadcastNotification({
        title: 'New client registration',
        message: `${name || email} (${email}) is awaiting approval.`,
        targets: ['*']
      });
    } catch (e) {
      console.error('Notification error:', e);
    }
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/register-employee', async (req, res) => {
  try {
    const { name, email, password, role, assignedProjects, phone, username } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const policyErr = validatePasswordPolicy(password);
    if (policyErr) return res.status(400).json({ error: policyErr });

    const exists = await models.User.findOne({ email: email.toLowerCase() });
    if (exists) return res.status(400).json({ error: 'Email already registered' });

    const passwordHash = await bcrypt.hash(password, 10);
    await models.User.create({
      email: email.toLowerCase(),
      passwordHash,
      role: role || 'employee',
      name: name || email.split('@')[0],
      approvalStatus: 'pending',
      username: username || email.split('@')[0],
      phone: phone || '',
      assignedProjects: assignedProjects || []
    });

    res.json({
      ok: true,
      message:
        'Registration received. An administrator will approve your account before you can sign in.'
    });
    try {
      await broadcastNotification({
        title: 'New employee registration',
        message: `${name || email} (${email}) is awaiting approval.`,
        targets: ['*']
      });
    } catch (e) {
      console.error(e);
    }
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, username, password, portalType } = req.body;
    const role = portalType || 'client';
    const identifier = (email || username || '').trim();
    
    console.log('Login attempt:', {
      email,
      username,
      portalType,
      role,
      identifier,
      hasPassword: !!password
    });
    
    const user = await findUserForLogin(identifier);
    console.log('User found:', user ? { 
      id: user._id, 
      email: user.email, 
      username: user.username, 
      role: user.role,
      approvalStatus: user.approvalStatus 
    } : null);
    
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const passwordOk = await bcrypt.compare(password || '', user.passwordHash);
    
    console.log('Password validation:', {
      passwordProvided: !!password,
      passwordOk: passwordOk,
      userRole: user.role,
      requiredRole: role,
      roleMatch: user.role === role
    });
    
    if (!passwordOk || user.role !== role) {
      console.log('Authentication failed:', {
        passwordFailed: !passwordOk,
        roleFailed: user.role !== role
      });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (user.role !== 'admin' && user.approvalStatus === 'pending') {
      return res.status(403).json({
        error: 'account_pending',
        message: 'Your account is pending administrator approval.'
      });
    }

    user.lastLogin = new Date();
    await user.save();

    const token = signToken(user);
    res.json({
      token,
      user: {
        email: user.email,
        role: user.role,
        name: user.name,
        loginTime: user.lastLogin.toISOString(),
        avatar:
          user.avatar ||
          `https://ui-avatars.com/api/?name=${encodeURIComponent(user.name || user.email)}&background=20c4b4&color=fff&size=128`
      }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const u = await models.User.findById(req.user.sub);
    if (!u) return res.status(404).json({ error: 'User not found' });
    res.json({
      email: u.email,
      username: u.username,
      role: u.role,
      name: u.name,
      phone: u.phone,
      avatar: u.avatar,
      loginTime: u.lastLogin,
      approvalStatus: u.approvalStatus
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/pending-users', authMiddleware, adminOnly, async (req, res) => {
  try {
    const list = await models.User.find({
      approvalStatus: 'pending',
      role: { $in: ['client', 'employee'] }
    })
      .sort({ createdAt: 1 })
      .lean();
    res.json(
      list.map((u) => ({
        id: String(u._id),
        email: u.email,
        name: u.name,
        role: u.role,
        createdAt: u.createdAt
      }))
    );
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/users/:id/approve', authMiddleware, adminOnly, async (req, res) => {
  try {
    const u = await models.User.findById(req.params.id);
    if (!u) return res.status(404).json({ error: 'User not found' });
    if (u.role === 'admin') return res.status(400).json({ error: 'Cannot change admin' });
    u.approvalStatus = 'approved';
    await u.save();
    try {
      await appendPortalNotification({
        title: 'Account approved',
        message: 'Your portal account is active. You can sign in anytime.',
        targets: [String(u.email).toLowerCase()]
      });
    } catch (e) {
      console.error(e);
    }
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

/** Approved clients/employees + admins — for User Management table */
app.get('/api/admin/users', authMiddleware, adminOnly, async (req, res) => {
  try {
    const list = await models.User.find({
      $or: [
        { role: 'admin' },
        { approvalStatus: 'approved' },
        { role: { $in: ['client', 'employee'] }, approvalStatus: { $exists: false } }
      ]
    })
      .select('-passwordHash')
      .sort({ role: 1, name: 1 })
      .lean();
    res.json(
      list.map((u) => ({
        id: String(u._id),
        name: u.name || u.email,
        email: u.email,
        role: u.role ? u.role.charAt(0).toUpperCase() + u.role.slice(1) : '',
        status:
          u.role === 'admin'
            ? 'Active'
            : u.approvalStatus === 'pending'
              ? 'Pending'
              : 'Active',
        lastLogin: u.lastLogin ? new Date(u.lastLogin).toISOString() : '-'
      }))
    );
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/admin/users/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    if (String(req.user.sub) === String(req.params.id)) {
      return res.status(400).json({ error: 'Cannot delete your own account' });
    }
    const target = await models.User.findById(req.params.id);
    if (!target) return res.status(404).json({ error: 'User not found' });
    if (target.role === 'admin') {
      const admins = await models.User.countDocuments({ role: 'admin' });
      if (admins <= 1) return res.status(400).json({ error: 'Cannot delete the only admin' });
    }
    await models.User.deleteOne({ _id: target._id });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ——— Public CMS & Authenticated Project API ——— */
app.get('/api/projects', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    const { client } = req.query;

    // If authenticated and requesting client-specific projects
    if (authHeader && client) {
      try {
        const decoded = jwt.verify(authHeader.replace('Bearer ', ''), process.env.JWT_SECRET || 'dev-secret-key');
        if (decoded.role === 'client') {
          const projects = await models.EnhancedProject.find({
            client: decoded.sub
          }).populate('client', 'name email').sort({ createdAt: -1 });
          return res.json(projects);
        }
      } catch (e) {
        // Token invalid, fall through to public
      }
    }

    // If authenticated admin/foreman requesting all portal projects
    if (authHeader && !client) {
      try {
        const decoded = jwt.verify(authHeader.replace('Bearer ', ''), process.env.JWT_SECRET || 'dev-secret-key');
        if (decoded.role === 'admin') {
          const projects = await models.EnhancedProject.find().populate('client', 'name email').sort({ createdAt: -1 });
          return res.json(projects);
        }
        if (decoded.role === 'foreman') {
          const projects = await models.EnhancedProject.find({
            foremanId: decoded.sub
          }).populate('client', 'name email').sort({ createdAt: -1 });
          return res.json(projects);
        }
        // Employee can see projects they're assigned to
        if (decoded.role === 'employee') {
          const projects = await models.EnhancedProject.find({
            workers: decoded.sub
          }).populate('client', 'name email').sort({ createdAt: -1 });
          return res.json(projects);
        }
      } catch (e) {
        // Token invalid, fall through to public
      }
    }

    // Public: return website portfolio projects
    const list = await models.WebsiteProject.find().sort({ sortOrder: 1, title: 1 }).lean();
    const mapped = list.map((p, i) => ({
      id: p._id,
      slug: p.slug,
      title: p.title,
      category: p.category,
      categorySecondary: p.categorySecondary,
      image: p.image,
      heroImage: p.heroImage || p.image,
      description: p.description,
      conceptSketches: p.conceptSketches || [],
      siteAnalysis: p.siteAnalysis || [],
      floorPlans: p.floorPlans || [],
      renderings: p.renderings || [],
      constructionPhotos: p.constructionPhotos || [],
      completedPhotos: p.completedPhotos || [],
      metrics: p.metrics || {}
    }));
    res.json(mapped);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/projects/detail/:slug', async (req, res) => {
  try {
    const p = await models.WebsiteProject.findOne({ slug: req.params.slug }).lean();
    if (!p) return res.status(404).json({ error: 'Not found' });
    res.json({
      id: p._id,
      slug: p.slug,
      title: p.title,
      category: p.category,
      categorySecondary: p.categorySecondary,
      image: p.image,
      heroImage: p.heroImage || p.image,
      description: p.description,
      conceptSketches: p.conceptSketches || [],
      siteAnalysis: p.siteAnalysis || [],
      floorPlans: p.floorPlans || [],
      renderings: p.renderings || [],
      constructionPhotos: p.constructionPhotos || [],
      completedPhotos: p.completedPhotos || [],
      metrics: p.metrics || {}
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/services', async (req, res) => {
  try {
    const list = await models.WebsiteService.find().sort({ sortOrder: 1 }).lean();
    res.json(
      list.map((s, i) => ({
        id: s._id || i + 1,
        title: s.title,
        category: s.category,
        image: s.image,
        description: s.description
      }))
    );
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/blog', async (req, res) => {
  try {
    const list = await models.BlogPost.find().sort({ sortOrder: 1 }).lean();
    res.json(
      list.map((b, i) => ({
        id: b._id || i + 1,
        title: b.title,
        date: b.date,
        author: b.author || '',
        excerpt: b.excerpt,
        image: b.image
      }))
    );
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/site/home', async (req, res) => {
  try {
    const doc = await models.SiteContent.findOne({ key: 'home' }).lean();
    res.json({
      testimonials: doc && doc.testimonials ? doc.testimonials : [],
      partners: doc && doc.partners ? doc.partners : []
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ——— Forms ——— */
app.post('/api/newsletter', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    await models.NewsletterSubscriber.create({ email: email.toLowerCase() });
    res.json({ ok: true });
  } catch (e) {
    if (e.code === 11000) return res.json({ ok: true, note: 'already_subscribed' });
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, message } = req.body;
    if (!name || !email || !message) return res.status(400).json({ error: 'Missing fields' });
    await models.ContactMessage.create({ name, email, message });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/enquiries', upload.single('file'), async (req, res) => {
  try {
    const body = req.body;
    let fileName = null;
    let fileData = null;
    if (req.file) {
      fileName = req.file.originalname;
      fileData = req.file.buffer.toString('base64');
    }
    await models.ProjectEnquiry.create({
      name: body.name,
      type: body.type,
      contact: body.contact,
      location: body.location,
      timeline: body.timeline,
      budget: body.budget,
      fileName,
      fileData
    });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/careers/apply', async (req, res) => {
  try {
    await models.CareerApplication.create({ fields: req.body });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

const PORTAL_KEYS = [
  'assignments',
  'portalInvoices',
  'portalMessages',
  'clientSupportTickets',
  'portalUsers',
  'portalProjects',
  'clientProjects',
  'clientDocuments',
  'clientInvoices',
  'clientTransactions',
  'clientNotifications',
  'careerApplications',
  'employeeTasks',
  'employeeTaskUpdates',
  'employeeTimeEntries',
  'employeeProgress',
  'employeeAssignmentStatus',
  'adminSettings',
  'adminClientProgressUpdates',
  'faqs'
];

app.get('/api/notifications', authMiddleware, requireApprovedAccount, async (req, res) => {
  try {
    const state = await models.PortalState.findOne({ key: 'main' }).lean();
    const all = (state && state.notifications) || [];
    const email = (req.user.email || '').toLowerCase();
    const role = req.user.role;
    const filtered = all.filter((n) => notificationVisibleForUser({ email, role }, n));
    const items = filtered
      .slice()
      .reverse()
      .map((n) => ({
        id: n.id,
        createdAt: n.createdAt,
        title: n.title,
        message: n.message,
        read: (n.readBy || []).includes(email)
      }));
    const unreadCount = items.filter((x) => !x.read).length;
    res.json({ items, unreadCount });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/notifications/mark-read', authMiddleware, requireApprovedAccount, async (req, res) => {
  try {
    const ids = Array.isArray(req.body.ids) ? req.body.ids : [];
    const email = (req.user.email || '').toLowerCase();
    const doc = await models.PortalState.findOne({ key: 'main' });
    const list = (doc && doc.notifications) || [];
    list.forEach((n) => {
      if (ids.length === 0 || ids.includes(n.id)) {
        if (notificationVisibleForUser({ email, role: req.user.role }, n)) {
          n.readBy = n.readBy || [];
          if (!n.readBy.includes(email)) n.readBy.push(email);
        }
      }
    });
    await models.PortalState.findOneAndUpdate(
      { key: 'main' },
      { $set: { notifications: list } },
      { upsert: true }
    );
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/portal/employee-progress', authMiddleware, requireApprovedAccount, async (req, res) => {
  try {
    const u = await models.User.findById(req.user.sub).lean();
    if (!u || u.role !== 'employee') return res.status(403).json({ error: 'Employees only' });
    const { project, description, images } = req.body;
    if (!project || !String(description || '').trim()) {
      return res.status(400).json({ error: 'Project and description required' });
    }
    const imgs = Array.isArray(images) ? images.slice(0, 8) : [];
    const state = await models.PortalState.findOne({ key: 'main' }).lean();
    const assignments = state.assignments || [];
    const match = assignments.find(
      (a) =>
        String(a.project || '') === String(project) &&
        String(a.employeeEmail || '').toLowerCase() === String(u.email).toLowerCase()
    );
    if (!match) return res.status(400).json({ error: 'No matching assignment for this project' });
    const updates = [...(state.employeeTaskUpdates || [])];
    updates.push({
      taskId: project,
      project,
      description: String(description).trim(),
      images: imgs,
      imageData: imgs[0] || null,
      date: new Date().toISOString(),
      employeeEmail: u.email
    });
    await models.PortalState.findOneAndUpdate(
      { key: 'main' },
      { $set: { employeeTaskUpdates: updates } },
      { upsert: true, new: true }
    );
    const snippet = String(description).trim().slice(0, 120);
    await appendPortalNotification({
      title: 'Employee progress update',
      message: `${u.name || u.email} updated "${project}": ${snippet}${snippet.length < String(description).trim().length ? '…' : ''}`,
      targets: ['*']
    });
    const clientEmail = (match.clientEmail || '').toLowerCase();
    if (clientEmail) {
      await appendPortalNotification({
        title: 'Progress on ' + project,
        message: `Your team posted an update: ${snippet}${snippet.length < String(description).trim().length ? '…' : ''}`,
        targets: [clientEmail]
      });
    }
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/send-message', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { to, project, body } = req.body;
    if (!to || !body) return res.status(400).json({ error: 'Missing to or body' });
    const from = (req.user.email || 'admin').toLowerCase();
    const state = await models.PortalState.findOne({ key: 'main' }).lean();
    const messages = [...(state.portalMessages || [])];
    messages.push({
      from,
      to: String(to).toLowerCase(),
      project: project || '',
      body: String(body),
      timestamp: new Date().toISOString()
    });
    await models.PortalState.findOneAndUpdate(
      { key: 'main' },
      { $set: { portalMessages: messages } },
      { upsert: true }
    );
    await appendPortalNotification({
      title: 'New message from AIS Concepts',
      message: (String(body).slice(0, 200) + (String(body).length > 200 ? '…' : '')) || 'You have a new message.',
      targets: [String(to).toLowerCase()]
    });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/client-progress-broadcast', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { projectId, projectName, clientEmail, message, images } = req.body;
    if (!clientEmail || !String(message || '').trim()) {
      return res.status(400).json({ error: 'Client email and message required' });
    }
    const ce = String(clientEmail).toLowerCase();
    const state = await models.PortalState.findOne({ key: 'main' }).lean();
    const rows = [...(state.adminClientProgressUpdates || [])];
    rows.push({
      projectId: projectId || null,
      projectName: projectName || '',
      clientEmail: ce,
      message: String(message).trim(),
      images: Array.isArray(images) ? images.slice(0, 8) : [],
      at: new Date().toISOString()
    });
    await models.PortalState.findOneAndUpdate(
      { key: 'main' },
      { $set: { adminClientProgressUpdates: rows } },
      { upsert: true }
    );
    await appendPortalNotification({
      title: 'Project update from your team',
      message: `${projectName || 'Project'}: ${String(message).trim().slice(0, 200)}${String(message).trim().length > 200 ? '…' : ''}`,
      targets: [ce]
    });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/portal/client-project', authMiddleware, requireApprovedAccount, async (req, res) => {
  try {
    const u = await models.User.findById(req.user.sub).lean();
    if (!u || u.role !== 'client') return res.status(403).json({ error: 'Clients only' });
    const { name, description, deadline } = req.body;
    if (!name || !String(name).trim()) return res.status(400).json({ error: 'Project name required' });
    const state = await models.PortalState.findOne({ key: 'main' }).lean();
    const projects = [...(state.portalProjects || [])];
    const id = Date.now();
    projects.push({
      id,
      name: String(name).trim(),
      client: u.email,
      budget: '',
      progress: 0,
      status: 'Pending',
      category: 'Client request',
      nextMilestone: 'Awaiting review',
      completionDate: deadline || '',
      description: String(description || '').trim(),
      image: '',
      moneyPaid: '',
      moneyUsed: '',
      moneyRemaining: '',
      moneyOwed: '',
      clientSubmitted: true
    });
    await models.PortalState.findOneAndUpdate(
      { key: 'main' },
      { $set: { portalProjects: projects } },
      { upsert: true }
    );
    await appendPortalNotification({
      title: 'Client submitted a new project',
      message: `${u.name || u.email} added "${String(name).trim()}".`,
      targets: ['*']
    });
    res.json({ ok: true, id });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/portal/bootstrap', authMiddleware, requireApprovedAccount, async (req, res) => {
  try {
    let state = await models.PortalState.findOne({ key: 'main' }).lean();
    if (!state) {
      state = { key: 'main' };
    }
    const profile = await models.UserProfile.findOne({
      emailKey: (req.user.email || '').replace(/[^a-z0-9]/gi, '_')
    }).lean();

    const payload = {
      assignments: state.assignments || [],
      portalInvoices: state.portalInvoices || [],
      portalMessages: state.portalMessages || [],
      clientSupportTickets: state.clientSupportTickets || [],
      portalUsers: state.portalUsers || [],
      portalProjects: state.portalProjects || [],
      clientProjects: state.clientProjects || [],
      clientDocuments: state.clientDocuments || [],
      clientInvoices: state.clientInvoices || [],
      careerApplications: state.careerApplications || [],
      employeeTasks: state.employeeTasks || [],
      employeeTaskUpdates: state.employeeTaskUpdates || [],
      employeeTimeEntries: state.employeeTimeEntries || [],
      employeeProgress: state.employeeProgress || [],
      employeeAssignmentStatus: state.employeeAssignmentStatus || {},
      adminSettings: state.adminSettings || {},
      adminClientProgressUpdates: state.adminClientProgressUpdates || []
    };

    if (req.user.role !== 'admin') {
      payload.portalUsers = [];
      if (req.user.role === 'client') {
        payload.careerApplications = [];
        const email = (req.user.email || '').toLowerCase();
        payload.adminClientProgressUpdates = (payload.adminClientProgressUpdates || []).filter(
          (x) => String(x.clientEmail || '').toLowerCase() === email
        );
      } else {
        payload.adminClientProgressUpdates = [];
      }
    }

    res.json({ ...payload, profile });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/portal/key/:key', authMiddleware, requireApprovedAccount, async (req, res) => {
  const { key } = req.params;
  try {
    if (!PORTAL_KEYS.includes(key)) return res.status(400).json({ error: 'Invalid key' });
    
    const portalState = await models.PortalState.findOne({ key: 'main' });
    const data = portalState?.data?.[key] || [];
    
    res.json(data);
  } catch (e) {
    console.error('GET /api/portal/key/' + key, e.message || e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/portal/key/:key', authMiddleware, requireApprovedAccount, async (req, res) => {
  const { key } = req.params;
  try {
    if (!PORTAL_KEYS.includes(key)) return res.status(400).json({ error: 'Invalid key' });
    const body = req.body;
    await models.PortalState.findOneAndUpdate(
      { key: 'main' },
      { $set: { [`data.${key}`]: body } },
      { upsert: true }
    );
    res.json({ ok: true });
  } catch (e) {
    console.error('PUT /api/portal/key/' + key, e.message || e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/user/profile', authMiddleware, requireApprovedAccount, async (req, res) => {
  try {
    const emailKey = (req.user.email || '').replace(/[^a-z0-9]/gi, '_');
    await models.UserProfile.findOneAndUpdate(
      { emailKey },
      {
        emailKey,
        name: req.body.name,
        email: req.body.email,
        phone: req.body.phone,
        avatar: req.body.avatar,
        password: req.body.password
      },
      { upsert: true }
    );
    if (req.body.name || req.body.email) {
      await models.User.findByIdAndUpdate(req.user.sub, {
        ...(req.body.name ? { name: req.body.name } : {}),
        ...(req.body.email ? { email: req.body.email.toLowerCase() } : {}),
        ...(req.body.avatar ? { avatar: req.body.avatar } : {}),
        ...(req.body.phone ? { phone: req.body.phone } : {})
      });
    }
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/user/profile', authMiddleware, requireApprovedAccount, async (req, res) => {
  const emailKey = (req.user.email || '').replace(/[^a-z0-9]/gi, '_');
  const p = await models.UserProfile.findOne({ emailKey }).lean();
  res.json(p || {});
});

app.put('/api/admin/projects', authMiddleware, adminOnly, async (req, res) => {
  try {
    const arr = Array.isArray(req.body) ? req.body : [];
    await models.WebsiteProject.deleteMany({});
    for (let i = 0; i < arr.length; i++) {
      const p = arr[i];
      await models.WebsiteProject.create({
        slug:
          p.slug ||
          String(p.title || 'project')
            .toLowerCase()
            .replace(/\s+/g, '-')
            .replace(/[^a-z0-9-]/g, '') +
            '-' +
            (i + 1),
        title: p.title,
        category: p.category,
        categorySecondary: p.categorySecondary || '',
        image: p.image,
        heroImage: p.heroImage || p.image,
        description: p.description || '',
        conceptSketches: p.conceptSketches || [],
        siteAnalysis: p.siteAnalysis || [],
        floorPlans: p.floorPlans || [],
        renderings: p.renderings || [],
        constructionPhotos: p.constructionPhotos || [],
        completedPhotos: p.completedPhotos || [],
        metrics: p.metrics || {},
        sortOrder: i
      });
    }
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/admin/services', authMiddleware, adminOnly, async (req, res) => {
  const arr = Array.isArray(req.body) ? req.body : [];
  await models.WebsiteService.deleteMany({});
  for (let i = 0; i < arr.length; i++) {
    const s = arr[i];
    await models.WebsiteService.create({
      title: s.title,
      category: s.category || '',
      image: s.image || '',
      description: s.description || '',
      sortOrder: i
    });
  }
  res.json({ ok: true });
});

app.put('/api/admin/blog', authMiddleware, adminOnly, async (req, res) => {
  const arr = Array.isArray(req.body) ? req.body : [];
  await models.BlogPost.deleteMany({});
  for (let i = 0; i < arr.length; i++) {
    const b = arr[i];
    await models.BlogPost.create({
      title: b.title,
      date: b.date || '',
      author: b.author || '',
      excerpt: b.excerpt || '',
      image: b.image || '',
      sortOrder: i
    });
  }
  res.json({ ok: true });
});

app.put('/api/admin/site/home', authMiddleware, adminOnly, async (req, res) => {
  await models.SiteContent.findOneAndUpdate(
    { key: 'home' },
    {
      testimonials: req.body.testimonials || [],
      partners: req.body.partners || []
    },
    { upsert: true }
  );
  res.json({ ok: true });
});

// Site Statistics Endpoints
app.get('/api/statistics', async (req, res) => {
  try {
    // Get statistics from admin settings only
    const doc = await models.SiteStatistics.findOne({ key: 'main' }).lean();
    
    res.json({
      projectsDone: doc?.projectsDone || 150,
      happyClients: doc?.happyClients || 80,
      yearsExperience: doc?.yearsExperience || 15,
      teamMembers: doc?.teamMembers || 25
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/admin/statistics', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { projectsDone, happyClients, yearsExperience, teamMembers } = req.body;
    
    await models.SiteStatistics.findOneAndUpdate(
      { key: 'main' },
      {
        projectsDone: projectsDone || 150,
        happyClients: happyClients || 80,
        yearsExperience: yearsExperience || 15,
        teamMembers: teamMembers || 25,
        updatedAt: new Date()
      },
      { upsert: true }
    );
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/enquiries', authMiddleware, adminOnly, async (req, res) => {
  try {
    const list = await models.ProjectEnquiry.find().sort({ createdAt: -1 }).lean();
    res.json(
      list.map((e) => ({
        name: e.name,
        contact: e.contact,
        type: e.type,
        location: e.location,
        timeline: e.timeline,
        budget: e.budget,
        date: e.createdAt
      }))
    );
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/career-applications', authMiddleware, adminOnly, async (req, res) => {
  try {
    const list = await models.CareerApplication.find().sort({ createdAt: -1 }).lean();
    res.json(
      list.map((a) => {
        const f = a.fields || {};
        return {
          name: f.name,
          email: f.email,
          phone: f.phone,
          type: f.type,
          campus: f.campus,
          yearOfStudy: f.yearOfStudy,
          message: f.message,
          date: a.createdAt
        };
      })
    );
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/ais_concepts';

async function ensureDefaultAdmin() {
  const adminEmail = (process.env.ADMIN_EMAIL || 'admin@aisconcepts.com').toLowerCase();
  const adminUser = (process.env.ADMIN_USERNAME || 'aisconcepts').toLowerCase();
  const adminPass = process.env.ADMIN_PASSWORD || '#Aisconcepts16';
  const hash = await bcrypt.hash(adminPass, 10);
  await models.User.findOneAndUpdate(
    { $or: [{ username: adminUser }, { email: adminEmail }] },
    {
      $set: {
        email: adminEmail,
        username: adminUser,
        passwordHash: hash,
        role: 'admin',
        name: 'AIS Concepts Admin',
        approvalStatus: 'approved'
      }
    },
    { upsert: true }
  );
  console.log('Admin account synced in MongoDB (username:', adminUser + ').');
}

mongoose
  .connect(MONGODB_URI)
  .then(async () => {
    console.log('MongoDB connected');
    try {
      await ensureDefaultAdmin();
    } catch (e) {
      console.error('ensureDefaultAdmin:', e);
    }
  })
  .catch((err) => {
    console.error('MongoDB connection failed', err);
    process.exit(1);
  });

    // ===== WORKER MANAGEMENT ENDPOINTS =====

// Worker Registration with Face Recognition
app.post('/api/workers/register', async (req, res) => {
  try {
    const { name, nationalId, phone, email, dailyRate, faceImages } = req.body;
    
    // Validate required fields
    if (!name || !nationalId || !phone || !email || !dailyRate || !faceImages || faceImages.length === 0) {
      return res.status(400).json({ error: 'Missing required fields: name, nationalId, phone, email, dailyRate, faceImages' });
    }
    
    // Check for duplicate worker
    const existingWorker = await models.Worker.findOne({
      $or: [{ nationalId }, { email }, { phone }]
    });
    
    if (existingWorker) {
      return res.status(400).json({ error: 'Worker already exists with this national ID, email, or phone' });
    }
    
    // Create face encoding from multiple images
    const faceEncodings = faceImages.map(img => ({
      image: img,
      encoding: 'base64_face_encoding_' + Math.random().toString(36).substr(2, 9)
    }));
    
    const worker = await models.Worker.create({
      name,
      nationalId,
      phone,
      email,
      dailyRate,
      faceData: {
        faceImage: faceImages[0], // Primary face image
        faceEncoding: faceEncodings[0].encoding,
        livenessImages: faceImages.slice(1),
        registrationDate: new Date()
      },
      assignedProjects: []
    });
    
    res.status(201).json({
      message: 'Worker registered successfully',
      worker: {
        id: worker._id,
        name: worker.name,
        nationalId: worker.nationalId,
        phone: worker.phone,
        email: worker.email,
        dailyRate: worker.dailyRate,
        registrationDate: worker.faceData.registrationDate
      }
    });
  } catch (error) {
    console.error('Worker registration error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Face Recognition Login
app.post('/api/workers/face-login', async (req, res) => {
  try {
    const { faceImage, livenessImages = [] } = req.body;
    
    if (!faceImage) {
      return res.status(400).json({ error: 'Face image required' });
    }
    
    // Generate face encoding
    const faceEncoding = 'base64_face_encoding_' + Math.random().toString(36).substr(2, 9);
    
    // Find worker by face recognition
    const workers = await models.Worker.find({});
    
    let matchedWorker = null;
    let highestConfidence = 0;
    
    // Simple face matching simulation (in production, use actual face recognition library)
    for (const worker of workers) {
      if (worker.faceData && worker.faceData.faceImage) {
        // Simulate face matching with confidence score
        const confidence = Math.random() * 30 + 70; // 70-100% confidence
        
        if (confidence > highestConfidence) {
          highestConfidence = confidence;
          matchedWorker = worker;
        }
      }
    }
    
    if (matchedWorker) {
      // Create face recognition session
      const faceSession = await models.FaceSession.create({
        workerId: matchedWorker._id,
        images: [faceImage],
        livenessPassed: livenessImages.length > 0,
        confidence: highestConfidence,
        sessionStart: new Date(),
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      });
      
      const token = signToken({
        sub: String(matchedWorker._id),
        email: matchedWorker.email,
        role: 'worker',
        name: matchedWorker.name
      });
      
      res.json({
        message: 'Face recognition successful',
        token,
        worker: {
          id: matchedWorker._id,
          name: matchedWorker.name,
          nationalId: matchedWorker.nationalId,
          phone: matchedWorker.phone,
          email: matchedWorker.email
        }
      });
    } else {
      res.status(401).json({ error: 'Face not recognized' });
    }
  } catch (error) {
    console.error('Face login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Project Assignment
app.post('/api/projects/:projectId/assign-worker', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { workerId } = req.body;
    const projectId = req.params.projectId;
    
    if (!workerId) {
      return res.status(400).json({ error: 'Worker ID required' });
    }
    
    const project = await models.EnhancedProject.findById(projectId);
    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }
    
    // Assign worker to project
    project.workers.push(workerId);
    await project.save();
    
    // Update worker's assigned projects
    await models.Worker.findByIdAndUpdate(workerId, {
      $push: { assignedProjects: projectId }
    });
    
    res.json({
      message: 'Worker assigned to project successfully',
      project: {
        id: project._id,
        name: project.name,
        workers: project.workers
      }
    });
  } catch (error) {
    console.error('Project assignment error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Assign Employee to Project with Duties
app.post('/api/projects/:projectId/assign-employee', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { employeeId, duties } = req.body;
    const projectId = req.params.projectId;
    
    console.log('Assign employee request:', { employeeId, duties, projectId });
    
    if (!employeeId) {
      return res.status(400).json({ error: 'Employee ID required' });
    }
    
    const project = await models.EnhancedProject.findById(projectId);
    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }
    
    const employee = await models.User.findById(employeeId);
    if (!employee) {
      return res.status(404).json({ error: 'Employee not found' });
    }
    
    if (employee.role !== 'employee') {
      return res.status(400).json({ error: 'User is not an employee' });
    }
    
    // Check if employee is already assigned to this project
    const existingAssignment = project.assignedEmployees.find(
      assignment => String(assignment.employeeId) === String(employeeId)
    );
    
    if (existingAssignment) {
      // Update duties if already assigned
      existingAssignment.duties = duties || existingAssignment.duties;
    } else {
      // Add new assignment
      project.assignedEmployees.push({
        employeeId: employee._id,
        employeeName: employee.name,
        duties: duties || '',
        assignedAt: new Date()
      });
    }
    
    await project.save();
    
    // Update employee's assigned projects - use $addToSet to avoid duplicates
    await models.User.findByIdAndUpdate(employeeId, {
      $addToSet: { assignedProjects: projectId }
    });
    
    res.json({
      message: 'Employee assigned to project successfully',
      project: {
        id: project._id,
        name: project.name,
        assignedEmployees: project.assignedEmployees
      }
    });
  } catch (error) {
    console.error('Employee assignment error:', error);
    console.error('Error details:', {
      message: error.message,
      stack: error.stack,
      name: error.name
    });
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Remove Employee from Project
app.delete('/api/projects/:projectId/employees/:employeeId', authMiddleware, adminOnly, async (req, res) => {
  try {
    const projectId = req.params.projectId;
    const employeeId = req.params.employeeId;
    
    const project = await models.EnhancedProject.findById(projectId);
    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }
    
    // Remove employee from project
    project.assignedEmployees = project.assignedEmployees.filter(
      assignment => String(assignment.employeeId) !== String(employeeId)
    );
    
    await project.save();
    
    // Remove project from employee's assigned projects
    await models.User.findByIdAndUpdate(employeeId, {
      $pull: { assignedProjects: projectId }
    });
    
    res.json({
      message: 'Employee removed from project successfully',
      project: {
        id: project._id,
        name: project.name,
        assignedEmployees: project.assignedEmployees
      }
    });
  } catch (error) {
    console.error('Employee removal error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Attendance Tracking
app.post('/api/attendance/check-in', authMiddleware, async (req, res) => {
  try {
    const { workerId, projectId, faceImage, livenessImages = [] } = req.body;
    
    if (!workerId || !projectId) {
      return res.status(400).json({ error: 'Worker ID and Project ID required' });
    }
    
    // Verify worker is assigned to project
    const project = await models.EnhancedProject.findById(projectId);
    const worker = await models.Worker.findById(workerId);
    
    if (!project || !worker) {
      return res.status(404).json({ error: 'Project or worker not found' });
    }
    
    // Check if worker is within project GPS radius
    const workerLocation = worker.assignedProjects.includes(projectId) ? project : null;
    let isWithinRadius = true;
    
    if (workerLocation) {
      const distance = calculateDistance(
        workerLocation.location.latitude, workerLocation.location.longitude,
        project.location.latitude, project.location.longitude
      );
      isWithinRadius = distance <= project.radius;
    }
    
    // Simulate liveness detection
    const livenessPassed = livenessImages.length > 0;
    const livenessScore = livenessPassed ? 85 : 0;
    
    // Create attendance record
    const attendance = await models.Attendance.create({
      workerId,
      projectId,
      date: new Date(),
      time: new Date().toLocaleTimeString(),
      status: isWithinRadius && livenessPassed ? 'present' : 'absent',
      gpsCoordinates: workerLocation ? {
        latitude: workerLocation.location.latitude,
        longitude: workerLocation.location.longitude
      } : null,
      faceImage: faceImage,
      livenessScore,
      checkOutTime: null
    });
    
    res.json({
      message: 'Check-in successful',
      attendance: {
        id: attendance._id,
        status: attendance.status,
        time: attendance.time,
        withinRadius: isWithinRadius
      }
    });
  } catch (error) {
    console.error('Check-in error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ===== FOREMAN MANAGEMENT ENDPOINTS =====

// Create Foreman Account
app.post('/api/foreman/create', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { name, email, phone, password, projectIds = [] } = req.body;
    
    if (!name || !email || !phone || !password) {
      return res.status(400).json({ error: 'Missing required fields: name, email, phone, password' });
    }
    
    // Check if foreman already exists
    const existingForeman = await models.User.findOne({
      $or: [{ email }, { phone }]
    });
    
    if (existingForeman) {
      return res.status(400).json({ error: 'Foreman already exists with this email or phone' });
    }
    
    // Create foreman account
    const hashedPassword = bcrypt.hashSync(password, 10);
    const foreman = await models.User.create({
      name,
      email,
      phone,
      passwordHash: hashedPassword,
      role: 'foreman',
      approvalStatus: 'approved',
      assignedProjects: projectIds || [],
      workerAssignments: []
    });
    
    res.status(201).json({
      message: 'Foreman account created successfully',
      foreman: {
        id: foreman._id,
        name: foreman.name,
        email: foreman.email,
        phone: foreman.phone,
        role: foreman.role
      }
    });
  } catch (error) {
    console.error('Foreman creation error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});


// Get Individual Project (for admin)
app.get('/api/projects/:projectId', authMiddleware, adminOnly, async (req, res) => {
  try {
    const projectId = req.params.projectId;
    const project = await models.EnhancedProject.findById(projectId);
    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }
    res.json(project);
  } catch (error) {
    console.error('Get project error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete Project
app.delete('/api/projects/:projectId', authMiddleware, adminOnly, async (req, res) => {
  try {
    const projectId = req.params.projectId;
    console.log('Delete request received for projectId:', projectId);
    console.log('Type of projectId:', typeof projectId);
    
    // Find and delete the project
    const project = await models.EnhancedProject.findById(projectId);
    console.log('Found project:', project);
    if (!project) {
      console.log('Project not found for ID:', projectId);
      return res.status(404).json({ error: 'Project not found' });
    }
    
    // Remove project from any assigned foremen
    if (project.foremanId) {
      await models.User.findByIdAndUpdate(
        project.foremanId,
        { $pull: { assignedProjects: projectId } }
      );
    }
    
    // Remove project from any assigned workers
    if (project.workers && project.workers.length > 0) {
      await models.User.updateMany(
        { _id: { $in: project.workers } },
        { $pull: { assignedProjects: projectId } }
      );
    }
    
    // Delete the project
    await models.EnhancedProject.findByIdAndDelete(projectId);
    
    res.json({ message: 'Project deleted successfully' });
  } catch (error) {
    console.error('Delete project error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Helper to parse money strings like '5.00M', '500K', '1.5B' into actual numbers
function parseMoney(val) {
  if (typeof val === 'number') return val;
  if (!val) return 0;
  const str = String(val).replace(/,/g, '').trim().toUpperCase();
  const match = str.match(/^([\d.]+)\s*(B|M|K)?$/);
  if (!match) return parseFloat(str) || 0;
  const num = parseFloat(match[1]) || 0;
  const suffix = match[2];
  if (suffix === 'B') return num * 1000000000;
  if (suffix === 'M') return num * 1000000;
  if (suffix === 'K') return num * 1000;
  return num;
}

// Create Project
app.post('/api/projects', authMiddleware, adminOnly, upload.array('images', 10), async (req, res) => {
  try {
    const { 
      name, 
      client, 
      location, 
      budget, 
      deadline, 
      assignedForeman, 
      progress, 
      status, 
      category, 
      moneyPaid, 
      moneyUsed, 
      moneyRemaining, 
      moneyOwed 
    } = req.body;
    
    // Parse JSON strings from FormData
    let parsedLocation = {};
    let parsedAssignedForeman = null;
    
    if (location && typeof location === 'string') {
      try {
        parsedLocation = JSON.parse(location);
      } catch (e) {
        console.error('Error parsing location:', e);
        parsedLocation = { name: location, latitude: null, longitude: null };
      }
    } else if (location) {
      parsedLocation = location;
    }
    
    if (assignedForeman && typeof assignedForeman === 'string') {
      try {
        parsedAssignedForeman = JSON.parse(assignedForeman);
      } catch (e) {
        console.error('Error parsing assignedForeman:', e);
        parsedAssignedForeman = null;
      }
    } else if (assignedForeman) {
      parsedAssignedForeman = assignedForeman;
    }
    
    console.log('Project creation request:', {
      name,
      client,
      location: parsedLocation,
      budget,
      deadline,
      assignedForeman: parsedAssignedForeman,
      progress,
      status,
      category,
      moneyPaid,
      moneyUsed,
      moneyRemaining,
      moneyOwed
    });
    
    if (!name || !client) {
      console.log('Missing required fields:', { name, client });
      return res.status(400).json({ error: 'Missing required fields: name, client' });
    }
    
    // Process uploaded images
    const images = [];
    if (req.files && req.files.length > 0) {
      req.files.forEach(file => {
        images.push(`data:${file.mimetype};base64,${file.buffer.toString('base64')}`);
      });
    }
    
    const project = await models.EnhancedProject.create({
      name,
      client,
      location: {
        address: parsedLocation?.name || parsedLocation?.address || '',
        latitude: parseFloat(parsedLocation?.latitude) || -1.2921,
        longitude: parseFloat(parsedLocation?.longitude) || 36.8219
      },
      budget: parseMoney(budget),
      startDate: deadline ? new Date(deadline) : new Date(),
      endDate: deadline ? new Date(deadline) : new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
      foremanId: parsedAssignedForeman?._id || parsedAssignedForeman?.id || null,
      foremanName: parsedAssignedForeman?.name || '',
      progress: parseFloat(progress) || 0,
      status: (status || 'planning').toLowerCase(),
      category: category || 'Commercial',
      moneyPaid: parseMoney(moneyPaid),
      moneyUsed: parseMoney(moneyUsed),
      moneyRemaining: parseMoney(moneyRemaining),
      moneyOwed: parseMoney(moneyOwed),
      images: images,
      createdBy: req.user.sub
    });
    
    // If foreman was assigned, update the foreman's assigned projects
    if (parsedAssignedForeman?._id || parsedAssignedForeman?.id) {
      const foremanId = parsedAssignedForeman._id || parsedAssignedForeman.id;
      await models.User.findByIdAndUpdate(foremanId, {
        $addToSet: { assignedProjects: project._id }
      });
    }
    
    res.json(project);
  } catch (error) {
    console.error('Create project error:', error);
    console.error('Error details:', {
      message: error.message,
      stack: error.stack,
      name: error.name
    });
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Update Project
app.put('/api/projects/:projectId', authMiddleware, adminOnly, upload.array('images', 10), async (req, res) => {
  try {
    const projectId = req.params.projectId;
    const { 
      name, 
      client, 
      location, 
      budget, 
      deadline, 
      assignedForeman, 
      progress, 
      status, 
      category, 
      moneyPaid, 
      moneyUsed, 
      moneyRemaining, 
      moneyOwed 
    } = req.body;
    
    // Parse JSON strings from FormData
    let parsedLocation = {};
    let parsedAssignedForeman = null;
    
    if (location && typeof location === 'string') {
      try {
        parsedLocation = JSON.parse(location);
      } catch (e) {
        console.error('Error parsing location:', e);
        parsedLocation = { name: location, latitude: null, longitude: null };
      }
    } else if (location) {
      parsedLocation = location;
    }
    
    if (assignedForeman && typeof assignedForeman === 'string') {
      try {
        parsedAssignedForeman = JSON.parse(assignedForeman);
      } catch (e) {
        console.error('Error parsing assignedForeman:', e);
        parsedAssignedForeman = null;
      }
    } else if (assignedForeman) {
      parsedAssignedForeman = assignedForeman;
    }
    
    if (!name || !client) {
      return res.status(400).json({ error: 'Missing required fields: name, client' });
    }
    
    // Process uploaded images
    const images = [];
    if (req.files && req.files.length > 0) {
      req.files.forEach(file => {
        images.push(`data:${file.mimetype};base64,${file.buffer.toString('base64')}`);
      });
    }
    
    const updateData = {
      name,
      client,
      location: parsedLocation || { name: '', latitude: null, longitude: null },
      budget: budget || 'KSH 0',
      deadline: deadline || '',
      assignedForeman: parsedAssignedForeman || null,
      progress: progress || 0,
      status: (status || 'planning').toLowerCase(),
      category: category || 'Commercial',
      moneyPaid: moneyPaid || '',
      moneyUsed: moneyUsed || '',
      moneyRemaining: moneyRemaining || '',
      moneyOwed: moneyOwed || '',
      updatedAt: new Date()
    };
    
    // Only update images if new ones were uploaded
    if (images.length > 0) {
      updateData.images = images;
    }
    
    const project = await models.EnhancedProject.findByIdAndUpdate(
      projectId,
      updateData,
      { new: true }
    );
    
    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }
    
    res.json(project);
  } catch (error) {
    console.error('Update project error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Register Worker with Face Recognition
app.post('/api/workers/register', authMiddleware, upload.array('images', 5), async (req, res) => {
  try {
    const { name, nationalId, phone, projectId, dailyRate, skills, location, livenessPassed } = req.body;
    
    if (!name || !nationalId || !phone || !projectId) {
      return res.status(400).json({ error: 'Missing required fields: name, nationalId, phone, projectId' });
    }
    
    // Check if foreman is assigned to this project
    const foreman = req.user;
    const project = await models.EnhancedProject.findById(projectId);
    
    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }
    
    // Verify foreman is assigned to this project
    if (!foreman.assignedProjects.includes(projectId)) {
      return res.status(403).json({ error: 'You are not assigned to this project' });
    }
    
    // Check if worker already exists
    const existingWorker = await models.Worker.findOne({ nationalId });
    if (existingWorker) {
      return res.status(400).json({ error: 'Worker with this National ID already exists' });
    }
    
    // Process face images
    const faceImages = [];
    const faceEmbeddings = [];
    
    // Handle uploaded face images
    if (req.files) {
      const faceImageFiles = Object.keys(req.files)
        .filter(key => key.startsWith('faceImage'))
        .map(key => req.files[key]);
      
      for (const file of faceImageFiles) {
        // Save image and generate embedding (simplified - in production, use face recognition service)
        const imagePath = `/uploads/worker-faces/${Date.now()}_${file.originalname}`;
        faceImages.push(imagePath);
        
        // Generate face embedding (mock implementation)
        faceEmbeddings.push({
          embedding: generateMockEmbedding(),
          confidence: 0.95,
          createdAt: new Date()
        });
      }
    }
    
    // Process liveness image
    let livenessImage = null;
    if (req.files && req.files.livenessImage) {
      livenessImage = `/uploads/liveness/${Date.now()}_${req.files.livenessImage.originalname}`;
    }
    
    // Create worker
    const worker = await models.Worker.create({
      name,
      nationalId,
      phone,
      assignedProjects: [projectId],
      dailyRate: parseFloat(dailyRate),
      skills: skills || '',
      registeredBy: foreman._id,
      registrationDate: new Date(),
      status: 'active',
      faceImages,
      faceEmbeddings,
      livenessImage,
      livenessPassed: livenessPassed === 'true',
      registrationLocation: {
        type: 'Point',
        coordinates: [location ? parseFloat(location.longitude) : 0, location ? parseFloat(location.latitude) : 0]
      }
    });
    
    // Update project workers list
    await models.EnhancedProject.findByIdAndUpdate(
      projectId,
      { $push: { workers: worker._id } }
    );
    
    // Update foreman worker assignments
    await models.User.findByIdAndUpdate(
      foreman._id,
      { $push: { workerAssignments: worker._id } }
    );
    
    // Log registration for audit
    await appendPortalNotification({
      title: 'New Worker Registered',
      message: `${foreman.name} registered ${name} for project ${project.name}`,
      targets: ['*']
    });
    
    res.json({
      success: true,
      worker: {
        _id: worker._id,
        name: worker.name,
        nationalId: worker.nationalId,
        phone: worker.phone,
        dailyRate: worker.dailyRate,
        skills: worker.skills,
        status: worker.status
      }
    });
    
  } catch (error) {
    console.error('Worker registration error:', error);
    res.status(500).json({ error: 'Server error during worker registration' });
  }
});

// Mock face embedding generation (replace with actual face recognition service)
function generateMockEmbedding() {
  return Array.from({ length: 128 }, () => Math.random() - 0.5);
}

// Mark Attendance with Face Recognition
app.post('/api/attendance/mark', authMiddleware, async (req, res) => {
  try {
    const { projectId, workerId, location, faceImage, livenessData } = req.body;
    
    if (!projectId || !workerId || !location) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    const foreman = req.user;
    
    // Verify foreman is assigned to this project
    if (!foreman.assignedProjects.includes(projectId)) {
      return res.status(403).json({ error: 'You are not assigned to this project' });
    }
    
    // Get project and worker
    const project = await models.EnhancedProject.findById(projectId);
    const worker = await models.Worker.findById(workerId);
    
    if (!project || !worker) {
      return res.status(404).json({ error: 'Project or worker not found' });
    }
    
    // Check if worker is assigned to this project
    if (!worker.assignedProjects.includes(projectId)) {
      return res.status(400).json({ error: 'Worker is not assigned to this project' });
    }
    
    // Validate GPS location (within 50m of project)
    if (!project.location || !project.location.latitude || !project.location.longitude) {
      return res.status(400).json({ error: 'Project location not set' });
    }
    
    const distance = calculateDistance(
      parseFloat(location.latitude),
      parseFloat(location.longitude),
      project.location.latitude,
      project.location.longitude
    );
    
    if (distance > 50) {
      return res.status(400).json({ 
        error: 'Too far from project location', 
        distance: Math.round(distance) 
      });
    }
    
    // Check if already marked today
    const today = new Date().toISOString().split('T')[0];
    const existingAttendance = await models.Attendance.findOne({
      workerId,
      projectId,
      date: today
    });
    
    if (existingAttendance) {
      return res.status(400).json({ error: 'Attendance already marked for today' });
    }
    
    // Face recognition validation (simplified)
    let faceMatch = false;
    let confidence = 0;
    
    if (faceImage && worker.faceEmbeddings && worker.faceEmbeddings.length > 0) {
      // In production, use actual face recognition service
      faceMatch = true; // Mock successful match
      confidence = 0.92; // Mock confidence score
    }
    
    // Liveness validation
    let livenessPassed = false;
    if (livenessData) {
      livenessPassed = livenessData.passed === true;
    }
    
    // Validate minimum requirements
    if (!faceMatch || confidence < 0.85 || !livenessPassed) {
      return res.status(400).json({ 
        error: 'Attendance verification failed',
        reasons: [
          !faceMatch ? 'Face recognition failed' : null,
          confidence < 0.85 ? 'Low confidence match' : null,
          !livenessPassed ? 'Liveness check failed' : null
        ].filter(Boolean)
      });
    }
    
    // Create attendance record
    const attendance = await models.Attendance.create({
      workerId,
      projectId,
      foremanId: foreman._id,
      date: today,
      time: new Date().toTimeString().split(' ')[0],
      status: 'present',
      checkInLocation: {
        type: 'Point',
        coordinates: [parseFloat(location.longitude), parseFloat(location.latitude)]
      },
      faceMatch: true,
      faceConfidence: confidence,
      livenessPassed: true,
      verificationMethod: 'face_recognition'
    });
    
    // Update worker attendance stats
    await models.Worker.findByIdAndUpdate(workerId, {
      $push: { attendanceRecords: attendance._id },
      $inc: { totalDaysPresent: 1 }
    });
    
    res.json({
      success: true,
      attendance: {
        workerName: worker.name,
        projectName: project.name,
        time: attendance.time,
        confidence: confidence,
        location: { distance: Math.round(distance) }
      }
    });
    
  } catch (error) {
    console.error('Attendance marking error:', error);
    res.status(500).json({ error: 'Server error during attendance marking' });
  }
});

// Get Today's Attendance for Foreman
app.get('/api/attendance/today', authMiddleware, async (req, res) => {
  try {
    const { projectId } = req.query;
    const foreman = req.user;
    
    let projectIds = foreman.assignedProjects;
    if (projectId) {
      if (!foreman.assignedProjects.includes(projectId)) {
        return res.status(403).json({ error: 'You are not assigned to this project' });
      }
      projectIds = [projectId];
    }
    
    const today = new Date().toISOString().split('T')[0];
    
    const attendance = await models.Attendance.find({
      projectId: { $in: projectIds },
      date: today
    })
    .populate('workerId', 'name nationalId phone')
    .populate('projectId', 'name')
    .sort({ time: 1 });
    
    // Get all assigned workers for comparison
    const allWorkers = await models.Worker.find({
      assignedProjects: { $in: projectIds }
    }).select('name nationalId phone');
    
    // Mark workers who haven't checked in
    const presentWorkerIds = attendance.map(a => a.workerId._id.toString());
    const absentWorkers = allWorkers.filter(w => !presentWorkerIds.includes(w._id.toString()));
    
    res.json({
      present: attendance,
      absent: absentWorkers,
      summary: {
        total: allWorkers.length,
        present: attendance.length,
        absent: absentWorkers.length,
        date: today
      }
    });
    
  } catch (error) {
    console.error('Get attendance error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Helper function to calculate distance
function calculateDistance(lat1, lon1, lat2, lon2) {
  const R = 6371e3; // Earth's radius in meters
  const φ1 = lat1 * Math.PI/180;
  const φ2 = lat2 * Math.PI/180;
  const Δφ = (lat2-lat1) * Math.PI/180;
  const Δλ = (lon2-lon1) * Math.PI/180;
  
  const a = Math.sin(Δφ/2) * Math.sin(Δφ/2) +
          Math.cos(φ1) * Math.cos(φ2) *
          Math.sin(Δλ/2) * Math.sin(Δλ/2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
  
  return R * c; // Distance in meters
}

// Create Project with Foreman Assignment
app.post('/api/projects/create-with-foreman', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { 
      name, 
      location, 
      radius, 
      foremanId, 
      foremanName, 
      foremanEmail, 
      foremanPhone,
      startDate, 
      endDate, 
      budget 
    } = req.body;
    
    if (!name || !location || !foremanId) {
      return res.status(400).json({ error: 'Missing required fields: name, location, foremanId' });
    }
    
    // Validate location object
    if (!location.latitude || !location.longitude || !location.address) {
      return res.status(400).json({ error: 'Project location must include latitude, longitude, and address' });
    }
    
    // Create or find foreman account
    let foreman;
    if (foremanId) {
      foreman = await models.User.findById(foremanId);
      if (!foreman || foreman.role !== 'foreman') {
        return res.status(400).json({ error: 'Invalid foreman account' });
      }
    } else {
      // Create new foreman account
      const hashedPassword = bcrypt.hashSync('defaultPassword123', 10);
      foreman = await models.User.create({
        name: foremanName || 'New Foreman',
        email: foremanEmail || `foreman_${Date.now()}@aisconcepts.com`,
        phone: foremanPhone || '+2540000000',
        passwordHash: hashedPassword,
        role: 'foreman',
        approvalStatus: 'approved'
      });
    }
    
    // Create project with foreman assignment
    const project = await models.EnhancedProject.create({
      name,
      location,
      radius: radius || 100,
      foremanId: foreman._id,
      foremanName: foreman.name,
      startDate: startDate || new Date(),
      endDate: endDate || new Date(Date.now() + 90 * 24 * 60 * 60 * 1000), // 90 days default
      budget: budget || 0,
      workers: [],
      createdBy: req.user.sub, // Admin who created it
      status: 'planning'
    });
    
    // Update foreman's assigned projects
    await models.User.findByIdAndUpdate(foreman._id, {
      $push: { assignedProjects: project._id }
    });
    
    res.status(201).json({
      message: 'Project created with foreman assignment',
      project: {
        id: project._id,
        name: project.name,
        location: project.location,
        radius: project.radius,
        foreman: {
          id: foreman._id,
          name: foreman.name,
          email: foreman.email,
          phone: foreman.phone
        },
        status: project.status,
        budget: project.budget
      }
    });
  } catch (error) {
    console.error('Project creation error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get Foreman Projects
app.get('/api/foreman/:foremanId/projects', authMiddleware, async (req, res) => {
  try {
    const foremanId = req.params.foremanId;
    
    // Verify user is a foreman or admin
    const currentUser = await models.User.findById(req.user.sub);
    if (currentUser.role !== 'admin' && currentUser._id.toString() !== foremanId) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    const foreman = await models.User.findById(foremanId);
    if (!foreman || foreman.role !== 'foreman') {
      return res.status(404).json({ error: 'Foreman not found' });
    }
    
    // Get foreman's projects
    const projects = await models.EnhancedProject.find({ foremanId: foreman._id })
      .populate('workers', 'name nationalId phone email')
      .sort({ createdAt: -1 });
    
    res.json({
      foreman: {
        id: foreman._id,
        name: foreman.name,
        email: foreman.email
      },
      projects: projects.map(project => ({
        id: project._id,
        name: project.name,
        location: project.location,
        radius: project.radius,
        status: project.status,
        budget: project.budget,
        startDate: project.startDate,
        endDate: project.endDate,
        workers: project.workers || [],
        workerCount: project.workers ? project.workers.length : 0
      }))
    });
  } catch (error) {
    console.error('Get foreman projects error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete Foreman
app.delete('/api/foreman/:foremanId', authMiddleware, adminOnly, async (req, res) => {
  try {
    const foremanId = req.params.foremanId;
    
    // Find and delete the foreman
    const foreman = await models.User.findById(foremanId);
    if (!foreman || foreman.role !== 'foreman') {
      return res.status(404).json({ error: 'Foreman not found' });
    }
    
    // Remove foreman from any assigned projects
    await models.EnhancedProject.updateMany(
      { foremanId: foreman._id },
      { $unset: { foremanId: 1, foremanName: 1 } }
    );
    
    // Delete the foreman
    await models.User.findByIdAndDelete(foremanId);
    
    res.json({ message: 'Foreman deleted successfully' });
  } catch (error) {
    console.error('Delete foreman error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get Documents (with optional client filter)
app.get('/api/documents', authMiddleware, async (req, res) => {
  try {
    const { client } = req.query;
    let documents;
    
    if (client) {
      // Filter documents by client user ID
      documents = await models.Document.find({ 
        uploadedBy: req.user.sub
      }).populate('project', 'title').sort({ createdAt: -1 });
    } else {
      // Get all documents for admin users
      if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access denied' });
      }
      documents = await models.Document.find().populate('project', 'title').sort({ createdAt: -1 });
    }
    
    res.json(documents);
  } catch (error) {
    console.error('Get documents error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get Invoices (with optional client filter)
app.get('/api/invoices', authMiddleware, async (req, res) => {
  try {
    const { client } = req.query;
    let invoices;
    
    if (client) {
      // Filter invoices by client user ID
      invoices = await models.Invoice.find({ 
        client: req.user.sub
      }).populate('project', 'title').sort({ createdAt: -1 });
    } else {
      // Get all invoices for admin users
      if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access denied' });
      }
      invoices = await models.Invoice.find().populate('project', 'title').sort({ createdAt: -1 });
    }
    
    res.json(invoices);
  } catch (error) {
    console.error('Get invoices error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Create Project Inquiry
app.post('/api/inquiries', authMiddleware, async (req, res) => {
  try {
    const inquiryData = {
      projectId: req.body.projectId,
      projectName: req.body.projectName,
      clientEmail: req.body.clientEmail,
      clientName: req.body.clientName,
      subject: req.body.subject,
      message: req.body.message,
      priority: req.body.priority,
      createdAt: new Date(),
      status: 'pending'
    };
    
    // Create a simple inquiry model (you can enhance this later)
    const inquiry = new models.Inquiry(inquiryData);
    await inquiry.save();
    
    // TODO: Send email notification to admin about new inquiry
    
    res.json({ success: true, message: 'Inquiry submitted successfully' });
  } catch (error) {
    console.error('Create inquiry error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get Inquiries (for admin and client)
app.get('/api/inquiries', authMiddleware, async (req, res) => {
  try {
    const { client } = req.query;
    
    if (client && req.user.role === 'client') {
      // Client can only see their own inquiries
      const inquiries = await models.Inquiry.find({ 
        clientEmail: req.user.email 
      }).sort({ createdAt: -1 });
      res.json(inquiries);
    } else if (!client && req.user.role === 'admin') {
      // Admin can see all inquiries
      const inquiries = await models.Inquiry.find().sort({ createdAt: -1 });
      res.json(inquiries);
    } else {
      return res.status(403).json({ error: 'Access denied' });
    }
  } catch (error) {
    console.error('Get inquiries error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

/* -- FAQ Management -- */
app.get('/api/faqs', async (req, res) => {
  try {
    const faqs = await models.FAQ.find({ isActive: true }).sort({ sortOrder: 1, createdAt: 1 }).lean();
    
    // Group FAQs by category
    const groupedFAQs = {
      general: [],
      services: [],
      process: [],
      style: []
    };
    
    faqs.forEach(faq => {
      if (groupedFAQs[faq.category]) {
        groupedFAQs[faq.category].push({
          id: faq._id,
          question: faq.question,
          answer: faq.answer,
          date: faq.createdAt,
          sortOrder: faq.sortOrder
        });
      }
    });
    
    res.json(groupedFAQs);
  } catch (error) {
    console.error('Error fetching FAQs:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/faqs/:category/:id', async (req, res) => {
  try {
    const { category, id } = req.params;
    const faq = await models.FAQ.findOne({ _id: id, category, isActive: true }).lean();
    
    if (!faq) {
      return res.status(404).json({ error: 'FAQ not found' });
    }
    
    res.json({
      id: faq._id,
      question: faq.question,
      answer: faq.answer,
      category: faq.category,
      sortOrder: faq.sortOrder,
      date: faq.createdAt
    });
  } catch (error) {
    console.error('Error fetching FAQ:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/faqs', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { category, question, answer } = req.body;
    
    if (!category || !question || !answer) {
      return res.status(400).json({ error: 'Category, question, and answer are required' });
    }
    
    if (!['general', 'services', 'process', 'style'].includes(category)) {
      return res.status(400).json({ error: 'Invalid category' });
    }
    
    // Get the highest sort order for this category and add 1
    const maxSort = await models.FAQ.findOne({ category }).sort({ sortOrder: -1 }).lean();
    const sortOrder = maxSort ? maxSort.sortOrder + 1 : 0;
    
    const faq = await models.FAQ.create({
      category,
      question,
      answer,
      sortOrder,
      createdBy: req.user.sub
    });
    
    res.status(201).json({
      id: faq._id,
      question: faq.question,
      answer: faq.answer,
      category: faq.category,
      sortOrder: faq.sortOrder,
      date: faq.createdAt
    });
  } catch (error) {
    console.error('Error creating FAQ:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/faqs/:category/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { category, id } = req.params;
    const { question, answer, sortOrder } = req.body;
    
    if (!question || !answer) {
      return res.status(400).json({ error: 'Question and answer are required' });
    }
    
    const faq = await models.FAQ.findOne({ _id: id, category });
    
    if (!faq) {
      return res.status(404).json({ error: 'FAQ not found' });
    }
    
    const updateData = {
      question,
      answer,
      updatedAt: new Date()
    };
    
    if (sortOrder !== undefined) {
      updateData.sortOrder = sortOrder;
    }
    
    const updatedFAQ = await models.FAQ.findByIdAndUpdate(
      id,
      updateData,
      { new: true }
    ).lean();
    
    res.json({
      id: updatedFAQ._id,
      question: updatedFAQ.question,
      answer: updatedFAQ.answer,
      category: updatedFAQ.category,
      sortOrder: updatedFAQ.sortOrder,
      date: updatedFAQ.createdAt
    });
  } catch (error) {
    console.error('Error updating FAQ:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/faqs/:category/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { category, id } = req.params;
    
    const faq = await models.FAQ.findOne({ _id: id, category });
    
    if (!faq) {
      return res.status(404).json({ error: 'FAQ not found' });
    }
    
    // Soft delete by setting isActive to false
    await models.FAQ.findByIdAndUpdate(id, { isActive: false });
    
    res.json({ message: 'FAQ deleted successfully' });
  } catch (error) {
    console.error('Error deleting FAQ:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Helper function for distance calculation
function calculateDistance(lat1, lon1, lat2, lon2) {
  const R = 63710; // Earth's radius in km
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = Math.sin(dLat) * Math.sin(dLon) + Math.cos(lat1) * Math.cos(dLon);
  const c = Math.cos(dLat) * Math.cos(dLon) + Math.sin(lat1) * Math.sin(dLon);
  const distance = R * Math.acos(c) * 1000; // Distance in meters
  return distance;
}

const server = app.listen(PORT, () => {
      console.log(`AIS Concepts backend running on port ${PORT}`);
    });

// Initialize Socket.IO for real-time notifications
const io = new Server(server, {
  cors: {
    origin: resolveCorsOrigin(),
    credentials: true
  }
});

// Store connected users by their role and email
const connectedUsers = new Map();

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);
  
  // Handle user authentication and registration
  socket.on('register-user', (userData) => {
    const { email, role, token } = userData;
    if (email && role) {
      connectedUsers.set(socket.id, { email, role, socket });
      console.log(`User registered: ${email} (${role})`);
      
      // Join role-based rooms for targeted notifications
      socket.join(`role-${role}`);
      socket.join(`user-${email.toLowerCase()}`);
    }
  });
  
  // Handle disconnection
  socket.on('disconnect', () => {
    const user = connectedUsers.get(socket.id);
    if (user) {
      console.log(`User disconnected: ${user.email} (${user.role})`);
      connectedUsers.delete(socket.id);
    }
  });
});

// Enhanced notification function with real-time broadcasting
async function broadcastNotification(notification) {
  // Store notification in database (existing logic)
  await appendPortalNotification(notification);
  
  // Broadcast to relevant users in real-time
  const targets = notification.targets || [];
  
  if (targets.includes('*')) {
    // Send to all connected users
    io.emit('new-notification', notification);
  } else {
    // Send to specific targets
    targets.forEach(target => {
      if (target === 'admin') {
        io.to('role-admin').emit('new-notification', notification);
      } else if (target === 'client') {
        io.to('role-client').emit('new-notification', notification);
      } else if (target === 'employee') {
        io.to('role-employee').emit('new-notification', notification);
      } else if (target === 'foreman') {
        io.to('role-foreman').emit('new-notification', notification);
      } else {
        // Specific email target
        io.to(`user-${target.toLowerCase()}`).emit('new-notification', notification);
      }
    });
  }
}

// ===== WORKERS API =====
app.get('/api/workers', authMiddleware, async (req, res) => {
  try {
    // Return empty workers data for now - no static data
    res.json({ workers: [] });
  } catch (error) {
    console.error('Get workers error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ===== ATTENDANCE API =====
app.get('/api/attendance/stats', authMiddleware, async (req, res) => {
  try {
    // Return empty attendance stats for now - no static data
    res.json({
      present: 0,
      absent: 0,
      late: 0,
      total: 0
    });
  } catch (error) {
    console.error('Get attendance stats error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ===== PAYROLL API =====
app.get('/api/payroll/stats', authMiddleware, async (req, res) => {
  try {
    // Return empty payroll stats for now - no static data
    res.json({
      totalPayroll: 0,
      monthlyPayroll: 0,
      averageSalary: 0,
      workerCount: 0,
      currency: 'KSH'
    });
  } catch (error) {
    console.error('Get payroll stats error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Export io for use in other modules
global.io = io;
