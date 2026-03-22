require('dotenv').config();
const path = require('path');
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const multer = require('multer');
const crypto = require('crypto');

const { signToken, authMiddleware } = require('./auth');
const models = require('./models');
const { validatePasswordPolicy } = require('./passwordPolicy');

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 12 * 1024 * 1024 } });

const app = express();

function resolveCorsOrigin() {
  const raw = process.env.CLIENT_ORIGIN;
  if (!raw || raw === 'true') return true;
  const parts = raw.split(',').map((s) => s.trim()).filter(Boolean);
  if (parts.length === 0) return true;
  if (parts.length === 1) return parts[0];
  return parts;
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
      await appendPortalNotification({
        title: 'New client registration',
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

app.post('/api/auth/register-employee', async (req, res) => {
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
      role: 'employee',
      name: name || email.split('@')[0],
      approvalStatus: 'pending'
    });

    res.json({
      ok: true,
      message:
        'Registration received. An administrator will approve your account before you can sign in.'
    });
    try {
      await appendPortalNotification({
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
    const user = await findUserForLogin(identifier);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const passwordOk = await bcrypt.compare(password || '', user.passwordHash);
    if (!passwordOk || user.role !== role) return res.status(401).json({ error: 'Invalid credentials' });

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

/* ——— Public CMS ——— */
app.get('/api/projects', async (req, res) => {
  try {
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
  'careerApplications',
  'employeeTasks',
  'employeeTaskUpdates',
  'employeeTimeEntries',
  'employeeProgress',
  'employeeAssignmentStatus',
  'adminSettings',
  'adminClientProgressUpdates'
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

app.put('/api/portal/key/:key', authMiddleware, requireApprovedAccount, async (req, res) => {
  const { key } = req.params;
  try {
    if (!PORTAL_KEYS.includes(key)) return res.status(400).json({ error: 'Invalid key' });
    const body = req.body;
    await models.PortalState.findOneAndUpdate(
      { key: 'main' },
      { $set: { [key]: body }, $setOnInsert: { key: 'main' } },
      { upsert: true, new: true, runValidators: false }
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
    app.listen(PORT, () => {
      console.log(`AIS Concepts backend running on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error('MongoDB connection failed', err);
    process.exit(1);
  });
