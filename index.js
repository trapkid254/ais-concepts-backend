require('dotenv').config();
const path = require('path');
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const multer = require('multer');

const { signToken, authMiddleware, optionalAuth } = require('./auth');
const models = require('./models');

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 12 * 1024 * 1024 } });

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/ais_concepts';

function resolveCorsOrigin() {
  const raw = process.env.CLIENT_ORIGIN;
  if (raw === undefined || raw === '' || raw === 'true') return true;
  const parts = raw.split(',').map((s) => s.trim()).filter(Boolean);
  if (parts.length === 0) return true;
  if (parts.length === 1) return parts[0];
  return parts;
}

const app = express();
app.use(
  cors({
    origin: resolveCorsOrigin(),
    credentials: true
  })
);
app.use(cookieParser());
app.use(express.json({ limit: '12mb' }));

const root = path.join(__dirname, '../frontend');

function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
}

/* ——— Auth ——— */
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const exists = await models.User.findOne({ email: email.toLowerCase() });
    if (exists) return res.status(400).json({ error: 'Email already registered' });
    const passwordHash = await bcrypt.hash(password, 10);
    const user = await models.User.create({
      email: email.toLowerCase(),
      passwordHash,
      role: 'client',
      name: name || email.split('@')[0]
    });
    const token = signToken(user);
    res.json({
      token,
      user: {
        email: user.email,
        role: user.role,
        name: user.name,
        loginTime: new Date().toISOString(),
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

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password, portalType } = req.body;
    const role = portalType || 'client';
    const user = await models.User.findOne({ email: (email || '').toLowerCase() });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const passwordOk = await bcrypt.compare(password || '', user.passwordHash);
    if (!passwordOk) return res.status(401).json({ error: 'Invalid credentials' });
    if (user.role !== role) return res.status(401).json({ error: 'Invalid credentials' });

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
  const u = await models.User.findById(req.user.sub);
  if (!u) return res.status(404).json({ error: 'User not found' });
  res.json({
    email: u.email,
    role: u.role,
    name: u.name,
    phone: u.phone,
    avatar: u.avatar,
    loginTime: u.lastLogin
  });
});

/* ——— Public CMS reads ——— */
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
});

app.get('/api/blog', async (req, res) => {
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
});

app.get('/api/site/home', async (req, res) => {
  const doc = await models.SiteContent.findOne({ key: 'home' }).lean();
  res.json({
    testimonials: doc && doc.testimonials ? doc.testimonials : [],
    partners: doc && doc.partners ? doc.partners : []
  });
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

/* ——— Portal ——— */
app.get('/api/portal/bootstrap', authMiddleware, async (req, res) => {
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
      adminSettings: state.adminSettings || {}
    };

    if (req.user.role !== 'admin') {
      payload.portalUsers = [];
      if (req.user.role === 'client') {
        payload.careerApplications = [];
      }
    }

    res.json({ ...payload, profile });
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
  'adminSettings'
];

app.put('/api/portal/key/:key', authMiddleware, async (req, res) => {
  try {
    const { key } = req.params;
    if (!PORTAL_KEYS.includes(key)) return res.status(400).json({ error: 'Invalid key' });
    let state = await models.PortalState.findOne({ key: 'main' });
    if (!state) state = new models.PortalState({ key: 'main' });
    state[key] = req.body;
    await state.save();
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/user/profile', authMiddleware, async (req, res) => {
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

app.get('/api/user/profile', authMiddleware, async (req, res) => {
  const emailKey = (req.user.email || '').replace(/[^a-z0-9]/gi, '_');
  const p = await models.UserProfile.findOne({ emailKey }).lean();
  res.json(p || {});
});

/* ——— Admin CMS ——— */
app.put('/api/admin/projects', authMiddleware, adminOnly, async (req, res) => {
  try {
    const arr = Array.isArray(req.body) ? req.body : [];
    await models.WebsiteProject.deleteMany({});
    for (let i = 0; i < arr.length; i++) {
      const p = arr[i];
      await models.WebsiteProject.create({
        slug: p.slug || String(p.title || 'project')
          .toLowerCase()
          .replace(/\s+/g, '-')
          .replace(/[^a-z0-9-]/g, '') + '-' + (i + 1),
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

/* Static site (same origin as API) */
app.use(express.static(root));

mongoose
  .connect(MONGODB_URI)
  .then(() => {
    console.log('MongoDB connected');
    app.listen(PORT, () => {
      console.log(`AIS Concepts server http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error('MongoDB connection failed', err);
    process.exit(1);
  });
