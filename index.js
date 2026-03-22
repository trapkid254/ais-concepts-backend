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

// --- 1. Initialize Express ---
const app = express();

// --- 2. Middleware ---
function resolveCorsOrigin() {
  const raw = process.env.CLIENT_ORIGIN;
  if (!raw || raw === 'true') return true;
  const parts = raw.split(',').map((s) => s.trim()).filter(Boolean);
  if (parts.length === 0) return true;
  if (parts.length === 1) return parts[0];
  return parts;
}

app.use(cors({
  origin: resolveCorsOrigin(),
  credentials: true
}));
app.use(cookieParser());
app.use(express.json({ limit: '12mb' }));

// --- 3. Serve frontend static files ---
const root = path.join(__dirname, '../frontend');
app.use(express.static(root));

// --- 4. Helper ---
function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
}

// --- 5. Auth Routes ---
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
        avatar: user.avatar || `https://ui-avatars.com/api/?name=${encodeURIComponent(user.name || user.email)}&background=20c4b4&color=fff&size=128`
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
    if (!passwordOk || user.role !== role) return res.status(401).json({ error: 'Invalid credentials' });

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
        avatar: user.avatar || `https://ui-avatars.com/api/?name=${encodeURIComponent(user.name || user.email)}&background=20c4b4&color=fff&size=128`
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
      role: u.role,
      name: u.name,
      phone: u.phone,
      avatar: u.avatar,
      loginTime: u.lastLogin
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// --- 6. Public API ---
app.get('/api/projects', async (req, res) => {
  try {
    const list = await models.WebsiteProject.find().sort({ sortOrder: 1, title: 1 }).lean();
    res.json(list.map((p, i) => ({
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
    })));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/projects/detail/:slug', async (req, res) => {
  try {
    const p = await models.WebsiteProject.findOne({ slug: req.params.slug }).lean();
    if (!p) return res.status(404).json({ error: 'Not found' });
    res.json(p);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/services', async (req, res) => {
  const list = await models.WebsiteService.find().sort({ sortOrder: 1 }).lean();
  res.json(list);
});

app.get('/api/blog', async (req, res) => {
  const list = await models.BlogPost.find().sort({ sortOrder: 1 }).lean();
  res.json(list);
});

app.get('/api/site/home', async (req, res) => {
  const doc = await models.SiteContent.findOne({ key: 'home' }).lean();
  res.json({
    testimonials: doc?.testimonials || [],
    partners: doc?.partners || []
  });
});

// --- 7. Forms ---
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
    await models.ProjectEnquiry.create({ ...body, fileName, fileData });
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

// --- 8. Admin routes ---
function setupAdminRoutes() {
  const PORTAL_KEYS = [
    'assignments', 'portalInvoices', 'portalMessages', 'clientSupportTickets',
    'portalUsers', 'portalProjects', 'clientProjects', 'clientDocuments',
    'clientInvoices', 'careerApplications', 'employeeTasks', 'employeeTaskUpdates',
    'employeeTimeEntries', 'employeeProgress', 'employeeAssignmentStatus', 'adminSettings'
  ];

  app.get('/api/portal/bootstrap', authMiddleware, async (req, res) => {
    const state = await models.PortalState.findOne({ key: 'main' }).lean() || {};
    const profile = await models.UserProfile.findOne({ emailKey: (req.user.email || '').replace(/[^a-z0-9]/gi, '_') }).lean();
    res.json({ ...state, profile });
  });

  app.put('/api/portal/key/:key', authMiddleware, async (req, res) => {
    const { key } = req.params;
    if (!PORTAL_KEYS.includes(key)) return res.status(400).json({ error: 'Invalid key' });
    let state = await models.PortalState.findOne({ key: 'main' });
    if (!state) state = new models.PortalState({ key: 'main' });
    state[key] = req.body;
    await state.save();
    res.json({ ok: true });
  });
}
setupAdminRoutes();

// --- 9. Connect to MongoDB and start server ---
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/ais_concepts';

mongoose
  .connect(MONGODB_URI)
  .then(() => {
    console.log('MongoDB connected');
    app.listen(PORT, () => {
      console.log(`AIS Concepts backend running on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error('MongoDB connection failed', err);
    process.exit(1);
  });