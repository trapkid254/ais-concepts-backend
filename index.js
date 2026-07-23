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
const BSON = require('bson');
const cloudinary = require('cloudinary').v2;

const { signToken, authMiddleware, verifyToken, JWT_SECRET } = require('./auth');
const models = require('./models');
const { validatePasswordPolicy } = require('./passwordPolicy');
const {
  WEBSITE_PROJECT_CATEGORIES,
  LEGACY_WEBSITE_PROJECT_CATEGORIES,
  isValidWebsiteProjectCategory
} = require('./projectCategories');

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const cloudinaryConfigured = Boolean(
  process.env.CLOUDINARY_CLOUD_NAME &&
  process.env.CLOUDINARY_API_KEY &&
  process.env.CLOUDINARY_API_SECRET
);
if (!cloudinaryConfigured) {
  console.warn('⚠️ Cloudinary env vars missing (CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET). /api/upload-image will fail until set on Render.');
}

const MAX_IMAGE_BYTES = 50 * 1024 * 1024;
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_IMAGE_BYTES } });

function uploadBufferToCloudinary(buffer) {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { folder: 'ais-concepts/projects', resource_type: 'image' },
      (error, result) => {
        if (error) reject(error);
        else resolve(result);
      }
    );
    stream.end(buffer);
  });
}

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

// Manual CORS middleware as fallback
app.use((req, res, next) => {
  const allowedOrigins = resolveCorsOrigin();
  const origin = req.headers.origin;
  
  console.log('Manual CORS - origin:', origin, 'allowed:', allowedOrigins);
  
  res.setHeader('Access-Control-Allow-Origin', origin || '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  
  next();
});

app.use(
  cors({
    origin: resolveCorsOrigin(),
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    preflightContinue: false
  })
);
app.use(cookieParser());
app.use(express.json({ limit: '50mb' }));

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
  if (targets.includes('*')) return role === 'admin';
  if (email && targets.includes(email)) return true;
  if (role && targets.includes(role)) return true;
  return false;
}

async function loadDbUser(req) {
  const u = await models.User.findById(req.user.sub).lean();
  if (!u) return null;
  return {
    ...req.user,
    _id: String(u._id),
    id: String(u._id),
    name: u.name,
    email: u.email,
    role: u.role,
    assignedProjects: (u.assignedProjects || []).map(String),
    workerAssignments: (u.workerAssignments || []).map(String)
  };
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    next();
  };
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
    const { role, status } = req.query;
    const filter = {};
    if (role) filter.role = String(role).toLowerCase();
    if (status === 'approved') {
      filter.$or = [
        { approvalStatus: 'approved' },
        { approvalStatus: { $exists: false } },
        { role: 'admin' }
      ];
    } else if (status === 'pending') {
      filter.approvalStatus = 'pending';
    }
    const users = await models.User.find(filter)
      .select('-passwordHash')
      .sort({ createdAt: -1 });
    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/users/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    const user = await models.User.findById(req.params.id).select('-passwordHash').lean();
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (error) {
    console.error('Error fetching user:', error);
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
    const { name, email, password, assignedProjects, phone, username } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const policyErr = validatePasswordPolicy(password);
    if (policyErr) return res.status(400).json({ error: policyErr });

    const exists = await models.User.findOne({ email: email.toLowerCase() });
    if (exists) return res.status(400).json({ error: 'Email already registered' });

    const passwordHash = await bcrypt.hash(password, 10);
    // Public registration may only create employee accounts (never admin/foreman).
    await models.User.create({
      email: email.toLowerCase(),
      passwordHash,
      role: 'employee',
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
        _id: String(user._id),
        id: String(user._id),
        email: user.email,
        username: user.username || '',
        role: user.role,
        name: user.name,
        phone: user.phone || '',
        assignedProjects: (user.assignedProjects || []).map(String),
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
      _id: String(u._id),
      id: String(u._id),
      email: u.email,
      username: u.username,
      role: u.role,
      name: u.name,
      phone: u.phone,
      avatar: u.avatar,
      assignedProjects: (u.assignedProjects || []).map(String),
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
    const roleFilter = req.query.role ? String(req.query.role).toLowerCase() : '';
    const base = {
      $or: [
        { role: 'admin' },
        { approvalStatus: 'approved' },
        { role: { $in: ['client', 'employee', 'foreman'] }, approvalStatus: { $exists: false } }
      ]
    };
    const filter = roleFilter ? { $and: [base, { role: roleFilter }] } : base;
    const list = await models.User.find(filter)
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

app.put('/api/admin/users/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    const target = await models.User.findById(req.params.id);
    if (!target) return res.status(404).json({ error: 'User not found' });

    const { name, email, role, status } = req.body || {};
    if (name != null) target.name = String(name).trim() || target.name;
    if (email != null) {
      const nextEmail = String(email).trim().toLowerCase();
      if (nextEmail && nextEmail !== target.email) {
        const exists = await models.User.findOne({ email: nextEmail, _id: { $ne: target._id } });
        if (exists) return res.status(400).json({ error: 'Email already in use' });
        target.email = nextEmail;
      }
    }
    if (role != null) {
      const nextRole = String(role).toLowerCase();
      if (['client', 'employee', 'admin', 'foreman'].includes(nextRole)) {
        if (target.role === 'admin' && nextRole !== 'admin') {
          const admins = await models.User.countDocuments({ role: 'admin' });
          if (admins <= 1) return res.status(400).json({ error: 'Cannot demote the only admin' });
        }
        target.role = nextRole;
      }
    }
    if (status != null) {
      const s = String(status).toLowerCase();
      if (s === 'inactive' || s === 'suspended') {
        target.approvalStatus = 'pending';
      } else if (s === 'active' || s === 'approved') {
        target.approvalStatus = 'approved';
      }
    }
    await target.save();
    res.json({
      ok: true,
      user: {
        id: String(target._id),
        name: target.name || target.email,
        email: target.email,
        role: target.role ? target.role.charAt(0).toUpperCase() + target.role.slice(1) : '',
        status:
          target.role === 'admin'
            ? 'Active'
            : target.approvalStatus === 'pending'
              ? 'Pending'
              : 'Active',
        lastLogin: target.lastLogin ? new Date(target.lastLogin).toISOString() : '-'
      }
    });
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

// Helper: Extract public ID from Cloudinary URL
function extractPublicIdFromCloudinaryUrl(url) {
  if (!url || typeof url !== 'string') return null;
  // URL format: https://res.cloudinary.com/{cloud_name}/image/upload/v{version}/{public_id}.ext
  const match = url.match(/\/image\/upload\/(?:v\d+\/)?(.+?)(?:\.[a-z]+)?$/i);
  return match ? match[1] : null;
}

// Helper: Delete images from Cloudinary by URL
async function deleteCloudinaryImages(imageUrls) {
  if (!imageUrls || !Array.isArray(imageUrls)) return;
  
  for (const url of imageUrls) {
    try {
      const publicId = extractPublicIdFromCloudinaryUrl(url);
      if (publicId) {
        await cloudinary.uploader.destroy(publicId);
        console.log(`🗑️ Deleted from Cloudinary: ${publicId}`);
      }
    } catch (err) {
      console.error(`⚠️ Failed to delete Cloudinary image: ${err.message}`);
    }
  }
}

function getWebsiteProjectGallery(p) {
  const src = p || {};
  let asDesignedImages = Array.isArray(src.asDesignedImages) ? src.asDesignedImages.filter(Boolean) : [];
  let asBuiltImages = Array.isArray(src.asBuiltImages) ? src.asBuiltImages.filter(Boolean) : [];

  if (!asDesignedImages.length && !asBuiltImages.length && Array.isArray(src.projectImages)) {
    asDesignedImages = src.projectImages.filter(Boolean);
  }

  const featured = asDesignedImages[0] || asBuiltImages[0] || src.image || '';
  return {
    asDesignedImages,
    asBuiltImages,
    projectImages: asDesignedImages.length ? asDesignedImages : asBuiltImages,
    image: featured,
    heroImage: src.heroImage || featured
  };
}

function collectProjectImageUrls(p) {
  const gallery = getWebsiteProjectGallery(p);
  const urls = new Set();
  gallery.asDesignedImages.forEach((url) => urls.add(url));
  gallery.asBuiltImages.forEach((url) => urls.add(url));
  if (Array.isArray(p.projectImages)) p.projectImages.forEach((url) => { if (url) urls.add(url); });
  if (p.image) urls.add(p.image);
  if (p.heroImage) urls.add(p.heroImage);
  return urls;
}

app.post('/api/upload-image', authMiddleware, adminOnly, (req, res) => {
  upload.single('image')(req, res, async (multerErr) => {
    if (multerErr) {
      if (multerErr.code === 'LIMIT_FILE_SIZE') {
        return res.status(413).json({
          error: 'File too large',
          details: `Maximum image size is ${MAX_IMAGE_BYTES / 1024 / 1024}MB per file`
        });
      }
      console.error('Multer upload error:', multerErr.message);
      return res.status(400).json({ error: 'Upload error', details: multerErr.message });
    }

    try {
      if (!cloudinaryConfigured) {
        return res.status(503).json({
          error: 'Image upload not configured',
          details: 'Cloudinary credentials are missing on the server. Set CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, and CLOUDINARY_API_SECRET in Render environment variables.'
        });
      }

      if (!req.file) {
        return res.status(400).json({ error: 'No image provided' });
      }

      const result = await uploadBufferToCloudinary(req.file.buffer);

      console.log(`✅ Image uploaded to Cloudinary: ${result.public_id}`);
      res.json({
        ok: true,
        url: result.secure_url,
        public_id: result.public_id,
        size: result.bytes
      });
    } catch (e) {
      console.error('Cloudinary upload error:', e.message || e);
      res.status(500).json({ error: 'Image upload failed', details: e.message || String(e) });
    }
  });
});

/* ——— Public CMS & Authenticated Project API ——— */
app.get('/api/project-categories', (req, res) => {
  res.json({
    categories: WEBSITE_PROJECT_CATEGORIES,
    legacy: LEGACY_WEBSITE_PROJECT_CATEGORIES
  });
});

app.get('/api/projects', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    const { client } = req.query;

    // If authenticated and requesting client-specific projects
    if (authHeader && client) {
      try {
        const decoded = jwt.verify(authHeader.replace('Bearer ', ''), JWT_SECRET);
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
        const decoded = jwt.verify(authHeader.replace('Bearer ', ''), JWT_SECRET);
        if (decoded.role === 'admin') {
          const projects = await models.EnhancedProject.find().populate('client', 'name email').sort({ createdAt: -1 }).lean();
          return res.json(projects.map((p) => ({
            ...p,
            id: String(p._id),
            workerCount: Array.isArray(p.workers) ? p.workers.length : 0,
            employeeCount: Array.isArray(p.assignedEmployees) ? p.assignedEmployees.length : 0,
            deadline: p.endDate ? new Date(p.endDate).toISOString().slice(0, 10) : ''
          })));
        }
        if (decoded.role === 'foreman') {
          const foremanOid = mongoose.Types.ObjectId.isValid(decoded.sub)
            ? new mongoose.Types.ObjectId(decoded.sub)
            : null;
          const dbForeman = foremanOid
            ? await models.User.findById(foremanOid).select('assignedProjects').lean()
            : null;
          const or = [];
          if (foremanOid) {
            or.push({ foremanId: foremanOid });
            or.push({ foremanId: String(decoded.sub) });
          }
          if (dbForeman?.assignedProjects?.length) {
            or.push({ _id: { $in: dbForeman.assignedProjects } });
          }
          const projects = or.length
            ? await models.EnhancedProject.find({ $or: or }).populate('client', 'name email').sort({ createdAt: -1 }).lean()
            : [];
          return res.json(projects.map((p) => ({
            ...p,
            id: String(p._id),
            workerCount: Array.isArray(p.workers) ? p.workers.length : 0,
            employeeCount: Array.isArray(p.assignedEmployees) ? p.assignedEmployees.length : 0,
            deadline: p.endDate ? new Date(p.endDate).toISOString().slice(0, 10) : ''
          })));
        }
        // Employee can see projects they're assigned to (via assignedEmployees + User.assignedProjects)
        if (decoded.role === 'employee') {
          const employeeOid = mongoose.Types.ObjectId.isValid(decoded.sub)
            ? new mongoose.Types.ObjectId(decoded.sub)
            : null;
          const dbEmployee = employeeOid
            ? await models.User.findById(employeeOid).select('assignedProjects email').lean()
            : null;
          const or = [];
          if (employeeOid) {
            or.push({ 'assignedEmployees.employeeId': employeeOid });
            // Legacy rows may have stored employeeId as a string
            or.push({ 'assignedEmployees.employeeId': String(decoded.sub) });
          }
          if (dbEmployee && Array.isArray(dbEmployee.assignedProjects) && dbEmployee.assignedProjects.length) {
            or.push({ _id: { $in: dbEmployee.assignedProjects } });
          }
          const projects = or.length
            ? await models.EnhancedProject.find({ $or: or }).populate('client', 'name email').sort({ createdAt: -1 })
            : [];
          return res.json(projects);
        }
        // Authenticated but unknown portal role — do not fall through to public website portfolio
        return res.json([]);
      } catch (e) {
        // Token invalid, fall through to public
      }
    }

    // Public: return website portfolio projects
    const list = await models.WebsiteProject.find().sort({ sortOrder: 1, title: 1 }).lean();
    const mapped = list.map((p, i) => {
      // Prepare metrics - only include if values exist
      const metrics = {};
      if (p.metrics && typeof p.metrics === 'object') {
        if (p.metrics.costEfficiency != null) metrics.costEfficiency = p.metrics.costEfficiency;
        if (p.metrics.sustainability != null) metrics.sustainability = p.metrics.sustainability;
        if (p.metrics.innovation != null) metrics.innovation = p.metrics.innovation;
      }
      
      const gallery = getWebsiteProjectGallery(p);
      
      return {
        id: p._id,
        slug: p.slug,
        title: p.title,
        category: p.category,
        categorySecondary: p.categorySecondary,
        image: gallery.image,
        heroImage: gallery.heroImage,
        projectImages: gallery.projectImages,
        asDesignedImages: gallery.asDesignedImages,
        asBuiltImages: gallery.asBuiltImages,
        description: p.description,
        conceptSketches: p.conceptSketches || [],
        siteAnalysis: p.siteAnalysis || [],
        floorPlans: p.floorPlans || [],
        renderings: p.renderings || [],
        constructionPhotos: p.constructionPhotos || [],
        completedPhotos: p.completedPhotos || [],
        metrics: metrics,
        hasMetrics: Object.keys(metrics).length > 0,
        featuredOnHomepage: !!p.featuredOnHomepage,
        homeSortOrder: p.homeSortOrder != null ? p.homeSortOrder : 0
      };
    });
    res.json(mapped);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/projects/detail/:slug', async (req, res) => {
  try {
    console.log(`\n📥 GET /api/projects/detail/${req.params.slug}`);
    const p = await models.WebsiteProject.findOne({ slug: req.params.slug }).lean();
    if (!p) {
      console.log('❌ Project not found');
      return res.status(404).json({ error: 'Not found' });
    }
    
    console.log(`✓ Found project: "${p.title}"`);
    console.log(`  projectImages in DB: ${p.projectImages ? p.projectImages.length + ' images' : 'MISSING'}`);
    if (p.projectImages && p.projectImages.length > 0) {
      p.projectImages.forEach((img, i) => {
        console.log(`    Image ${i + 1}: ${img.substring(0, 40)}... (${img.length} chars)`);
      });
    }
    
    // Prepare metrics - only include if values exist
    const metrics = {};
    if (p.metrics && typeof p.metrics === 'object') {
      if (p.metrics.costEfficiency != null) metrics.costEfficiency = p.metrics.costEfficiency;
      if (p.metrics.sustainability != null) metrics.sustainability = p.metrics.sustainability;
      if (p.metrics.innovation != null) metrics.innovation = p.metrics.innovation;
    }
    
    const gallery = getWebsiteProjectGallery(p);
    
    const response = {
      id: p._id,
      slug: p.slug,
      title: p.title,
      category: p.category,
      categorySecondary: p.categorySecondary,
      image: gallery.image,
      heroImage: gallery.heroImage,
      projectImages: gallery.projectImages,
      asDesignedImages: gallery.asDesignedImages,
      asBuiltImages: gallery.asBuiltImages,
      description: p.description,
      conceptSketches: p.conceptSketches || [],
      siteAnalysis: p.siteAnalysis || [],
      floorPlans: p.floorPlans || [],
      renderings: p.renderings || [],
      constructionPhotos: p.constructionPhotos || [],
      completedPhotos: p.completedPhotos || [],
      metrics: metrics,
      hasMetrics: Object.keys(metrics).length > 0,
      featuredOnHomepage: !!p.featuredOnHomepage,
      homeSortOrder: p.homeSortOrder != null ? p.homeSortOrder : 0
    };
    
    console.log(`📤 Returning ${response.projectImages.length} images to client`);
    res.json(response);
  } catch (e) {
    console.error('❌ Error fetching project detail:', e.message);
    res.status(500).json({ error: 'Server error', details: e.message });
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

async function sendWebsiteContactEmail({ name, email, phone, message }) {
  const to = process.env.CONTACT_TO_EMAIL || 'aisconceptsltd@gmail.com';
  const subject = `AIS Concepts website inquiry from ${name}`;
  const text = [
    `Name: ${name}`,
    `Email: ${email}`,
    phone ? `Phone: ${phone}` : '',
    '',
    'Message:',
    message
  ].filter(Boolean).join('\n');

  if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
    try {
      const nodemailer = require('nodemailer');
      const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: parseInt(process.env.SMTP_PORT || '587', 10),
        secure: process.env.SMTP_SECURE === 'true',
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS
        }
      });
      await transporter.sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to,
        replyTo: email,
        subject,
        text
      });
      return true;
    } catch (mailErr) {
      console.error('Contact email send failed:', mailErr.message);
    }
  }
  console.log('Contact message saved (configure SMTP_* env to email):', { to, name, email });
  return false;
}

app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, phone, message } = req.body;
    if (!name || !email || !message) {
      return res.status(400).json({ error: 'Name, email, and message are required.' });
    }
    const trimmedName = String(name).trim();
    const trimmedEmail = String(email).trim();
    const trimmedPhone = phone ? String(phone).trim() : '';
    const trimmedMessage = String(message).trim();

    await models.ContactMessage.create({
      name: trimmedName,
      email: trimmedEmail,
      phone: trimmedPhone,
      message: trimmedMessage
    });

    await models.ProjectEnquiry.create({
      name: trimmedName,
      type: 'Project inquiry',
      contact: trimmedPhone ? `${trimmedEmail} | ${trimmedPhone}` : trimmedEmail,
      location: '',
      timeline: '',
      budget: '',
      message: trimmedMessage,
      source: 'contact'
    });

    await sendWebsiteContactEmail({
      name: trimmedName,
      email: trimmedEmail,
      phone: trimmedPhone,
      message: trimmedMessage
    });
    res.json({ ok: true, message: 'Thank you. Your message has been received.' });
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
      message: body.message ? String(body.message).trim() : '',
      source: 'homepage',
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
    const { resume, portfolioType, portfolioPhotos, portfolioUrl, portfolioPdf } = req.body;
    
    // CV/Resume is now mandatory
    if (!resume) {
      return res.status(400).json({ error: 'CV/Resume is required for career applications.' });
    }
    
    // Prepare portfolio data
    const portfolio = {};
    if (portfolioType === 'photos' && portfolioPhotos && portfolioPhotos.length > 0) {
      portfolio.type = 'photos';
      portfolio.photos = portfolioPhotos.slice(0, 10); // Max 10 photos
    } else if (portfolioType === 'url' && portfolioUrl) {
      portfolio.type = 'url';
      portfolio.url = portfolioUrl;
    } else if (portfolioType === 'pdf' && portfolioPdf) {
      portfolio.type = 'pdf';
      portfolio.pdf = portfolioPdf;
    }
    
    await models.CareerApplication.create({ 
      fields: req.body,
      portfolio: portfolio,
      resume: resume
    });
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
  'faqs',
  'portalClients',
  'adminFundRequests',
  'adminCommunications',
  'adminSites',
  'adminFinancials',
  'adminApprovals',
  'adminPortfolio',
  'adminTasks'
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
    const entry = {
      taskId: project,
      project,
      projectName: project,
      description: String(description).trim(),
      message: String(description).trim(),
      images: imgs,
      imageData: imgs[0] || null,
      date: new Date().toISOString(),
      createdAt: new Date().toISOString(),
      employeeEmail: u.email,
      clientEmail: (match.clientEmail || '').toLowerCase()
    };
    updates.push(entry);
    const clientUpdates = [...(state.adminClientProgressUpdates || [])];
    if (entry.clientEmail) {
      clientUpdates.push({
        clientEmail: entry.clientEmail,
        projectName: project,
        projectId: match.projectId || '',
        message: entry.description,
        createdAt: entry.createdAt,
        from: u.email
      });
    }
    await models.PortalState.findOneAndUpdate(
      { key: 'main' },
      { $set: { employeeTaskUpdates: updates, adminClientProgressUpdates: clientUpdates } },
      { upsert: true, new: true }
    );
    const snippet = String(description).trim().slice(0, 120);
    await broadcastNotification({
      title: 'Employee progress update',
      message: `${u.name || u.email} updated "${project}": ${snippet}${snippet.length < String(description).trim().length ? '…' : ''}`,
      targets: ['admin']
    });
    const clientEmail = (match.clientEmail || '').toLowerCase();
    if (clientEmail) {
      await broadcastNotification({
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

    const email = (req.user.email || '').toLowerCase();
    const role = req.user.role;
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
      clientTransactions: state.clientTransactions || [],
      clientNotifications: state.clientNotifications || [],
      careerApplications: state.careerApplications || [],
      employeeTasks: state.employeeTasks || [],
      employeeTaskUpdates: state.employeeTaskUpdates || [],
      employeeTimeEntries: state.employeeTimeEntries || [],
      employeeProgress: state.employeeProgress || [],
      employeeAssignmentStatus: state.employeeAssignmentStatus || {},
      adminSettings: state.adminSettings || {},
      adminClientProgressUpdates: state.adminClientProgressUpdates || [],
      portalClients: state.portalClients || [],
      adminFundRequests: state.adminFundRequests || [],
      adminCommunications: state.adminCommunications || [],
      adminSites: state.adminSites || [],
      adminFinancials: state.adminFinancials || [],
      adminApprovals: state.adminApprovals || [],
      adminPortfolio: state.adminPortfolio || [],
      adminTasks: state.adminTasks || [],
      faqs: state.faqs || []
    };

    if (role !== 'admin') {
      payload.portalUsers = [];
      payload.portalClients = [];
      payload.adminFundRequests = [];
      payload.adminCommunications = [];
      payload.adminSites = [];
      payload.adminFinancials = [];
      payload.adminApprovals = [];
      payload.adminPortfolio = [];
      payload.adminSettings = {};
      payload.faqs = [];
      payload.careerApplications = [];
      // Non-admins do not get the full admin task board; employees get filtered below
      if (role !== 'employee') payload.adminTasks = [];

      payload.portalMessages = (payload.portalMessages || []).filter((m) => {
        const to = String(m.to || '').toLowerCase();
        const from = String(m.from || '').toLowerCase();
        return to === email || from === email;
      });

      if (role === 'client') {
        payload.assignments = [];
        payload.employeeTasks = [];
        payload.employeeTaskUpdates = (payload.employeeTaskUpdates || []).filter(
          (x) => String(x.clientEmail || '').toLowerCase() === email
        );
        payload.employeeTimeEntries = [];
        payload.employeeProgress = [];
        payload.employeeAssignmentStatus = {};
        payload.clientSupportTickets = (payload.clientSupportTickets || []).filter(
          (t) => String(t.email || '').toLowerCase() === email
        );
        payload.portalInvoices = (payload.portalInvoices || []).filter(
          (i) => String(i.client || i.clientEmail || '').toLowerCase() === email
        );
        payload.clientInvoices = (payload.clientInvoices || []).filter(
          (i) => String(i.client || i.clientEmail || '').toLowerCase() === email
        );
        payload.clientDocuments = (payload.clientDocuments || []).filter(
          (d) => String(d.clientEmail || d.uploadedBy || '').toLowerCase() === email
        );
        payload.clientProjects = (payload.clientProjects || []).filter(
          (p) => String(p.clientEmail || p.email || '').toLowerCase() === email
        );
        payload.portalProjects = [];
        payload.adminClientProgressUpdates = (payload.adminClientProgressUpdates || []).filter(
          (x) => String(x.clientEmail || '').toLowerCase() === email
        );
      } else if (role === 'employee') {
        payload.portalInvoices = [];
        payload.clientInvoices = [];
        payload.clientDocuments = [];
        payload.clientProjects = [];
        payload.clientSupportTickets = [];
        payload.clientTransactions = [];
        payload.clientNotifications = [];
        payload.portalProjects = [];
        payload.adminClientProgressUpdates = [];
        payload.assignments = (payload.assignments || []).filter(
          (a) => String(a.employeeEmail || '').toLowerCase() === email
        );
        // Always merge live assignments from EnhancedProject so portal stays in sync with admin assigns
        try {
          const employeeOid = mongoose.Types.ObjectId.isValid(req.user.sub)
            ? new mongoose.Types.ObjectId(req.user.sub)
            : null;
          const dbEmployee = employeeOid
            ? await models.User.findById(employeeOid).select('assignedProjects email').lean()
            : null;
          const or = [];
          if (employeeOid) {
            or.push({ 'assignedEmployees.employeeId': employeeOid });
            or.push({ 'assignedEmployees.employeeId': String(req.user.sub) });
          }
          if (dbEmployee?.assignedProjects?.length) {
            or.push({ _id: { $in: dbEmployee.assignedProjects } });
          }
          if (or.length) {
            const liveProjects = await models.EnhancedProject.find({ $or: or }).select(
              'name endDate assignedEmployees'
            ).lean();
            const byKey = {};
            (payload.assignments || []).forEach((a) => {
              const k = String(a.project || '') + '|' + String(a.employeeEmail || '').toLowerCase();
              byKey[k] = a;
            });
            liveProjects.forEach((p) => {
              const entry = (p.assignedEmployees || []).find(
                (a) =>
                  String(a.employeeId) === String(req.user.sub) ||
                  String(a.employeeId) === String(employeeOid)
              );
              const deadline = p.endDate ? new Date(p.endDate).toISOString().slice(0, 10) : '';
              const row = {
                project: p.name,
                employeeEmail: email,
                due: deadline,
                deadline: deadline,
                notes: (entry && entry.duties) || '',
                projectId: String(p._id)
              };
              const k = String(row.project) + '|' + email;
              byKey[k] = Object.assign({}, byKey[k] || {}, row);
            });
            payload.assignments = Object.keys(byKey).map((k) => byKey[k]);
          }
        } catch (syncErr) {
          console.error('Employee assignment sync in bootstrap:', syncErr.message || syncErr);
        }
        payload.employeeTimeEntries = (payload.employeeTimeEntries || []).filter(
          (e) => String(e.employeeEmail || e.email || '').toLowerCase() === email
        );
        payload.employeeTaskUpdates = (payload.employeeTaskUpdates || []).filter(
          (x) => String(x.employeeEmail || '').toLowerCase() === email
        );
        // Tasks assigned via Admin Task Management
        const myTasks = (payload.adminTasks || []).filter((t) => {
          const assignee = String(t.assigneeEmail || t.employeeEmail || '').toLowerCase();
          const assigneeId = String(t.assignee || t.assigneeId || '');
          return assignee === email || (assigneeId && assigneeId === String(req.user.sub));
        });
        payload.adminTasks = myTasks;
        payload.employeeTasks = myTasks;
        // Merge task projects into assignments so Projects tab shows them
        myTasks.forEach((t) => {
          if (!t.projectName && !t.project) return;
          const projectLabel = t.projectName || t.project;
          const exists = (payload.assignments || []).some(
            (a) =>
              String(a.project || '').toLowerCase() === String(projectLabel).toLowerCase() ||
              (t.projectId && String(a.projectId) === String(t.projectId))
          );
          if (!exists) {
            payload.assignments = payload.assignments || [];
            payload.assignments.push({
              project: projectLabel,
              employeeEmail: email,
              due: t.dueDate || '',
              deadline: t.dueDate || '',
              notes: t.title || t.description || '',
              projectId: t.projectId || t.project || '',
              fromTask: true
            });
          }
        });
        const status = payload.employeeAssignmentStatus || {};
        payload.employeeAssignmentStatus = Object.keys(status).reduce((acc, k) => {
          if (String(k).toLowerCase().includes(email) || status[k]?.employeeEmail === email) {
            acc[k] = status[k];
          }
          return acc;
        }, {});
      } else if (role === 'foreman') {
        payload.assignments = [];
        payload.portalInvoices = [];
        payload.clientInvoices = [];
        payload.clientDocuments = [];
        payload.clientProjects = [];
        payload.clientSupportTickets = [];
        payload.employeeTasks = [];
        payload.employeeTaskUpdates = [];
        payload.employeeTimeEntries = [];
        payload.employeeProgress = [];
        payload.employeeAssignmentStatus = {};
        payload.adminClientProgressUpdates = [];
        payload.portalProjects = [];
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
    const portalState = await models.PortalState.findOne({ key: 'main' }).lean();
    let data = portalState ? portalState[key] : undefined;
    if (data === undefined && portalState && portalState.data) data = portalState.data[key];
    if (data === undefined) data = key === 'employeeAssignmentStatus' || key === 'adminSettings' ? {} : [];
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
    // Non-admins may only write keys that belong to their role workflows
    const role = req.user.role;
    const adminOnlyKeys = [
      'portalUsers', 'portalClients', 'adminFundRequests', 'adminCommunications',
      'adminSites', 'adminFinancials', 'adminApprovals', 'adminPortfolio',
      'adminSettings', 'faqs', 'careerApplications', 'portalProjects', 'adminTasks'
    ];
    if (role !== 'admin' && adminOnlyKeys.includes(key)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    const body = req.body;
    await models.PortalState.findOneAndUpdate(
      { key: 'main' },
      { $set: { [key]: body } },
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
    const profileUpdate = {
      emailKey,
      name: req.body.name,
      email: req.body.email,
      phone: req.body.phone,
      avatar: req.body.avatar
    };
    await models.UserProfile.findOneAndUpdate({ emailKey }, profileUpdate, { upsert: true });
    const userUpdate = {
      ...(req.body.name ? { name: req.body.name } : {}),
      ...(req.body.email ? { email: req.body.email.toLowerCase() } : {}),
      ...(req.body.avatar ? { avatar: req.body.avatar } : {}),
      ...(req.body.phone ? { phone: req.body.phone } : {})
    };
    if (req.body.password) {
      const policyErr = validatePasswordPolicy(req.body.password);
      if (policyErr) return res.status(400).json({ error: policyErr });
      userUpdate.passwordHash = await bcrypt.hash(req.body.password, 10);
    }
    if (Object.keys(userUpdate).length) {
      await models.User.findByIdAndUpdate(req.user.sub, userUpdate);
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

app.get('/api/admin/projects/estimate-size', authMiddleware, adminOnly, (req, res) => {
  try {
    // Estimate BSON size of a minimal project document (no images)
    const minimalProject = {
      slug: 'test-project-1',
      title: 'Test Project',
      category: 'Commercial',
      categorySecondary: 'Interior',
      image: '',
      heroImage: '',
      projectImages: [],
      description: 'Sample description for a project.',
      conceptSketches: [],
      siteAnalysis: [],
      floorPlans: [],
      renderings: [],
      constructionPhotos: [],
      completedPhotos: [],
      metrics: { costEfficiency: 80, sustainability: 75, innovation: 90 },
      sortOrder: 0,
      createdAt: new Date(),
      updatedAt: new Date()
    };
    
    const BSON = require('bson');
    const minimalBson = BSON.serialize(minimalProject);
    const minimalSize = minimalBson.length;
    
    const MONGODB_16MB_LIMIT = 16 * 1024 * 1024;
    const SAFETY_MARGIN = 0.5 * 1024 * 1024; // 500KB buffer for metadata growth
    const MAX_IMAGE_SIZE = MONGODB_16MB_LIMIT - minimalSize - SAFETY_MARGIN;
    
    res.json({
      minimalDocumentBsonSize: minimalSize,
      minimalDocumentSizeMB: (minimalSize / 1024 / 1024).toFixed(3),
      mongoDbLimit: MONGODB_16MB_LIMIT,
      mongoDbLimitMB: (MONGODB_16MB_LIMIT / 1024 / 1024).toFixed(1),
      safetyMargin: SAFETY_MARGIN,
      safetyMarginMB: (SAFETY_MARGIN / 1024 / 1024).toFixed(1),
      recommendedMaxImageSize: MAX_IMAGE_SIZE,
      recommendedMaxImageSizeMB: (MAX_IMAGE_SIZE / 1024 / 1024).toFixed(1)
    });
  } catch (e) {
    console.error('Error estimating size:', e.message);
    res.status(500).json({ error: 'Could not estimate size', details: e.message });
  }
});

app.put('/api/admin/projects', authMiddleware, adminOnly, async (req, res) => {
  try {
    console.log('========================================');
    console.log('PUT /api/admin/projects - Request received');
    console.log('========================================');
    const bodyStr = JSON.stringify(req.body);
    console.log('Request body size:', bodyStr.length, 'characters (~' + (bodyStr.length / 1024 / 1024).toFixed(2) + ' MB)');
    
    const arr = Array.isArray(req.body) ? req.body : [];
    console.log('Number of projects to save:', arr.length);
    
    arr.forEach(function(proj, idx) {
      console.log(`\n📦 Project ${idx + 1}: "${proj.title}"`);
      console.log(`   Category: ${proj.category}`);
      console.log(`   ProjectImages count: ${proj.projectImages ? proj.projectImages.length : 'MISSING'}`);
      if (proj.projectImages && proj.projectImages.length > 0) {
        proj.projectImages.forEach(function(img, imgIdx) {
          console.log(`     Image ${imgIdx + 1}: ${img.substring(0, 30)}... (${img.length} chars)`);
        });
      }
    });
    
    // Validate all incoming projects before making destructive DB changes
    // With Cloudinary URLs, image sizes are no longer a concern
    console.log(`📤 Processing ${arr.length} projects with Cloudinary image URLs`);
    for (let i = 0; i < arr.length; i++) {
      const p = arr[i];
      if (!p.title || !p.category) {
        return res.status(400).json({ error: 'validation_error', details: `Project at index ${i} missing required fields: title and/or category` });
      }
      if (!isValidWebsiteProjectCategory(p.category)) {
        return res.status(400).json({
          error: 'validation_error',
          details: `Project at index ${i} has invalid category "${p.category}". Allowed: ${WEBSITE_PROJECT_CATEGORIES.join(', ')}`
        });
      }
    }

    // All validation passed — safe to delete existing documents and recreate
    // Only delete Cloudinary images that are no longer referenced (orphaned)
    const existingProjects = await models.WebsiteProject.find({}).lean();
    const incomingUrls = new Set();
    for (const p of arr) {
      collectProjectImageUrls(p).forEach((url) => incomingUrls.add(url));
    }

    console.log(`\n🗑️ Checking ${existingProjects.length} existing projects for orphaned Cloudinary images...`);
    for (const existing of existingProjects) {
      const existingUrls = collectProjectImageUrls(existing);
      const orphaned = [...existingUrls].filter((url) => !incomingUrls.has(url));
      if (orphaned.length) {
        console.log(`   Removing ${orphaned.length} orphaned image(s) for "${existing.title}"`);
        await deleteCloudinaryImages(orphaned);
      }
    }
    
    // Now delete all projects from database
    await models.WebsiteProject.deleteMany({});

    for (let i = 0; i < arr.length; i++) {
      const p = arr[i];
      console.log(`\n➡️ Processing project ${i + 1}/${arr.length}: "${p.title}"`);

      const gallery = getWebsiteProjectGallery(p);
      const asDesignedImages = gallery.asDesignedImages;
      const asBuiltImages = gallery.asBuiltImages;
      const projectImages = gallery.projectImages;

      if (asDesignedImages.length) {
        console.log(`   ✓ As Designed images: ${asDesignedImages.length}`);
      }
      if (asBuiltImages.length) {
        console.log(`   ✓ As Built images: ${asBuiltImages.length}`);
      }
      if (!asDesignedImages.length && !asBuiltImages.length) {
        console.log(`   ⚠️ No gallery images provided`);
      }

      // Parse metrics - only include if values are provided
      let metrics = {};
      if (p.metrics) {
        if (p.metrics.costEfficiency != null) metrics.costEfficiency = p.metrics.costEfficiency;
        if (p.metrics.sustainability != null) metrics.sustainability = p.metrics.sustainability;
        if (p.metrics.innovation != null) metrics.innovation = p.metrics.innovation;
      }

      try {
        // Generate unique slug
        let generatedSlug = p.slug ||
          String(p.title || 'project')
            .toLowerCase()
            .replace(/\s+/g, '-')
            .replace(/[^a-z0-9-]/g, '') +
            '-' +
            (i + 1);

        console.log(`   Slug: ${generatedSlug}`);

        // Calculate exact BSON size before attempting to save
        const docToSave = {
          slug: generatedSlug,
          title: p.title,
          category: p.category,
          categorySecondary: p.categorySecondary || '',
          image: gallery.image || p.image || '',
          heroImage: gallery.heroImage || gallery.image || p.image || '',
          projectImages: projectImages,
          asDesignedImages: asDesignedImages,
          asBuiltImages: asBuiltImages,
          description: p.description || '',
          conceptSketches: p.conceptSketches || [],
          siteAnalysis: p.siteAnalysis || [],
          floorPlans: p.floorPlans || [],
          renderings: p.renderings || [],
          constructionPhotos: p.constructionPhotos || [],
          completedPhotos: p.completedPhotos || [],
          metrics: metrics,
          sortOrder: i,
          featuredOnHomepage: !!p.featuredOnHomepage,
          homeSortOrder: p.featuredOnHomepage && p.homeSortOrder != null ? p.homeSortOrder : 0
        };
        
        const bsonBytes = BSON.serialize(docToSave).length;
        const bsonMB = (bsonBytes / 1024 / 1024).toFixed(2);
        console.log(`   📦 Exact BSON size: ${bsonBytes} bytes (~${bsonMB} MB)`);
        
        if (bsonBytes > 16 * 1024 * 1024) {
          throw new Error(`Document size exceeds 16 MB limit (${bsonMB} MB). This includes all metadata, images, and arrays.`);
        }

        const savedProject = await models.WebsiteProject.create(docToSave);

        // Verify what was saved
        console.log(`   ✅ Project saved with projectImages count: ${savedProject.projectImages.length}`);
      } catch (createError) {
        console.error(`❌ Error saving project ${i}:`, createError.message, createError.code);
        if (createError.code === 11000) {
          throw new Error(`Duplicate slug for project "${p.title}". Please ensure each project has a unique title.`);
        }
        throw new Error(`Failed to save project "${p.title}": ${createError.message}`);
      }
    }
    console.log('\n✅ All projects saved successfully');
    console.log('========================================\n');
    res.json({ ok: true });
  } catch (e) {
    console.error('❌ Error in PUT /api/admin/projects:', e);
    res.status(500).json({ error: 'Server error', details: e.message });
  }
});

app.delete('/api/admin/projects/:projectId', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { projectId } = req.params;
    console.log(`🗑️ Delete request for website project: ${projectId}`);
    
    // Find the project
    const project = await models.WebsiteProject.findById(projectId);
    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }
    
    // Delete associated Cloudinary images
    const imageUrls = [...collectProjectImageUrls(project)];
    if (imageUrls.length) {
      console.log(`🗑️ Deleting ${imageUrls.length} Cloudinary images for project: ${project.title}`);
      await deleteCloudinaryImages(imageUrls);
    }
    
    // Delete the project
    await models.WebsiteProject.findByIdAndDelete(projectId);
    console.log(`✅ Project deleted: ${project.title}`);
    
    res.json({ ok: true, message: `Project "${project.title}" deleted successfully` });
  } catch (e) {
    console.error('❌ Error deleting project:', e);
    res.status(500).json({ error: 'Server error', details: e.message });
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
        id: String(e._id),
        name: e.name,
        contact: e.contact,
        type: e.type,
        location: e.location,
        timeline: e.timeline,
        budget: e.budget,
        message: e.message || '',
        source: e.source || 'homepage',
        date: e.createdAt
      }))
    );
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/admin/enquiries/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    const id = req.params.id;
    if (!id || id === 'undefined' || id === 'null' || !mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: 'Invalid enquiry id' });
    }
    const removed = await models.ProjectEnquiry.findByIdAndDelete(id);
    if (!removed) return res.status(404).json({ error: 'Enquiry not found' });

    if (removed.source === 'contact') {
      const emailPart = (removed.contact || '').split(' | ')[0].trim();
      if (emailPart) {
        await models.ContactMessage.deleteMany({
          name: removed.name,
          email: emailPart,
          message: removed.message || ''
        });
      }
    }

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/career-applications', authMiddleware, adminOnly, async (req, res) => {
  try {
    console.log('Fetching career applications...');
    const list = await models.CareerApplication.find().sort({ createdAt: -1 }).lean();
    console.log('Found', list.length, 'career applications');
    res.json(
      list.map((a) => {
        const f = a.fields || {};
        return {
          id: a._id || a.id,
          name: f.name,
          email: f.email,
          phone: f.phone,
          type: f.type,
          campus: f.campus,
          yearOfStudy: f.yearOfStudy,
          message: f.message,
          certificates: f.certificates || [],
          resume: f.resume || null,
          date: a.createdAt
        };
      })
    );
  } catch (e) {
    console.error('Error fetching career applications:', e.message, e.stack);
    res.status(500).json({ error: 'Server error', details: e.message });
  }
});

app.delete('/api/admin/career-applications/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    const id = req.params.id;
    const removed = await models.CareerApplication.findByIdAndDelete(id);
    if (!removed) return res.status(404).json({ error: 'Application not found' });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Database health check endpoint
app.get('/api/health/db', async (req, res) => {
  try {
    const mongooseConnection = mongoose.connection;
    if (mongooseConnection.readyState !== 1) {
      return res.status(503).json({ 
        status: 'error', 
        message: 'Database not connected',
        readyState: mongooseConnection.readyState 
      });
    }
    // Try a simple query to verify the database is responding
    await models.User.countDocuments();
    res.json({ status: 'ok', database: 'connected' });
  } catch (e) {
    console.error('Database health check failed:', e.message);
    res.status(503).json({ 
      status: 'error', 
      message: 'Database error', 
      details: e.message 
    });
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

/** Remove demo/static "Horizon Tower" project from all stores. */
async function removeStaticHorizonTowerProject() {
  const nameRe = /horizon\s*towers?/i;
  const enhanced = await models.EnhancedProject.find({ name: nameRe }).select('_id name').lean();
  const website = await models.WebsiteProject.find({
    $or: [{ title: nameRe }, { slug: /horizon/i }]
  }).select('_id title slug').lean();
  const enhancedIds = enhanced.map((p) => p._id);

  if (enhancedIds.length) {
    await models.EnhancedProject.deleteMany({ _id: { $in: enhancedIds } });
    await models.User.updateMany({}, { $pull: { assignedProjects: { $in: enhancedIds } } });
    await models.Attendance.deleteMany({ projectId: { $in: enhancedIds } });
    await models.Payroll.deleteMany({ projectId: { $in: enhancedIds } });
  }
  if (website.length) {
    await models.WebsiteProject.deleteMany({ _id: { $in: website.map((p) => p._id) } });
  }

  const state = await models.PortalState.findOne({ key: 'main' });
  if (state) {
    const scrub = (arr) =>
      (Array.isArray(arr) ? arr : []).filter((item) => {
        if (!item || typeof item !== 'object') return true;
        const label = String(item.name || item.title || item.project || item.projectName || '');
        return !nameRe.test(label);
      });
    state.assignments = scrub(state.assignments);
    state.portalProjects = scrub(state.portalProjects);
    state.clientProjects = scrub(state.clientProjects);
    state.adminPortfolio = scrub(state.adminPortfolio);
    state.markModified('assignments');
    state.markModified('portalProjects');
    state.markModified('clientProjects');
    state.markModified('adminPortfolio');
    await state.save();
  }

  if (enhanced.length || website.length) {
    console.log(
      'Removed static Horizon Tower project(s):',
      enhanced.map((p) => p.name).concat(website.map((p) => p.title || p.slug)).join(', ')
    );
  }
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
    try {
      await removeStaticHorizonTowerProject();
    } catch (e) {
      console.error('removeStaticHorizonTowerProject:', e);
    }
  })
  .catch((err) => {
    console.error('MongoDB connection failed', err);
    process.exit(1);
  });

    // ===== WORKER MANAGEMENT ENDPOINTS =====

// Worker Registration with Face Recognition (foreman only)
app.post('/api/workers/register', authMiddleware, requireApprovedAccount, requireRole('foreman', 'admin'), upload.any(), async (req, res) => {
  try {
    const dbUser = await loadDbUser(req);
    if (!dbUser) return res.status(401).json({ error: 'Unauthorized' });

    const name = req.body.name;
    const nationalId = req.body.nationalId;
    const phone = req.body.phone;
    const projectId = req.body.projectId;
    const dailyRate = parseFloat(req.body.dailyRate) || 0;
    const skills = req.body.skills || '';
    let email = (req.body.email || '').toLowerCase().trim();
    if (!email) email = `worker.${nationalId}@aisconcepts.local`.toLowerCase();

    if (!name || !nationalId || !phone || !projectId) {
      return res.status(400).json({ error: 'Missing required fields: name, nationalId, phone, projectId' });
    }

    const project = await models.EnhancedProject.findById(projectId);
    if (!project) return res.status(404).json({ error: 'Project not found' });

    const assigned = (dbUser.assignedProjects || []).map(String);
    const isForemanOfProject = String(project.foremanId || '') === String(dbUser._id);
    if (dbUser.role === 'foreman' && !isForemanOfProject && !assigned.includes(String(projectId))) {
      return res.status(403).json({ error: 'You are not assigned to this project' });
    }

    const existingWorker = await models.Worker.findOne({
      $or: [{ nationalId }, { email }, { phone }]
    });
    if (existingWorker) {
      return res.status(400).json({ error: 'Worker already exists with this national ID, email, or phone' });
    }

    const files = Array.isArray(req.files) ? req.files : [];
    const faceFiles = files.filter((f) => String(f.fieldname || '').startsWith('faceImage'));
    const livenessFile = files.find((f) => f.fieldname === 'livenessImage');

    const faceUrls = [];
    for (const file of faceFiles) {
      try {
        if (cloudinaryConfigured && file.buffer) {
          const uploaded = await uploadBufferToCloudinary(file.buffer);
          faceUrls.push(uploaded.secure_url);
        } else if (file.buffer) {
          faceUrls.push(`data:${file.mimetype};base64,${file.buffer.toString('base64')}`);
        }
      } catch (e) {
        console.error('Face upload failed', e.message || e);
      }
    }

    let livenessUrl = '';
    if (livenessFile && livenessFile.buffer) {
      try {
        if (cloudinaryConfigured) {
          const uploaded = await uploadBufferToCloudinary(livenessFile.buffer);
          livenessUrl = uploaded.secure_url;
        } else {
          livenessUrl = `data:${livenessFile.mimetype};base64,${livenessFile.buffer.toString('base64')}`;
        }
      } catch (e) {
        console.error('Liveness upload failed', e.message || e);
      }
    }

    // Also accept JSON base64 faceImages from older clients
    if (!faceUrls.length && Array.isArray(req.body.faceImages)) {
      faceUrls.push(...req.body.faceImages.filter(Boolean));
    }

    if (!faceUrls.length) {
      return res.status(400).json({ error: 'At least one face image is required' });
    }

    const worker = await models.Worker.create({
      name,
      nationalId,
      phone,
      email,
      dailyRate,
      skills,
      status: 'active',
      registeredBy: dbUser._id,
      assignedProjects: [projectId],
      faceData: {
        faceImage: faceUrls[0],
        faceEncoding: 'encoding_' + crypto.randomBytes(8).toString('hex'),
        livenessImages: [livenessUrl, ...faceUrls.slice(1)].filter(Boolean),
        registrationDate: new Date()
      }
    });

    await models.EnhancedProject.findByIdAndUpdate(projectId, { $addToSet: { workers: worker._id } });
    await models.User.findByIdAndUpdate(dbUser._id, { $addToSet: { workerAssignments: worker._id } });

    await broadcastNotification({
      title: 'New Worker Registered',
      message: `${dbUser.name || dbUser.email} registered ${name} for project ${project.name}`,
      targets: ['admin', dbUser.email]
    });

    res.status(201).json({
      success: true,
      message: 'Worker registered successfully',
      worker: {
        _id: worker._id,
        id: worker._id,
        name: worker.name,
        nationalId: worker.nationalId,
        phone: worker.phone,
        email: worker.email,
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
    let { employeeId, duties, employeeEmail } = req.body;
    const projectId = req.params.projectId;

    console.log('Assign employee request:', { employeeId, employeeEmail, duties, projectId });

    if (!employeeId && employeeEmail) {
      const byEmail = await models.User.findOne({
        email: String(employeeEmail).toLowerCase().trim(),
        role: 'employee'
      });
      if (!byEmail) return res.status(404).json({ error: 'Employee not found for that email' });
      employeeId = String(byEmail._id);
    }

    if (!employeeId) {
      return res.status(400).json({ error: 'Employee ID or email required' });
    }
    if (!mongoose.Types.ObjectId.isValid(projectId)) {
      return res.status(400).json({ error: 'Invalid project ID' });
    }
    if (!mongoose.Types.ObjectId.isValid(employeeId)) {
      return res.status(400).json({ error: 'Invalid employee ID' });
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

    const assignedList = Array.isArray(project.assignedEmployees) ? project.assignedEmployees : [];
    const alreadyAssigned = assignedList.some(
      (a) => a && String(a.employeeId) === String(employeeId)
    );

    let updatedProject;
    if (alreadyAssigned) {
      updatedProject = await models.EnhancedProject.findOneAndUpdate(
        { _id: projectId, 'assignedEmployees.employeeId': new mongoose.Types.ObjectId(employeeId) },
        {
          $set: {
            'assignedEmployees.$.duties': duties || '',
            'assignedEmployees.$.employeeName': employee.name || employee.email,
            'assignedEmployees.$.employeeEmail': employee.email
          }
        },
        { new: true, runValidators: false }
      );
      if (!updatedProject) {
        updatedProject = await models.EnhancedProject.findById(projectId);
        const entry = (updatedProject.assignedEmployees || []).find(
          (a) => String(a.employeeId) === String(employeeId)
        );
        if (entry) {
          entry.duties = duties || entry.duties || '';
          entry.employeeName = employee.name || employee.email;
          updatedProject.markModified('assignedEmployees');
          await updatedProject.save({ validateBeforeSave: false });
        }
      }
    } else {
      updatedProject = await models.EnhancedProject.findByIdAndUpdate(
        projectId,
        {
          $push: {
            assignedEmployees: {
              employeeId: employee._id,
              employeeName: employee.name || employee.email,
              employeeEmail: employee.email,
              duties: duties || '',
              assignedAt: new Date()
            }
          }
        },
        { new: true, runValidators: false }
      );
    }

    if (!updatedProject) {
      return res.status(500).json({ error: 'Failed to update project assignment' });
    }

    await models.User.findByIdAndUpdate(employeeId, {
      $addToSet: { assignedProjects: project._id }
    });

    const deadlineStr = updatedProject.endDate
      ? new Date(updatedProject.endDate).toISOString().slice(0, 10)
      : '';
    let clientEmail = '';
    try {
      const clientUser = await models.User.findById(updatedProject.client).lean();
      clientEmail = clientUser?.email || '';
    } catch (e) { /* ignore */ }

    const portalState = await models.PortalState.findOne({ key: 'main' });
    const assignments = portalState?.assignments ? portalState.assignments.slice() : [];
    const assignmentRow = {
      project: updatedProject.name,
      employeeEmail: employee.email,
      due: deadlineStr,
      deadline: deadlineStr,
      notes: duties || '',
      clientEmail: clientEmail || undefined,
      projectId: String(updatedProject._id)
    };
    const existingIdx = assignments.findIndex(
      (a) =>
        a &&
        String(a.project) === String(updatedProject.name) &&
        String(a.employeeEmail || '').toLowerCase() === String(employee.email).toLowerCase()
    );
    if (existingIdx >= 0) {
      assignments[existingIdx] = Object.assign({}, assignments[existingIdx], assignmentRow);
    } else {
      assignments.push(assignmentRow);
    }
    await models.PortalState.findOneAndUpdate(
      { key: 'main' },
      { $set: { assignments } },
      { upsert: true }
    );

    res.json({
      message: 'Employee assigned to project successfully',
      assignment: assignmentRow,
      project: {
        id: updatedProject._id,
        name: updatedProject.name,
        assignedEmployees: updatedProject.assignedEmployees
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

    const employee = await models.User.findById(employeeId).lean();
    if (employee && employee.email) {
      await models.PortalState.findOneAndUpdate(
        { key: 'main' },
        {
          $pull: {
            assignments: {
              $or: [
                { projectId: String(projectId), employeeEmail: employee.email },
                { projectId: projectId, employeeEmail: employee.email }
              ]
            }
          }
        }
      );
    }
    
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
app.get('/api/projects/:projectId', authMiddleware, requireApprovedAccount, async (req, res) => {
  try {
    const projectAccess = await models.EnhancedProject.findById(req.params.projectId).lean();
    if (!projectAccess) return res.status(404).json({ error: 'Project not found' });
    if (req.user.role === 'foreman' && String(projectAccess.foremanId || '') !== String(req.user.sub)) {
      const dbUser = await loadDbUser(req);
      if (!dbUser || !(dbUser.assignedProjects || []).map(String).includes(String(req.params.projectId))) {
        return res.status(403).json({ error: 'Access denied' });
      }
    } else if (req.user.role === 'client' && String(projectAccess.client) !== String(req.user.sub)) {
      return res.status(403).json({ error: 'Access denied' });
    } else if (req.user.role === 'employee') {
      const assigned = (projectAccess.assignedEmployees || []).some((a) => String(a.employeeId) === String(req.user.sub));
      if (!assigned) return res.status(403).json({ error: 'Access denied' });
    } else if (req.user.role !== 'admin' && req.user.role !== 'foreman' && req.user.role !== 'client' && req.user.role !== 'employee') {
      return res.status(403).json({ error: 'Access denied' });
    }
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
      foremanId: (parsedAssignedForeman?._id || parsedAssignedForeman?.id) &&
        mongoose.Types.ObjectId.isValid(String(parsedAssignedForeman._id || parsedAssignedForeman.id))
        ? (parsedAssignedForeman._id || parsedAssignedForeman.id)
        : null,
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
    const createdForemanId = parsedAssignedForeman?._id || parsedAssignedForeman?.id;
    if (createdForemanId && mongoose.Types.ObjectId.isValid(String(createdForemanId))) {
      await models.User.findByIdAndUpdate(createdForemanId, {
        $addToSet: { assignedProjects: project._id }
      });
      // Ensure project stores ObjectId, not a non-id string
      if (String(project.foremanId || '') !== String(createdForemanId)) {
        project.foremanId = createdForemanId;
        project.foremanName = parsedAssignedForeman?.name || project.foremanName || '';
        await project.save();
      }
    }
    
    // Notify assigned foreman
    try {
      const foremanUser = createdForemanId
        ? await models.User.findById(createdForemanId).lean()
        : null;
      if (foremanUser?.email) {
        await broadcastNotification({
          title: 'New project assigned',
          message: `You have been assigned as foreman on "${project.name}".`,
          targets: [foremanUser.email, 'admin'],
          type: 'project',
          meta: { projectId: String(project._id) }
        });
      }
    } catch (e) { /* non-fatal */ }

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
    
    const existing = await models.EnhancedProject.findById(projectId);
    if (!existing) {
      return res.status(404).json({ error: 'Project not found' });
    }

    if (!name || !client) {
      return res.status(400).json({ error: 'Missing required fields: name, client' });
    }

    const locName = parsedLocation?.name || parsedLocation?.address || '';
    const locLat = parsedLocation?.latitude != null && parsedLocation?.latitude !== ''
      ? parseFloat(parsedLocation.latitude)
      : (existing.location?.latitude ?? -1.2921);
    const locLng = parsedLocation?.longitude != null && parsedLocation?.longitude !== ''
      ? parseFloat(parsedLocation.longitude)
      : (existing.location?.longitude ?? 36.8219);

    const previousForemanId = existing.foremanId ? String(existing.foremanId) : '';
    const rawForemanId = parsedAssignedForeman?._id || parsedAssignedForeman?.id || existing.foremanId || null;
    const foremanId = rawForemanId && mongoose.Types.ObjectId.isValid(String(rawForemanId))
      ? String(rawForemanId)
      : (existing.foremanId || null);
    const foremanName = parsedAssignedForeman?.name || existing.foremanName || '';

    const images = [];
    if (req.files && req.files.length > 0) {
      req.files.forEach(file => {
        images.push(`data:${file.mimetype};base64,${file.buffer.toString('base64')}`);
      });
    }

    const updateData = {
      name,
      client,
      location: {
        address: locName || existing.location?.address || '',
        latitude: Number.isFinite(locLat) ? locLat : -1.2921,
        longitude: Number.isFinite(locLng) ? locLng : 36.8219
      },
      budget: parseMoney(budget),
      endDate: deadline ? new Date(deadline) : existing.endDate,
      foremanId: foremanId || null,
      foremanName,
      progress: parseFloat(progress) || 0,
      status: (status || existing.status || 'planning').toLowerCase(),
      category: category || existing.category || 'Commercial',
      moneyPaid: parseMoney(moneyPaid),
      moneyUsed: parseMoney(moneyUsed),
      moneyRemaining: parseMoney(moneyRemaining),
      moneyOwed: parseMoney(moneyOwed),
      updatedAt: new Date()
    };

    if (images.length > 0) {
      updateData.images = images;
    }

    const project = await models.EnhancedProject.findByIdAndUpdate(
      projectId,
      updateData,
      { new: true, runValidators: true }
    );
    
    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }

    // Keep User.assignedProjects in sync when foreman changes
    const nextForemanId = project.foremanId ? String(project.foremanId) : '';
    if (previousForemanId && previousForemanId !== nextForemanId) {
      await models.User.findByIdAndUpdate(previousForemanId, {
        $pull: { assignedProjects: project._id }
      });
    }
    if (nextForemanId) {
      await models.User.findByIdAndUpdate(nextForemanId, {
        $addToSet: { assignedProjects: project._id }
      });
      if (previousForemanId !== nextForemanId) {
        try {
          const foremanUser = await models.User.findById(nextForemanId).lean();
          if (foremanUser?.email) {
            await broadcastNotification({
              title: 'Project assigned to you',
              message: `Admin assigned you as foreman on "${project.name}".`,
              targets: [foremanUser.email, 'admin'],
              type: 'project',
              meta: { projectId: String(project._id) }
            });
          }
        } catch (e) { /* non-fatal */ }
      }
    }
    
    res.json(project);
  } catch (error) {
    console.error('Update project error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Mock face embedding generation (replace with actual face recognition service)
function generateMockEmbedding() {
  return Array.from({ length: 128 }, () => Math.random() - 0.5);
}

// Mark Attendance with Face Recognition
app.post('/api/attendance/mark', authMiddleware, requireApprovedAccount, requireRole('foreman', 'admin'), async (req, res) => {
  try {
    const { projectId, workerId, location, faceImage, livenessData, status, notes } = req.body;
    
    if (!projectId || !workerId) {
      return res.status(400).json({ error: 'Missing required fields: projectId, workerId' });
    }
    
    const foreman = await loadDbUser(req);
    if (!foreman) return res.status(401).json({ error: 'Unauthorized' });
    const project = await models.EnhancedProject.findById(projectId);
    if (!project) return res.status(404).json({ error: 'Project not found' });
    const assigned = (foreman.assignedProjects || []).map(String);
    const isForemanOfProject = String(project.foremanId || '') === String(foreman._id);
    if (foreman.role === 'foreman' && !isForemanOfProject && !assigned.includes(String(projectId))) {
      return res.status(403).json({ error: 'You are not assigned to this project' });
    }
    
    const worker = await models.Worker.findById(workerId);
    
    if (!worker) {
      return res.status(404).json({ error: 'Worker not found' });
    }
    
    // Check if worker is assigned to this project
    if (!(worker.assignedProjects || []).map(String).includes(String(projectId))) {
      return res.status(400).json({ error: 'Worker is not assigned to this project' });
    }

    let gps = null;
    if (location && location.latitude != null && location.longitude != null) {
      if (!project.location || project.location.latitude == null || project.location.longitude == null) {
        return res.status(400).json({ error: 'Project location not set' });
      }
      const distance = calculateDistance(
        parseFloat(location.latitude),
        parseFloat(location.longitude),
        project.location.latitude,
        project.location.longitude
      );
      if (distance > (project.radius || 100)) {
        return res.status(400).json({
          error: 'Too far from project location',
          distance: Math.round(distance)
        });
      }
      gps = {
        latitude: parseFloat(location.latitude),
        longitude: parseFloat(location.longitude)
      };
    }
    
    // Check if already marked today
    const start = new Date();
    start.setHours(0, 0, 0, 0);
    const end = new Date();
    end.setHours(23, 59, 59, 999);
    const existingAttendance = await models.Attendance.findOne({
      workerId,
      projectId,
      date: { $gte: start, $lte: end }
    });
    
    if (existingAttendance) {
      return res.status(400).json({ error: 'Attendance already marked for today' });
    }

    // Face/liveness: accept registered faceData or explicit liveness pass (camera flows)
    const hasFaceOnFile = !!(worker.faceData && (worker.faceData.faceImage || worker.faceData.faceEncoding));
    const livenessPassed = !livenessData || livenessData.passed === true || livenessData.passed === 'true';
    if (!hasFaceOnFile && faceImage === undefined && livenessData && !livenessPassed) {
      return res.status(400).json({ error: 'Attendance verification failed', reasons: ['Liveness check failed'] });
    }
    
    const attendanceStatus = ['present', 'absent', 'late'].includes(String(status || '').toLowerCase())
      ? String(status).toLowerCase()
      : 'present';

    const attendance = await models.Attendance.create({
      workerId,
      projectId,
      date: new Date(),
      time: new Date().toTimeString().split(' ')[0],
      status: attendanceStatus,
      gpsCoordinates: gps || undefined,
      faceImage: faceImage || (worker.faceData && worker.faceData.faceImage) || '',
      livenessScore: livenessPassed ? 1 : 0
    });

    try {
      await broadcastNotification({
        title: 'Attendance marked',
        message: `${worker.name} marked ${attendanceStatus} on ${project.name}` + (notes ? ` — ${notes}` : ''),
        targets: ['admin', 'foreman'],
        type: 'attendance',
        meta: { projectId: String(project._id), workerId: String(worker._id), status: attendanceStatus }
      });
    } catch (e) { /* non-fatal */ }
    
    res.json({
      success: true,
      workerName: worker.name,
      attendance
    });
  } catch (error) {
    console.error('Mark attendance error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Get Today's Attendance for Foreman
app.get('/api/attendance/today', authMiddleware, requireApprovedAccount, requireRole('foreman', 'admin'), async (req, res) => {
  try {
    const { projectId } = req.query;
    const foreman = await loadDbUser(req);
    if (!foreman) return res.status(401).json({ error: 'Unauthorized' });

    let projectIds = (foreman.assignedProjects || []).map(String);
    if (foreman.role === 'foreman') {
      const linked = await models.EnhancedProject.find({ foremanId: foreman._id }).select('_id').lean();
      projectIds = Array.from(new Set([...projectIds, ...linked.map((p) => String(p._id))]));
    } else if (foreman.role === 'admin') {
      const all = await models.EnhancedProject.find().select('_id').lean();
      projectIds = all.map((p) => String(p._id));
    }

    if (projectId) {
      if (foreman.role !== 'admin' && !projectIds.includes(String(projectId))) {
        return res.status(403).json({ error: 'You are not assigned to this project' });
      }
      projectIds = [String(projectId)];
    }

    const start = new Date();
    start.setHours(0, 0, 0, 0);
    const end = new Date();
    end.setHours(23, 59, 59, 999);

    const attendance = await models.Attendance.find({
      projectId: { $in: projectIds },
      date: { $gte: start, $lte: end }
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
        $or: [
          { uploadedBy: req.user.sub },
          { isPublic: true }
        ]
      }).populate('project', 'name').sort({ createdAt: -1 });
    } else {
      if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access denied' });
      }
      documents = await models.Document.find().populate('project', 'name').sort({ createdAt: -1 });
    }

    res.json(documents.map((d) => {
      const obj = d.toObject ? d.toObject() : d;
      return {
        ...obj,
        id: String(obj._id),
        name: obj.title || obj.fileName,
        size: obj.fileSize,
        url: obj.filePath
      };
    }));
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
      }).populate('project', 'name').sort({ createdAt: -1 });
    } else {
      if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access denied' });
      }
      invoices = await models.Invoice.find().populate('project', 'name').populate('client', 'name email').sort({ createdAt: -1 });
    }

    res.json(invoices.map((inv) => {
      const obj = inv.toObject ? inv.toObject() : inv;
      return {
        ...obj,
        id: String(obj._id),
        number: obj.invoiceNumber
      };
    }));
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

// Helper function for distance calculation (kept for compatibility; primary Haversine is defined earlier)
function calculateDistanceMeters(lat1, lon1, lat2, lon2) {
  const R = 6371e3;
  const φ1 = lat1 * Math.PI / 180;
  const φ2 = lat2 * Math.PI / 180;
  const Δφ = (lat2 - lat1) * Math.PI / 180;
  const Δλ = (lon2 - lon1) * Math.PI / 180;
  const a = Math.sin(Δφ / 2) * Math.sin(Δφ / 2) +
          Math.cos(φ1) * Math.cos(φ2) *
          Math.sin(Δλ / 2) * Math.sin(Δλ / 2);
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
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
    const token = userData && userData.token;
    const payload = verifyToken(token);
    if (!payload || !payload.email || !payload.role) {
      socket.emit('auth-error', { error: 'Invalid token' });
      return;
    }
    const email = String(payload.email).toLowerCase();
    const role = payload.role;
    connectedUsers.set(socket.id, { email, role, socket });
    console.log(`User registered: ${email} (${role})`);
    socket.join(`role-${role}`);
    socket.join(`user-${email}`);
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
    // Wildcard notifications are admin-targeted over the wire
    io.to('role-admin').emit('new-notification', notification);
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
app.get('/api/workers', authMiddleware, requireApprovedAccount, async (req, res) => {
  try {
    const dbUser = await loadDbUser(req);
    if (!dbUser) return res.status(401).json({ error: 'Unauthorized' });

    let workers = [];
    if (dbUser.role === 'admin') {
      workers = await models.Worker.find().sort({ createdAt: -1 }).lean();
    } else if (dbUser.role === 'foreman') {
      const projectIds = new Set((dbUser.assignedProjects || []).map(String));
      const linked = await models.EnhancedProject.find({ foremanId: dbUser._id }).select('_id workers').lean();
      linked.forEach((p) => projectIds.add(String(p._id)));
      workers = await models.Worker.find({
        $or: [
          { assignedProjects: { $in: Array.from(projectIds) } },
          { registeredBy: dbUser._id },
          { _id: { $in: dbUser.workerAssignments || [] } }
        ]
      }).sort({ createdAt: -1 }).lean();
    } else {
      return res.status(403).json({ error: 'Access denied' });
    }

    res.json({
      workers: workers.map((w) => ({
        ...w,
        id: String(w._id),
        _id: String(w._id)
      }))
    });
  } catch (error) {
    console.error('Get workers error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ===== ATTENDANCE API =====
app.get('/api/attendance/stats', authMiddleware, requireApprovedAccount, async (req, res) => {
  try {
    const dbUser = await loadDbUser(req);
    if (!dbUser) return res.status(401).json({ error: 'Unauthorized' });

    let projectIds = [];
    if (dbUser.role === 'admin') {
      projectIds = (await models.EnhancedProject.find().select('_id').lean()).map((p) => p._id);
    } else if (dbUser.role === 'foreman') {
      const linked = await models.EnhancedProject.find({ foremanId: dbUser._id }).select('_id').lean();
      projectIds = Array.from(new Set([...(dbUser.assignedProjects || []).map(String), ...linked.map((p) => String(p._id))]));
    } else {
      return res.status(403).json({ error: 'Access denied' });
    }

    const start = new Date();
    start.setHours(0, 0, 0, 0);
    const end = new Date();
    end.setHours(23, 59, 59, 999);

    const rows = await models.Attendance.find({
      projectId: { $in: projectIds },
      date: { $gte: start, $lte: end }
    }).lean();

    const present = rows.filter((r) => r.status === 'present').length;
    const late = rows.filter((r) => r.status === 'late').length;
    const workers = await models.Worker.countDocuments({ assignedProjects: { $in: projectIds } });
    const absent = Math.max(0, workers - present - late);

    res.json({ present, absent, late, total: workers });
  } catch (error) {
    console.error('Get attendance stats error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ===== PAYROLL API =====
app.get('/api/payroll/stats', authMiddleware, requireApprovedAccount, async (req, res) => {
  try {
    const dbUser = await loadDbUser(req);
    if (!dbUser) return res.status(401).json({ error: 'Unauthorized' });

    let projectIds = [];
    if (dbUser.role === 'admin') {
      projectIds = (await models.EnhancedProject.find().select('_id').lean()).map((p) => p._id);
    } else if (dbUser.role === 'foreman') {
      const linked = await models.EnhancedProject.find({ foremanId: dbUser._id }).select('_id').lean();
      projectIds = Array.from(new Set([...(dbUser.assignedProjects || []).map(String), ...linked.map((p) => String(p._id))]));
    } else {
      return res.status(403).json({ error: 'Access denied' });
    }

    const workers = await models.Worker.find({ assignedProjects: { $in: projectIds } }).lean();
    const monthStart = new Date();
    monthStart.setDate(1);
    monthStart.setHours(0, 0, 0, 0);
    const attendance = await models.Attendance.find({
      projectId: { $in: projectIds },
      date: { $gte: monthStart },
      status: { $in: ['present', 'late'] }
    }).lean();

    const daysByWorker = {};
    attendance.forEach((a) => {
      const id = String(a.workerId);
      daysByWorker[id] = (daysByWorker[id] || 0) + 1;
    });

    let monthlyPayroll = 0;
    workers.forEach((w) => {
      const days = daysByWorker[String(w._id)] || 0;
      monthlyPayroll += days * (Number(w.dailyRate) || 0);
    });

    const workerCount = workers.length;
    res.json({
      totalPayroll: monthlyPayroll,
      monthlyPayroll,
      averageSalary: workerCount ? Math.round(monthlyPayroll / workerCount) : 0,
      workerCount,
      currency: 'KSH'
    });
  } catch (error) {
    console.error('Get payroll stats error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Generate payroll records for a project (current calendar month)
app.post('/api/payroll/generate', authMiddleware, requireApprovedAccount, requireRole('foreman', 'admin'), async (req, res) => {
  try {
    const dbUser = await loadDbUser(req);
    if (!dbUser) return res.status(401).json({ error: 'Unauthorized' });
    const { projectId } = req.body || {};
    if (!projectId || !mongoose.Types.ObjectId.isValid(String(projectId))) {
      return res.status(400).json({ error: 'Valid projectId required' });
    }

    const project = await models.EnhancedProject.findById(projectId);
    if (!project) return res.status(404).json({ error: 'Project not found' });

    if (dbUser.role === 'foreman') {
      const assigned = (dbUser.assignedProjects || []).map(String);
      const isForeman = String(project.foremanId || '') === String(dbUser._id);
      if (!isForeman && !assigned.includes(String(project._id))) {
        return res.status(403).json({ error: 'Access denied' });
      }
    }

    const monthStart = new Date();
    monthStart.setDate(1);
    monthStart.setHours(0, 0, 0, 0);
    const monthEnd = new Date(monthStart);
    monthEnd.setMonth(monthEnd.getMonth() + 1);
    monthEnd.setMilliseconds(-1);

    const workers = await models.Worker.find({
      $or: [
        { _id: { $in: project.workers || [] } },
        { assignedProjects: project._id }
      ],
      status: { $ne: 'inactive' }
    });

    const attendance = await models.Attendance.find({
      projectId: project._id,
      date: { $gte: monthStart, $lte: monthEnd }
    }).lean();

    const byWorker = {};
    attendance.forEach((a) => {
      const id = String(a.workerId);
      if (!byWorker[id]) byWorker[id] = { present: 0, absent: 0, late: 0 };
      if (a.status === 'late') byWorker[id].late += 1;
      else if (a.status === 'absent') byWorker[id].absent += 1;
      else byWorker[id].present += 1;
    });

    const created = [];
    for (const w of workers) {
      const stats = byWorker[String(w._id)] || { present: 0, absent: 0, late: 0 };
      const daysPaid = stats.present + stats.late;
      const totalSalary = daysPaid * (Number(w.dailyRate) || 0);
      const row = await models.Payroll.findOneAndUpdate(
        {
          workerId: w._id,
          projectId: project._id,
          'payPeriod.startDate': monthStart,
          'payPeriod.endDate': monthEnd
        },
        {
          $set: {
            workerId: w._id,
            projectId: project._id,
            payPeriod: { startDate: monthStart, endDate: monthEnd },
            daysPresent: stats.present,
            daysAbsent: stats.absent,
            daysLate: stats.late,
            hourlyRate: Number(w.dailyRate) || 0,
            overtimeHours: 0,
            totalSalary,
            deductions: 0
          }
        },
        { upsert: true, new: true }
      );
      created.push({
        workerId: String(w._id),
        workerName: w.name,
        daysPresent: stats.present,
        daysLate: stats.late,
        daysAbsent: stats.absent,
        totalSalary
      });
    }

    try {
      await broadcastNotification({
        title: 'Payroll generated',
        message: `Payroll for ${project.name} (${created.length} workers) was generated by ${dbUser.name || dbUser.email}.`,
        targets: ['admin', dbUser.email],
        type: 'payroll',
        meta: { projectId: String(project._id) }
      });
    } catch (e) { /* non-fatal */ }

    res.json({ ok: true, projectId: String(project._id), period: { start: monthStart, end: monthEnd }, rows: created });
  } catch (error) {
    console.error('Generate payroll error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});


// Project workers list
app.get('/api/projects/:projectId/workers', authMiddleware, requireApprovedAccount, async (req, res) => {
  try {
    const dbUser = await loadDbUser(req);
    if (!dbUser) return res.status(401).json({ error: 'Unauthorized' });
    const project = await models.EnhancedProject.findById(req.params.projectId).lean();
    if (!project) return res.status(404).json({ error: 'Project not found' });

    if (dbUser.role === 'foreman') {
      const assigned = (dbUser.assignedProjects || []).map(String);
      const isForeman = String(project.foremanId || '') === String(dbUser._id);
      if (!isForeman && !assigned.includes(String(project._id))) {
        return res.status(403).json({ error: 'Access denied' });
      }
    } else if (dbUser.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }

    const workers = await models.Worker.find({
      $or: [
        { _id: { $in: project.workers || [] } },
        { assignedProjects: project._id }
      ]
    }).lean();
    res.json({ workers });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Create invoice (admin)
app.post('/api/invoices', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { number, invoiceNumber, client, clientEmail, project, projectId, amount, dueDate, status, description } = req.body;
    const invNo = String(invoiceNumber || number || '').trim() || ('INV-' + Date.now());
    let clientId = client;
    if (!clientId && clientEmail) {
      const u = await models.User.findOne({ email: String(clientEmail).toLowerCase(), role: 'client' });
      if (u) clientId = u._id;
    }
    if (!clientId) return res.status(400).json({ error: 'Client required' });
    if (!amount || !dueDate) return res.status(400).json({ error: 'Amount and due date required' });

    const invoice = await models.Invoice.create({
      invoiceNumber: invNo,
      client: clientId,
      project: projectId || project || undefined,
      amount: Number(amount),
      dueDate: new Date(dueDate),
      status: status || 'pending',
      description: description || '',
      items: [{
        description: description || 'Project invoice',
        quantity: 1,
        unitPrice: Number(amount),
        total: Number(amount)
      }]
    });

    // Mirror into PortalState for admin UI tables
    await models.PortalState.findOneAndUpdate(
      { key: 'main' },
      {
        $push: {
          portalInvoices: {
            id: String(invoice._id),
            number: invNo,
            client: clientEmail || clientId,
            project: project || '',
            amount: Number(amount),
            dueDate,
            status: invoice.status
          }
        }
      },
      { upsert: true }
    );

    const clientUser = await models.User.findById(clientId).lean();
    if (clientUser && clientUser.email) {
      await broadcastNotification({
        title: 'New invoice',
        message: `Invoice ${invNo} for KES ${Number(amount).toLocaleString()} has been issued.`,
        targets: [clientUser.email]
      });
    }

    res.status(201).json({
      ...invoice.toObject(),
      number: invoice.invoiceNumber,
      id: String(invoice._id)
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.code === 11000 ? 'Invoice number already exists' : 'Server error' });
  }
});

// Create / upload document metadata (admin or client)
app.post('/api/documents', authMiddleware, requireApprovedAccount, async (req, res) => {
  try {
    const { title, name, fileName, filePath, fileData, fileSize, size, mimeType, project, projectId, category, description, clientEmail } = req.body;
    const finalName = fileName || name || title;
    const finalTitle = title || name || finalName;
    if (!finalTitle || !finalName) return res.status(400).json({ error: 'Document title/name required' });

    let pathOrData = filePath || fileData || '';
    if (!pathOrData) return res.status(400).json({ error: 'filePath or fileData required' });

    let projectRef = projectId || project || undefined;
    let uploadedBy = req.user.sub;

    // Admin may upload for a client project
    if (req.user.role === 'admin' && clientEmail) {
      const clientUser = await models.User.findOne({ email: String(clientEmail).toLowerCase() });
      if (clientUser) uploadedBy = clientUser._id;
    }

    const doc = await models.Document.create({
      title: finalTitle,
      fileName: finalName,
      filePath: pathOrData,
      fileSize: Number(fileSize || size || 0),
      mimeType: mimeType || 'application/octet-stream',
      project: projectRef || undefined,
      uploadedBy,
      category: category || 'other',
      description: description || ''
    });

    await models.PortalState.findOneAndUpdate(
      { key: 'main' },
      {
        $push: {
          clientDocuments: {
            id: String(doc._id),
            name: finalTitle,
            fileName: finalName,
            size: doc.fileSize,
            url: pathOrData,
            projectId: projectRef ? String(projectRef) : '',
            clientEmail: clientEmail || req.user.email,
            uploadedBy: req.user.email,
            date: new Date().toISOString()
          }
        }
      },
      { upsert: true }
    );

    res.status(201).json({
      ...doc.toObject(),
      id: String(doc._id),
      name: doc.title,
      size: doc.fileSize
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Client add funds -> update EnhancedProject moneyPaid
app.post('/api/projects/:projectId/add-funds', authMiddleware, requireApprovedAccount, requireRole('client', 'admin'), async (req, res) => {
  try {
    const amount = Number(req.body.amount);
    if (!amount || amount <= 0) return res.status(400).json({ error: 'Valid amount required' });
    const project = await models.EnhancedProject.findById(req.params.projectId);
    if (!project) return res.status(404).json({ error: 'Project not found' });
    if (req.user.role === 'client' && String(project.client) !== String(req.user.sub)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    project.moneyPaid = Number(project.moneyPaid || 0) + amount;
    project.moneyRemaining = Number(project.budget || 0) - Number(project.moneyPaid || 0) + Number(project.moneyOwed || 0);
    await project.save();

    await models.PortalState.findOneAndUpdate(
      { key: 'main' },
      {
        $push: {
          clientTransactions: {
            id: Date.now(),
            projectId: String(project._id),
            projectName: project.name,
            amount,
            paymentMethod: req.body.paymentMethod || '',
            transactionId: req.body.transactionId || '',
            notes: req.body.notes || '',
            date: new Date().toISOString(),
            type: 'payment',
            clientEmail: req.user.email
          }
        }
      },
      { upsert: true }
    );

    await broadcastNotification({
      title: 'Funds added',
      message: `${req.user.name || req.user.email} added KES ${amount.toLocaleString()} to ${project.name}`,
      targets: ['admin']
    });

    res.json({ ok: true, project });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});


// Export io for use in other modules
global.io = io;

// Deactivate / unassign worker (foreman/admin)
// Deactivate / unassign worker (foreman/admin)
app.patch('/api/workers/:workerId', authMiddleware, requireApprovedAccount, requireRole('foreman', 'admin'), async (req, res) => {
  try {
    const dbUser = await loadDbUser(req);
    if (!dbUser) return res.status(401).json({ error: 'Unauthorized' });
    const worker = await models.Worker.findById(req.params.workerId);
    if (!worker) return res.status(404).json({ error: 'Worker not found' });

    if (dbUser.role === 'foreman') {
      const projectIds = new Set((dbUser.assignedProjects || []).map(String));
      const linked = await models.EnhancedProject.find({ foremanId: dbUser._id }).select('_id').lean();
      linked.forEach((p) => projectIds.add(String(p._id)));
      const allowed = (worker.assignedProjects || []).some((pid) => projectIds.has(String(pid)))
        || String(worker.registeredBy || '') === String(dbUser._id);
      if (!allowed) return res.status(403).json({ error: 'Access denied' });
    }

    const { phone, dailyRate, skills, status } = req.body || {};
    if (phone !== undefined) worker.phone = String(phone).trim();
    if (dailyRate !== undefined) {
      const rate = Number(dailyRate);
      if (!Number.isFinite(rate) || rate <= 0) return res.status(400).json({ error: 'Invalid daily rate' });
      worker.dailyRate = rate;
    }
    if (skills !== undefined) worker.skills = String(skills);
    if (status !== undefined && ['active', 'inactive'].includes(status)) worker.status = status;

    await worker.save();
    res.json({ ok: true, worker });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/workers/:workerId', authMiddleware, requireApprovedAccount, requireRole('foreman', 'admin'), async (req, res) => {
  try {
    const dbUser = await loadDbUser(req);
    if (!dbUser) return res.status(401).json({ error: 'Unauthorized' });
    const worker = await models.Worker.findById(req.params.workerId);
    if (!worker) return res.status(404).json({ error: 'Worker not found' });

    if (dbUser.role === 'foreman') {
      const projectIds = new Set((dbUser.assignedProjects || []).map(String));
      const linked = await models.EnhancedProject.find({ foremanId: dbUser._id }).select('_id').lean();
      linked.forEach((p) => projectIds.add(String(p._id)));
      const allowed = (worker.assignedProjects || []).some((pid) => projectIds.has(String(pid)))
        || String(worker.registeredBy || '') === String(dbUser._id);
      if (!allowed) return res.status(403).json({ error: 'Access denied' });
    }

    worker.status = 'inactive';
    await worker.save();
    await models.EnhancedProject.updateMany(
      { workers: worker._id },
      { $pull: { workers: worker._id } }
    );
    await models.User.findByIdAndUpdate(dbUser._id, {
      $pull: { workerAssignments: worker._id }
    });

    res.json({ ok: true, message: 'Worker removed' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});
