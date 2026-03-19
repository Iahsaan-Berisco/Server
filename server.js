const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const { MongoClient } = require('mongodb');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

const JWT_SECRET = process.env.JWT_SECRET || 'gamezone-secret-2024';
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || process.env.DATABASE_URL;

// ─── MongoDB Connection ───────────────────────────────────────────────────────
let db;
let dbClient;

async function connectDatabase() {
  if (!MONGODB_URI) {
    console.error('❌ MONGODB_URI not set! Check Railway environment variables.');
    process.exit(1);
  }

  try {
    console.log('🔗 Connecting to MongoDB...');
    dbClient = new MongoClient(MONGODB_URI, {
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });
    
    await dbClient.connect();
    db = dbClient.db();
    
    const collections = ['users', 'groups', 'pcs', 'sessions', 'group_members', 'installed_apps'];
    const existingCollections = await db.listCollections().toArray();
    const existingNames = existingCollections.map(c => c.name);
    
    for (const collection of collections) {
      if (!existingNames.includes(collection)) {
        await db.createCollection(collection);
        console.log(`📁 Created collection: ${collection}`);
      }
    }
    
    console.log('✅ MongoDB connected successfully');
    return true;
  } catch (error) {
    console.error('❌ MongoDB connection failed:', error.message);
    throw error;
  }
}

// ─── Database Helper Functions ────────────────────────────────────────────────
const dbHelpers = {
  async get(collection, filterFn) {
    const items = await db.collection(collection).find({}).toArray();
    return items.find(filterFn) || null;
  },
  
  async filter(collection, filterFn) {
    const items = await db.collection(collection).find({}).toArray();
    return items.filter(filterFn);
  },
  
  async insert(collection, data) {
    const result = await db.collection(collection).insertOne(data);
    return { ...data, _id: result.insertedId };
  },
  
  async update(collection, filterFn, updateData) {
    const items = await db.collection(collection).find({}).toArray();
    const item = items.find(filterFn);
    if (item) {
      await db.collection(collection).updateOne(
        { _id: item._id },
        { $set: updateData }
      );
      return { ...item, ...updateData };
    }
    return null;
  },
  
  async delete(collection, filterFn) {
    const items = await db.collection(collection).find({}).toArray();
    const idsToDelete = items.filter(filterFn).map(i => i._id);
    if (idsToDelete.length > 0) {
      await db.collection(collection).deleteMany({ _id: { $in: idsToDelete } });
    }
    return idsToDelete.length;
  },
  
  async insertOrIgnore(collection, data) {
    try {
      await db.collection(collection).insertOne(data);
      return data;
    } catch (e) {
      return data;
    }
  }
};

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try { 
    req.user = jwt.verify(token, JWT_SECRET); 
    next(); 
  } catch { 
    res.status(401).json({ error: 'Invalid token' }); 
  }
}

async function canManageGroup(userId, groupId) {
  const group = await dbHelpers.get('groups', g => g.id === groupId);
  if (!group) return false;
  if (group.owner_id === userId) return true;
  return !!(await dbHelpers.get('group_members', m => m.group_id === groupId && m.user_id === userId));
}

// ─── Auth Routes ──────────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    
    const existingUser = await dbHelpers.get('users', u => u.username === username);
    if (existingUser) return res.status(400).json({ error: 'Username already taken' });
    
    const id = uuidv4();
    const user = await dbHelpers.insert('users', { 
      id, 
      username, 
      password: bcrypt.hashSync(password, 10), 
      created_at: Date.now() 
    });
    
    const token = jwt.sign({ id, username }, JWT_SECRET);
    res.json({ token, user: { id, username } });
  } catch(e) { 
    res.status(500).json({ error: e.message }); 
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await dbHelpers.get('users', u => u.username === username);
    
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);
    res.json({ token, user: { id: user.id, username: user.username } });
  } catch(e) { 
    res.status(500).json({ error: e.message }); 
  }
});

// ─── Groups Routes ────────────────────────────────────────────────────────────
app.post('/api/groups', authMiddleware, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'Group name required' });
    
    const id = uuidv4();
    const group = await dbHelpers.insert('groups', { 
      id, 
      name, 
      owner_id: req.user.id, 
      created_at: Date.now() 
    });
    
    res.json(group);
  } catch(e) { 
    res.status(500).json({ error: e.message }); 
  }
});

app.get('/api/groups', authMiddleware, async (req, res) => {
  try {
    const owned = await dbHelpers.filter('groups', g => g.owner_id === req.user.id);
    const memberGroupIds = (await dbHelpers.filter('group_members', m => m.user_id === req.user.id)).map(m => m.group_id);
    const membered = await dbHelpers.filter('groups', g => memberGroupIds.includes(g.id));
    const all = [...owned, ...membered].filter((g, i, arr) => arr.findIndex(x => x.id === g.id) === i);
    
    res.json(all);
  } catch(e) { 
    res.status(500).json({ error: e.message }); 
  }
});

app.delete('/api/groups/:groupId', authMiddleware, async (req, res) => {
  try {
    const { groupId } = req.params;
    const group = await dbHelpers.get('groups', g => g.id === groupId && g.owner_id === req.user.id);
    
    if (!group) return res.status(403).json({ error: 'Only owner can delete this group' });
    
    const pcIds = (await dbHelpers.filter('pcs', p => p.group_id === groupId)).map(p => p.id);
    await dbHelpers.delete('installed_apps', a => pcIds.includes(a.pc_id));
    await dbHelpers.delete('sessions', s => pcIds.includes(s.pc_id));
    await dbHelpers.delete('pcs', p => p.group_id === groupId);
    await dbHelpers.delete('group_members', m => m.group_id === groupId);
    await dbHelpers.delete('groups', g => g.id === groupId);
    
    res.json({ success: true });
  } catch(e) { 
    res.status(500).json({ error: e.message }); 
  }
});

app.post('/api/groups/:groupId/admins', authMiddleware, async (req, res) => {
  try {
    const { groupId } = req.params;
    const group = await dbHelpers.get('groups', g => g.id === groupId && g.owner_id === req.user.id);
    
    if (!group) return res.status(403).json({ error: 'Only owner can add admins' });
    
    const user = await dbHelpers.get('users', u => u.username === req.body.username);
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    await dbHelpers.insertOrIgnore('group_members', { 
      id: uuidv4(), 
      group_id: groupId, 
      user_id: user.id, 
      role: 'admin' 
    });
    
    res.json({ success: true });
  } catch(e) { 
    res.status(500).json({ error: e.message }); 
  }
});

app.get('/api/groups/:groupId/admins', authMiddleware, async (req, res) => {
  try {
    const { groupId } = req.params;
    if (!await canManageGroup(req.user.id, groupId)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    const members = await dbHelpers.filter('group_members', m => m.group_id === groupId);
    const admins = await Promise.all(members.map(async m => {
      const u = await dbHelpers.get('users', u => u.id === m.user_id);
      return u ? { id: u.id, username: u.username, role: m.role } : null;
    }));
    
    res.json(admins.filter(Boolean));
  } catch(e) { 
    res.status(500).json({ error: e.message }); 
  }
});

app.delete('/api/groups/:groupId/admins/:userId', authMiddleware, async (req, res) => {
  try {
    const { groupId, userId } = req.params;
    const group = await dbHelpers.get('groups', g => g.id === groupId && g.owner_id === req.user.id);
    
    if (!group) return res.status(403).json({ error: 'Only owner can remove admins' });
    
    await dbHelpers.delete('group_members', m => m.group_id === groupId && m.user_id === userId);
    res.json({ success: true });
  } catch(e) { 
    res.status(500).json({ error: e.message }); 
  }
});

// ─── PCs Routes ───────────────────────────────────────────────────────────────
app.get('/api/groups/:groupId/pcs', authMiddleware, async (req, res) => {
  try {
    const { groupId } = req.params;
    if (!await canManageGroup(req.user.id, groupId)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    const pcs = (await dbHelpers.filter('pcs', p => p.group_id === groupId)).map(p => ({ 
      ...p, 
      password: undefined 
    }));
    
    res.json(pcs);
  } catch(e) { 
    res.status(500).json({ error: e.message }); 
  }
});

app.post('/api/groups/:groupId/pcs', authMiddleware, async (req, res) => {
  try {
    const { groupId } = req.params;
    if (!await canManageGroup(req.user.id, groupId)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    const { name, password, price_per_hour } = req.body;
    if (!name || !password) {
      return res.status(400).json({ error: 'Name and password required' });
    }
    
    const id = uuidv4();
    const pc = await dbHelpers.insert('pcs', { 
      id, 
      group_id: groupId, 
      name, 
      password: bcrypt.hashSync(password, 10), 
      is_online: 0, 
      session_end: 0, 
      stopwatch_start: 0,
      payment_status: null,
      price_per_hour: price_per_hour || 0,
      order: Date.now()
    });
    
    res.json({ 
      id, 
      name, 
      group_id: groupId, 
      is_online: 0, 
      session_end: 0, 
      stopwatch_start: 0,
      payment_status: null,
      price_per_hour: price_per_hour || 0,
      order: Date.now()
    });
  } catch(e) { 
    res.status(500).json({ error: e.message }); 
  }
});

app.delete('/api/groups/:groupId/pcs/:pcId', authMiddleware, async (req, res) => {
  try {
    const { groupId, pcId } = req.params;
    if (!await canManageGroup(req.user.id, groupId)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    await dbHelpers.delete('installed_apps', a => a.pc_id === pcId);
    await dbHelpers.delete('sessions', s => s.pc_id === pcId);
    await dbHelpers.delete('pcs', p => p.id === pcId && p.group_id === groupId);
    
    res.json({ success: true });
  } catch(e) { 
    res.status(500).json({ error: e.message }); 
  }
});

// ─── Payment Status Route (FIXED) ─────────────────────────────────────────────
app.post('/api/pcs/:pcId/payment', authMiddleware, async (req, res) => {
  try {
    const { pcId } = req.params;
    const { payment_status, group_id } = req.body;
    
    if (!await canManageGroup(req.user.id, group_id)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    await dbHelpers.update('pcs', p => p.id === pcId, { payment_status });
    
    // Emit to all admins in the group
    io.to(`group:${group_id}`).emit('group:'+group_id+':pc-session', {
      pc_id: pcId,
      payment_status
    });
    
    res.json({ success: true, payment_status });
  } catch(e) { 
    res.status(500).json({ error: e.message }); 
  }
});

// ─── Session Routes ───────────────────────────────────────────────────────────
app.post('/api/pcs/:pcId/session/start', authMiddleware, async (req, res) => {
  try {
    const { pcId } = req.params;
    const { duration_minutes, group_id } = req.body;
    
    if (!await canManageGroup(req.user.id, group_id)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    const pc = await dbHelpers.get('pcs', p => p.id === pcId);
    if (!pc) return res.status(404).json({ error: 'PC not found' });
    
    const session_end = Math.floor(Date.now() / 1000) + duration_minutes * 60;
    await dbHelpers.update('pcs', p => p.id === pcId, { session_end, stopwatch_start: 0 });
    
    await dbHelpers.insert('sessions', { 
      id: uuidv4(), 
      pc_id: pcId, 
      started_at: Math.floor(Date.now() / 1000), 
      duration_minutes, 
      price: (duration_minutes / 60) * pc.price_per_hour, 
      ended_at: null 
    });
    
    const remaining = duration_minutes * 60;
    
    io.to(`pc:${pcId}`).emit('session:start', { session_end, duration_minutes, remaining_seconds: remaining });
    io.to(`group:${group_id}`).emit('group:'+group_id+':pc-session', { 
      pc_id: pcId, 
      session_end, 
      stopwatch_start: 0,
      payment_status: pc.payment_status
    });
    
    res.json({ success: true, session_end, remaining_seconds: remaining });
  } catch(e) { 
    res.status(500).json({ error: e.message }); 
  }
});

app.post('/api/pcs/:pcId/session/add-time', authMiddleware, async (req, res) => {
  try {
    const { pcId } = req.params;
    const { minutes, group_id } = req.body;
    
    if (!await canManageGroup(req.user.id, group_id)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    const pc = await dbHelpers.get('pcs', p => p.id === pcId);
    if (!pc) return res.status(404).json({ error: 'PC not found' });
    
    const now = Math.floor(Date.now() / 1000);
    const new_end = (pc.session_end > now ? pc.session_end : now) + minutes * 60;
    await dbHelpers.update('pcs', p => p.id === pcId, { session_end: new_end });
    
    const rem = new_end - Math.floor(Date.now() / 1000);
    
    io.to(`pc:${pcId}`).emit('session:add-time', { session_end: new_end, added_minutes: minutes, remaining_seconds: rem });
    io.to(`group:${group_id}`).emit('group:'+group_id+':pc-session', { 
      pc_id: pcId, 
      session_end: new_end, 
      stopwatch_start: pc.stopwatch_start || 0,
      payment_status: pc.payment_status
    });
    
    res.json({ success: true, session_end: new_end, remaining_seconds: rem });
  } catch(e) { 
    res.status(500).json({ error: e.message }); 
  }
});

app.post('/api/pcs/:pcId/session/end', authMiddleware, async (req, res) => {
  try {
    const { pcId } = req.params;
    const { group_id } = req.body;
    
    if (!await canManageGroup(req.user.id, group_id)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    await dbHelpers.update('pcs', p => p.id === pcId, { session_end: 0, stopwatch_start: 0 });
    await dbHelpers.update('sessions', s => s.pc_id === pcId && !s.ended_at, { ended_at: Math.floor(Date.now() / 1000) });
    
    io.to(`pc:${pcId}`).emit('session:end', {});
    io.to(`group:${group_id}`).emit('group:'+group_id+':pc-session', { 
      pc_id: pcId, 
      session_end: 0, 
      stopwatch_start: 0,
      payment_status: undefined
    });
    
    res.json({ success: true });
  } catch(e) { 
    res.status(500).json({ error: e.message }); 
  }
});

app.post('/api/pcs/:pcId/session/stopwatch', authMiddleware, async (req, res) => {
  try {
    const { pcId } = req.params;
    const { group_id } = req.body;
    
    if (!await canManageGroup(req.user.id, group_id)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    const started_at = Math.floor(Date.now() / 1000);
    
    await dbHelpers.update('pcs', p => p.id === pcId, { session_end: 0, stopwatch_start: started_at });
    
    io.to(`pc:${pcId}`).emit('session:stopwatch', { started_at });
    io.to(`group:${group_id}`).emit('group:'+group_id+':pc-session', { 
      pc_id: pcId, 
      session_end: 0, 
      stopwatch_start: started_at,
      payment_status: undefined
    });
    
    res.json({ success: true, started_at });
  } catch(e) { 
    res.status(500).json({ error: e.message }); 
  }
});

app.post('/api/pcs/:pcId/session/stopwatch-end', authMiddleware, async (req, res) => {
  try {
    const { pcId } = req.params;
    const { group_id } = req.body;
    
    if (!await canManageGroup(req.user.id, group_id)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    await dbHelpers.update('pcs', p => p.id === pcId, { session_end: 0, stopwatch_start: 0 });
    
    io.to(`pc:${pcId}`).emit('session:stopwatch-end', {});
    io.to(`group:${group_id}`).emit('group:'+group_id+':pc-session', { 
      pc_id: pcId, 
      session_end: 0, 
      stopwatch_start: 0,
      payment_status: undefined
    });
    
    io.to(`pc:${pcId}`).emit('command:lock', {});
    
    res.json({ success: true });
  } catch(e) { 
    res.status(500).json({ error: e.message }); 
  }
});

// ─── PC Control Routes ────────────────────────────────────────────────────────
app.post('/api/pcs/:pcId/lock', authMiddleware, async (req, res) => {
  try {
    if (!await canManageGroup(req.user.id, req.body.group_id)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    io.to(`pc:${req.params.pcId}`).emit('command:lock', {});
    res.json({ success: true });
  } catch(e) { 
    res.status(500).json({ error: e.message }); 
  }
});

app.post('/api/pcs/:pcId/unlock', authMiddleware, async (req, res) => {
  try {
    if (!await canManageGroup(req.user.id, req.body.group_id)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    io.to(`pc:${req.params.pcId}`).emit('command:unlock', {});
    res.json({ success: true });
  } catch(e) { 
    res.status(500).json({ error: e.message }); 
  }
});

app.post('/api/pcs/:pcId/launch', authMiddleware, async (req, res) => {
  try {
    const { app_path, group_id } = req.body;
    
    if (!await canManageGroup(req.user.id, group_id)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    io.to(`pc:${req.params.pcId}`).emit('command:launch', { app_path });
    res.json({ success: true });
  } catch(e) { 
    res.status(500).json({ error: e.message }); 
  }
});

app.get('/api/pcs/:pcId/apps', authMiddleware, async (req, res) => {
  try {
    const apps = await dbHelpers.filter('installed_apps', a => a.pc_id === req.params.pcId);
    res.json(apps);
  } catch(e) { 
    res.status(500).json({ error: e.message }); 
  }
});

// ─── PC Reorder Route ─────────────────────────────────────────────────────────
app.post('/api/groups/:groupId/pcs/reorder', authMiddleware, async (req, res) => {
  try {
    const { groupId } = req.params;
    const { order } = req.body;
    
    if (!await canManageGroup(req.user.id, groupId)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    for (const item of order) {
      await dbHelpers.update('pcs', p => p.id === item.pc_id, { order: item.order });
    }
    
    res.json({ success: true });
  } catch(e) { 
    res.status(500).json({ error: e.message }); 
  }
});

// ─── WebSocket ────────────────────────────────────────────────────────────────
io.on('connection', (socket) => {
  socket.on('pc:auth', async ({ pc_name, group_id, password }, callback) => {
    const pc = await dbHelpers.get('pcs', p => p.name === pc_name && p.group_id === group_id);
    
    if (!pc || !bcrypt.compareSync(password, pc.password)) {
      return callback({ success: false, error: 'Invalid PC credentials' });
    }
    
    socket.join(`pc:${pc.id}`);
    socket.pcId = pc.id;
    socket.groupId = group_id;
    
    await dbHelpers.update('pcs', p => p.id === pc.id, { is_online: 1 });
    io.emit(`group:${group_id}:pc-status`, { pc_id: pc.id, is_online: true });
    
    const now = Math.floor(Date.now()/1000);
    const swStart = (pc.stopwatch_start && pc.stopwatch_start < now) ? pc.stopwatch_start : 0;
    const remAuth = pc.session_end > now ? pc.session_end - now : 0;
    
    callback({ 
      success: true, 
      pc_id: pc.id, 
      session_end: pc.session_end, 
      stopwatch_start: swStart, 
      remaining_seconds: remAuth 
    });
  });

  socket.on('pc:apps', async ({ apps }) => {
    if (!socket.pcId) return;
    
    await dbHelpers.delete('installed_apps', a => a.pc_id === socket.pcId);
    for (const a of apps) {
      await dbHelpers.insert('installed_apps', { 
        id: uuidv4(), 
        pc_id: socket.pcId, 
        name: a.name, 
        path: a.path 
      });
    }
  });

  socket.on('admin:subscribe', ({ group_id, token }) => {
    try { 
      jwt.verify(token, JWT_SECRET); 
      socket.join(`group:${group_id}`);
    } catch {}
  });

  socket.on('disconnect', async () => {
    if (socket.pcId) {
      await dbHelpers.update('pcs', p => p.id === socket.pcId, { is_online: 0 });
      if (socket.groupId) {
        io.emit(`group:${socket.groupId}:pc-status`, { pc_id: socket.pcId, is_online: false });
      }
    }
  });
});

// ─── Health Check Endpoint ────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    database: db ? 'connected' : 'disconnected',
    uptime: process.uptime()
  });
});

// ─── Start Server ─────────────────────────────────────────────────────────────
async function startServer() {
  try {
    await connectDatabase();
    
    server.listen(PORT, '0.0.0.0', () => {
      console.log('\n' + '='.repeat(50));
      console.log('🎮 GameZone Server Started Successfully!');
      console.log('='.repeat(50));
      console.log(`   Port: ${PORT}`);
      console.log(`   Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`   Database: ${MONGODB_URI ? 'Connected ✅' : 'Not configured ❌'}`);
      console.log(`   JWT Secret: ${JWT_SECRET ? 'Set ✅' : 'Not set ❌'}`);
      console.log('='.repeat(50));
      console.log(`   Open: http://localhost:${PORT}`);
      console.log(`   Health: http://localhost:${PORT}/api/health`);
      console.log('='.repeat(50) + '\n');
    });
    
    server.keepAliveTimeout = 65000;
    server.headersTimeout = 66000;
    
  } catch (error) {
    console.error('\n❌ Failed to start server:', error.message);
    process.exit(1);
  }
}

startServer();
