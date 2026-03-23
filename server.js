const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const db = require('./db');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*' } });

const JWT_SECRET = process.env.JWT_SECRET || 'gamezone-secret-2024';
const PORT       = process.env.PORT || 3000;

// ─── Super Admin (hardcoded, never registerable) ──────────────────────────────
const ADMIN_UNAME  = 'iahsaan.berisco';
const ADMIN_HASH   = bcrypt.hashSync('B@nkaiminazuk1', 10);  // hashed once at startup
const ADMIN_SECRET = JWT_SECRET + '_superadmin_v1';

app.use(cors());
app.use(express.json());

// Admin panel — must be BEFORE static middleware
app.get('/connect', (_req, res) =>
  res.sendFile(path.join(__dirname, 'admin.html'))
);

app.use(express.static(path.join(__dirname, 'public')));

// ─── Middleware ────────────────────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}

function adminAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const p = jwt.verify(token, ADMIN_SECRET);
    if (!p.sa) throw new Error();
    next();
  } catch { res.status(401).json({ error: 'Unauthorized' }); }
}

async function accountCheck(req, res, next) {
  try {
    const user = await db.get('users', u => u.id === req.user.id);
    if (!user) return res.status(401).json({ error: 'User not found' });
    let status = user.status || 'active';
    // Auto-expire
    if (status === 'active' && user.expiry_date && Date.now() > user.expiry_date) {
      status = 'expired';
      await db.update('users', u => u.id === user.id, { status: 'expired' });
    }
    if (status === 'pending')     return res.status(403).json({ error: 'account_pending' });
    if (status === 'deactivated') return res.status(403).json({ error: 'account_deactivated' });
    if (status === 'expired')     return res.status(403).json({ error: 'subscription_expired' });
    next();
  } catch { next(); }   // don't break existing users if check fails
}

async function canManageGroup(userId, groupId) {
  const group = await db.get('groups', g => g.id === groupId);
  if (!group) return false;
  if (group.owner_id === userId) return true;
  return !!(await db.get('group_members', m => m.group_id === groupId && m.user_id === userId));
}

// ─── Super Admin Login ─────────────────────────────────────────────────────────
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  // Username: case-insensitive  |  Password: case-sensitive
  if (username.toLowerCase().trim() !== ADMIN_UNAME.toLowerCase())
    return res.status(401).json({ error: 'Invalid credentials' });
  if (!bcrypt.compareSync(password, ADMIN_HASH))
    return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ sa: true }, ADMIN_SECRET, { expiresIn: '12h' });
  res.json({ token, username: ADMIN_UNAME });
});

// ─── Super Admin Account Management ───────────────────────────────────────────
app.get('/api/admin/accounts', adminAuth, async (req, res) => {
  try {
    const users = await db.filter('users', () => true);
    const result = await Promise.all(users.map(async u => {
      const groups = await db.filter('groups', g => g.owner_id === u.id);
      let pcCount = 0;
      for (const g of groups) {
        const pcs = await db.filter('pcs', p => p.group_id === g.id);
        pcCount += pcs.length;
      }
      let status = u.status || 'active';
      if (status === 'active' && u.expiry_date && Date.now() > u.expiry_date) {
        status = 'expired';
        await db.update('users', x => x.id === u.id, { status: 'expired' });
      }
      return {
        id: u.id, username: u.username,
        label: u.label || '',
        status,
        price: u.price || 0,
        expiry_date: u.expiry_date || null,
        notes: u.notes || '',
        last_active: u.last_active || u.created_at || Date.now(),
        created_at: u.created_at || Date.now(),
        pc_count: pcCount,
        group_count: groups.length
      };
    }));
    result.sort((a, b) => {
      const o = { pending: 0, active: 1, deactivated: 2, expired: 3 };
      return (o[a.status] ?? 1) - (o[b.status] ?? 1);
    });
    res.json(result);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/admin/accounts/:id', adminAuth, async (req, res) => {
  try {
    const updates = {};
    ['label','status','price','expiry_date','notes'].forEach(f => {
      if (req.body[f] !== undefined) updates[f] = req.body[f];
    });
    await db.update('users', u => u.id === req.params.id, updates);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/accounts/:id', adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const groups = await db.filter('groups', g => g.owner_id === id);
    for (const g of groups) {
      const pcs = await db.filter('pcs', p => p.group_id === g.id);
      for (const pc of pcs) {
        await db.delete('installed_apps', a => a.pc_id === pc.id);
        await db.delete('sessions', s => s.pc_id === pc.id);
      }
      await db.delete('pcs', p => p.group_id === g.id);
      await db.delete('group_members', m => m.group_id === g.id);
    }
    await db.delete('groups', g => g.owner_id === id);
    await db.delete('users', u => u.id === id);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── Auth ──────────────────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    if (await db.get('users', u => u.username === username)) return res.status(400).json({ error: 'Username already taken' });
    const id = uuidv4();
    await db.insert('users', {
      id, username,
      password: bcrypt.hashSync(password, 10),
      status: 'pending',
      label: '', price: 0, expiry_date: null, notes: '',
      last_active: Date.now(),
      created_at: Date.now()
    });
    const token = jwt.sign({ id, username }, JWT_SECRET);
    res.json({ token, user: { id, username }, status: 'pending', expiry_date: null });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await db.get('users', u => u.username === username);
    if (!user || !bcrypt.compareSync(password, user.password))
      return res.status(401).json({ error: 'Invalid credentials' });
    let status = user.status || 'active';
    if (status === 'active' && user.expiry_date && Date.now() > user.expiry_date) {
      status = 'expired';
      await db.update('users', u => u.id === user.id, { status: 'expired', last_active: Date.now() });
    } else {
      await db.update('users', u => u.id === user.id, { last_active: Date.now() });
    }
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);
    res.json({ token, user: { id: user.id, username: user.username }, status, expiry_date: user.expiry_date || null });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── Groups ────────────────────────────────────────────────────────────────────
app.post('/api/groups', authMiddleware, accountCheck, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'Group name required' });
    const id = uuidv4();
    const group = await db.insert('groups', { id, name, owner_id: req.user.id, created_at: Date.now() });
    res.json(group);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/groups', authMiddleware, accountCheck, async (req, res) => {
  try {
    const owned = await db.filter('groups', g => g.owner_id === req.user.id);
    const memberGroupIds = (await db.filter('group_members', m => m.user_id === req.user.id)).map(m => m.group_id);
    const membered = await db.filter('groups', g => memberGroupIds.includes(g.id));
    const all = [...owned, ...membered].filter((g, i, arr) => arr.findIndex(x => x.id === g.id) === i);
    res.json(all);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/groups/:groupId', authMiddleware, accountCheck, async (req, res) => {
  try {
    const { groupId } = req.params;
    const group = await db.get('groups', g => g.id === groupId && g.owner_id === req.user.id);
    if (!group) return res.status(403).json({ error: 'Only owner can delete this group' });
    const pcIds = (await db.filter('pcs', p => p.group_id === groupId)).map(p => p.id);
    await db.delete('installed_apps', a => pcIds.includes(a.pc_id));
    await db.delete('sessions', s => pcIds.includes(s.pc_id));
    await db.delete('pcs', p => p.group_id === groupId);
    await db.delete('group_members', m => m.group_id === groupId);
    await db.delete('groups', g => g.id === groupId);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/groups/:groupId/admins', authMiddleware, accountCheck, async (req, res) => {
  try {
    const { groupId } = req.params;
    const group = await db.get('groups', g => g.id === groupId && g.owner_id === req.user.id);
    if (!group) return res.status(403).json({ error: 'Only owner can add admins' });
    const user = await db.get('users', u => u.username === req.body.username);
    if (!user) return res.status(404).json({ error: 'User not found' });
    await db.insertOrIgnore('group_members', { id: uuidv4(), group_id: groupId, user_id: user.id, role: 'admin' });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/groups/:groupId/admins', authMiddleware, accountCheck, async (req, res) => {
  try {
    const { groupId } = req.params;
    if (!await canManageGroup(req.user.id, groupId)) return res.status(403).json({ error: 'Forbidden' });
    const members = await db.filter('group_members', m => m.group_id === groupId);
    const admins = await Promise.all(members.map(async m => {
      const u = await db.get('users', u => u.id === m.user_id);
      return u ? { id: u.id, username: u.username, role: m.role } : null;
    }));
    res.json(admins.filter(Boolean));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/groups/:groupId/admins/:userId', authMiddleware, accountCheck, async (req, res) => {
  try {
    const { groupId, userId } = req.params;
    const group = await db.get('groups', g => g.id === groupId && g.owner_id === req.user.id);
    if (!group) return res.status(403).json({ error: 'Only owner can remove admins' });
    await db.delete('group_members', m => m.group_id === groupId && m.user_id === userId);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── PCs ───────────────────────────────────────────────────────────────────────
app.get('/api/groups/:groupId/pcs', authMiddleware, accountCheck, async (req, res) => {
  try {
    const { groupId } = req.params;
    if (!await canManageGroup(req.user.id, groupId)) return res.status(403).json({ error: 'Forbidden' });
    const pcs = (await db.filter('pcs', p => p.group_id === groupId))
      .sort((a, b) => (a.order || 0) - (b.order || 0))
      .map(p => ({ ...p, password: undefined }));
    res.json(pcs);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/groups/:groupId/pcs', authMiddleware, accountCheck, async (req, res) => {
  try {
    const { groupId } = req.params;
    if (!await canManageGroup(req.user.id, groupId)) return res.status(403).json({ error: 'Forbidden' });
    const { name, password, price_per_hour } = req.body;
    if (!name || !password) return res.status(400).json({ error: 'Name and password required' });
    const id = uuidv4();
    const existingPcs = await db.filter('pcs', p => p.group_id === groupId);
    const maxOrder = existingPcs.reduce((m, p) => Math.max(m, p.order || 0), 0);
    await db.insert('pcs', {
      id, group_id: groupId, name,
      password: bcrypt.hashSync(password, 10),
      is_online: 0, session_end: 0, stopwatch_start: 0,
      payment_status: null,
      price_per_hour: price_per_hour || 0,
      order: maxOrder + 1,
      time_history: []
    });
    res.json({ id, name, group_id: groupId, is_online: 0, session_end: 0, stopwatch_start: 0, payment_status: null, price_per_hour: price_per_hour || 0, order: maxOrder + 1, time_history: [] });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/groups/:groupId/pcs/:pcId', authMiddleware, accountCheck, async (req, res) => {
  try {
    const { groupId, pcId } = req.params;
    if (!await canManageGroup(req.user.id, groupId)) return res.status(403).json({ error: 'Forbidden' });
    await db.delete('installed_apps', a => a.pc_id === pcId);
    await db.delete('sessions', s => s.pc_id === pcId);
    await db.delete('pcs', p => p.id === pcId && p.group_id === groupId);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/groups/:groupId/pcs/reorder', authMiddleware, accountCheck, async (req, res) => {
  try {
    const { groupId } = req.params;
    const { order } = req.body;
    if (!await canManageGroup(req.user.id, groupId)) return res.status(403).json({ error: 'Forbidden' });
    for (const item of order)
      await db.update('pcs', p => p.id === item.pc_id, { order: item.order });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── Payment ───────────────────────────────────────────────────────────────────
app.post('/api/pcs/:pcId/payment', authMiddleware, accountCheck, async (req, res) => {
  try {
    const { pcId } = req.params;
    const { payment_status, group_id } = req.body;
    if (!await canManageGroup(req.user.id, group_id)) return res.status(403).json({ error: 'Forbidden' });
    await db.update('pcs', p => p.id === pcId, { payment_status });
    io.to(`group:${group_id}`).emit('group:'+group_id+':pc-session', { pc_id: pcId, payment_status, session_end: undefined, stopwatch_start: undefined });
    res.json({ success: true, payment_status });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── Sessions ──────────────────────────────────────────────────────────────────
app.post('/api/pcs/:pcId/session/start', authMiddleware, accountCheck, async (req, res) => {
  try {
    const { pcId } = req.params;
    const { duration_minutes, group_id } = req.body;
    if (!await canManageGroup(req.user.id, group_id)) return res.status(403).json({ error: 'Forbidden' });
    const pc = await db.get('pcs', p => p.id === pcId);
    if (!pc) return res.status(404).json({ error: 'PC not found' });
    const session_end = Math.floor(Date.now() / 1000) + duration_minutes * 60;
    await db.update('pcs', p => p.id === pcId, { session_end, stopwatch_start: 0 });
    await db.insert('sessions', { id: uuidv4(), pc_id: pcId, started_at: Math.floor(Date.now() / 1000), duration_minutes, price: (duration_minutes / 60) * pc.price_per_hour, ended_at: null });
    const remaining = duration_minutes * 60;
    io.to(`pc:${pcId}`).emit('session:start', { session_end, duration_minutes, remaining_seconds: remaining });
    io.to(`group:${group_id}`).emit('group:'+group_id+':pc-session', { pc_id: pcId, session_end, stopwatch_start: 0, payment_status: pc.payment_status });
    res.json({ success: true, session_end, remaining_seconds: remaining });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/pcs/:pcId/session/add-time', authMiddleware, accountCheck, async (req, res) => {
  try {
    const { pcId } = req.params;
    const { minutes, group_id } = req.body;
    if (!await canManageGroup(req.user.id, group_id)) return res.status(403).json({ error: 'Forbidden' });
    const pc = await db.get('pcs', p => p.id === pcId);
    if (!pc) return res.status(404).json({ error: 'PC not found' });
    const now = Math.floor(Date.now() / 1000);
    const new_end = Math.max((pc.session_end > now ? pc.session_end : now) + minutes * 60, now + 30);
    // Time history (max 5 entries)
    const history = pc.time_history || [];
    const newHistory = [{ mins: minutes, at: Date.now(), type: minutes > 0 ? 'add' : 'remove' }, ...history].slice(0, 5);
    await db.update('pcs', p => p.id === pcId, { session_end: new_end, time_history: newHistory });
    const rem = new_end - now;
    io.to(`pc:${pcId}`).emit('session:add-time', { session_end: new_end, added_minutes: minutes, remaining_seconds: rem });
    io.to(`group:${group_id}`).emit('group:'+group_id+':pc-session', { pc_id: pcId, session_end: new_end, stopwatch_start: pc.stopwatch_start || 0, payment_status: pc.payment_status, time_history: newHistory });
    res.json({ success: true, session_end: new_end, remaining_seconds: rem });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/pcs/:pcId/session/end', authMiddleware, accountCheck, async (req, res) => {
  try {
    const { pcId } = req.params;
    const { group_id } = req.body;
    if (!await canManageGroup(req.user.id, group_id)) return res.status(403).json({ error: 'Forbidden' });
    await db.update('pcs', p => p.id === pcId, { session_end: 0, stopwatch_start: 0 });
    await db.update('sessions', s => s.pc_id === pcId && !s.ended_at, { ended_at: Math.floor(Date.now() / 1000) });
    io.to(`pc:${pcId}`).emit('session:end', {});
    io.to(`group:${group_id}`).emit('group:'+group_id+':pc-session', { pc_id: pcId, session_end: 0, stopwatch_start: 0 });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/pcs/:pcId/session/stopwatch', authMiddleware, accountCheck, async (req, res) => {
  try {
    const { pcId } = req.params;
    const { group_id } = req.body;
    if (!await canManageGroup(req.user.id, group_id)) return res.status(403).json({ error: 'Forbidden' });
    const started_at = Math.floor(Date.now() / 1000);
    await db.update('pcs', p => p.id === pcId, { session_end: 0, stopwatch_start: started_at });
    io.to(`pc:${pcId}`).emit('session:stopwatch', { started_at });
    io.to(`group:${group_id}`).emit('group:'+group_id+':pc-session', { pc_id: pcId, session_end: 0, stopwatch_start: started_at });
    res.json({ success: true, started_at });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/pcs/:pcId/session/stopwatch-end', authMiddleware, accountCheck, async (req, res) => {
  try {
    const { pcId } = req.params;
    const { group_id } = req.body;
    if (!await canManageGroup(req.user.id, group_id)) return res.status(403).json({ error: 'Forbidden' });
    await db.update('pcs', p => p.id === pcId, { session_end: 0, stopwatch_start: 0 });
    io.to(`pc:${pcId}`).emit('session:stopwatch-end', {});
    io.to(`pc:${pcId}`).emit('command:lock', {});
    io.to(`group:${group_id}`).emit('group:'+group_id+':pc-session', { pc_id: pcId, session_end: 0, stopwatch_start: 0 });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── PC Control ────────────────────────────────────────────────────────────────
app.post('/api/pcs/:pcId/lock', authMiddleware, accountCheck, async (req, res) => {
  try {
    if (!await canManageGroup(req.user.id, req.body.group_id)) return res.status(403).json({ error: 'Forbidden' });
    io.to(`pc:${req.params.pcId}`).emit('command:lock', {});
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/pcs/:pcId/unlock', authMiddleware, accountCheck, async (req, res) => {
  try {
    if (!await canManageGroup(req.user.id, req.body.group_id)) return res.status(403).json({ error: 'Forbidden' });
    io.to(`pc:${req.params.pcId}`).emit('command:unlock', {});
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Request process list from PC — PC responds via socket 'pc:processes' event
app.post('/api/pcs/:pcId/processes', authMiddleware, accountCheck, async (req, res) => {
  try {
    const { group_id } = req.body;
    if (!await canManageGroup(req.user.id, group_id)) return res.status(403).json({ error: 'Forbidden' });
    // Ask the PC to send its process list, wait up to 5s for response
    const pcId = req.params.pcId;
    const responseKey = `procs:${pcId}`;
    let resolved = false;
    const cleanup = () => { io.off(responseKey, handler); };
    const handler = (data) => {
      if (!resolved) { resolved = true; cleanup(); res.json({ processes: data.processes }); }
    };
    io.once(responseKey, handler);
    io.to(`pc:${pcId}`).emit('command:get-processes', {});
    setTimeout(() => { if (!resolved) { resolved = true; cleanup(); res.json({ processes: [] }); } }, 5000);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Kill a specific process by PID
app.post('/api/pcs/:pcId/kill-process', authMiddleware, accountCheck, async (req, res) => {
  try {
    const { group_id, pid, name } = req.body;
    if (!await canManageGroup(req.user.id, group_id)) return res.status(403).json({ error: 'Forbidden' });
    io.to(`pc:${req.params.pcId}`).emit('command:kill-process', { pid, name });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/pcs/:pcId/launch', authMiddleware, accountCheck, async (req, res) => {
  try {
    const { app_path, group_id } = req.body;
    if (!await canManageGroup(req.user.id, group_id)) return res.status(403).json({ error: 'Forbidden' });
    io.to(`pc:${req.params.pcId}`).emit('command:launch', { app_path });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/pcs/:pcId/apps', authMiddleware, accountCheck, async (req, res) => {
  try {
    res.json(await db.filter('installed_apps', a => a.pc_id === req.params.pcId));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── Me (fresh status check) ─────────────────────────────────────────────────
app.get('/api/me', authMiddleware, async (req, res) => {
  try {
    const user = await db.get('users', u => u.id === req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    let status = user.status || 'active';
    if (status === 'active' && user.expiry_date && Date.now() > user.expiry_date) {
      status = 'expired';
      await db.update('users', u => u.id === user.id, { status: 'expired' });
    }
    res.json({ status, expiry_date: user.expiry_date || null });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── Health ─────────────────────────────────────────────────────────────────────
app.get('/api/health', async (req, res) => {
  try {
    await db._ready;
    res.json({ status: 'ok', database: 'connected', uptime: process.uptime() });
  } catch { res.json({ status: 'ok', database: 'disconnected', uptime: process.uptime() }); }
});

// ─── WebSocket ──────────────────────────────────────────────────────────────────
io.on('connection', (socket) => {
  socket.on('pc:auth', async ({ pc_name, group_id, password }, callback) => {
    const pc = await db.get('pcs', p => p.name === pc_name && p.group_id === group_id);
    if (!pc || !bcrypt.compareSync(password, pc.password))
      return callback({ success: false, error: 'Invalid PC credentials' });
    socket.join(`pc:${pc.id}`);
    socket.pcId = pc.id;
    socket.groupId = group_id;
    await db.update('pcs', p => p.id === pc.id, { is_online: 1 });
    io.emit(`group:${group_id}:pc-status`, { pc_id: pc.id, is_online: true });
    console.log(`[+] PC "${pc_name}" connected`);
    const now = Math.floor(Date.now()/1000);
    const swStart = (pc.stopwatch_start && pc.stopwatch_start < now) ? pc.stopwatch_start : 0;
    const remAuth = pc.session_end > now ? pc.session_end - now : 0;
    callback({ success: true, pc_id: pc.id, session_end: pc.session_end, stopwatch_start: swStart, remaining_seconds: remAuth });
  });

  socket.on('pc:apps', async ({ apps }) => {
    if (!socket.pcId) return;
    await db.delete('installed_apps', a => a.pc_id === socket.pcId);
    for (const a of apps)
      await db.insert('installed_apps', { id: uuidv4(), pc_id: socket.pcId, name: a.name, path: a.path });
  });

  socket.on('admin:subscribe', ({ group_id, token }) => {
    try { jwt.verify(token, JWT_SECRET); socket.join(`group:${group_id}`); } catch {}
  });

  // Admin broadcasts history update to other admins in same group
  socket.on('admin:history-update', ({ group_id, pc_id, history }) => {
    socket.to(`group:${group_id}`).emit('admin:history-sync', { pc_id, history });
  });

  // Admin requests history from other devices in same group
  socket.on('admin:request-history', ({ group_id, pc_id }) => {
    socket.to(`group:${group_id}`).emit('admin:request-history', { pc_id });
  });

  // PC sends back process list in response to command:get-processes
  socket.on('pc:processes', ({ processes }) => {
    if (socket.pcId) {
      io.emit(`procs:${socket.pcId}`, { processes });
    }
  });

  socket.on('disconnect', async () => {
    if (socket.pcId) {
      await db.update('pcs', p => p.id === socket.pcId, { is_online: 0 });
      if (socket.groupId) io.emit(`group:${socket.groupId}:pc-status`, { pc_id: socket.pcId, is_online: false });
    }
  });
});

// ─── Start ──────────────────────────────────────────────────────────────────────
db._ready.then(() => {
  server.listen(PORT, () => {
    console.log(`\n🎮 GameZone Server running on port ${PORT}`);
    console.log(`   Mode: ${process.env.MONGODB_URI ? 'MongoDB (cloud)' : 'Local JSON file'}`);
    console.log(`   Admin panel: /connect\n`);
  });
}).catch(err => {
  console.error('Failed to connect to database:', err);
  process.exit(1);
});
