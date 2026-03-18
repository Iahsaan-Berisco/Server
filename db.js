/**
 * Database layer — uses MongoDB if MONGODB_URI env var is set (production/Railway),
 * otherwise falls back to local JSON file (local development).
 */
const fs = require('fs');
const path = require('path');

const USE_MONGO = !!process.env.MONGODB_URI;

// ── LOCAL JSON DB (for running locally) ──────────────────────────────────────
const DB_FILE = path.join(__dirname, 'gamezone-data.json');
const DEFAULTS = { users: [], groups: [], group_members: [], pcs: [], sessions: [], installed_apps: [] };

function loadJson() {
  if (!fs.existsSync(DB_FILE)) { fs.writeFileSync(DB_FILE, JSON.stringify(DEFAULTS, null, 2)); return JSON.parse(JSON.stringify(DEFAULTS)); }
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch { return JSON.parse(JSON.stringify(DEFAULTS)); }
}
function saveJson(data) { fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2)); }
let _db = loadJson();

const localDb = {
  all: (t) => _db[t] || [],
  get: (t, fn) => (_db[t] || []).find(fn) || null,
  filter: (t, fn) => (_db[t] || []).filter(fn),
  insert: (t, row) => { if (!_db[t]) _db[t] = []; _db[t].push(row); saveJson(_db); return row; },
  insertOrIgnore: (t, row) => { if (!_db[t]) _db[t] = []; if (!_db[t].find(r => r.id === row.id)) { _db[t].push(row); saveJson(_db); } return row; },
  update: (t, fn, changes) => { if (!_db[t]) return; _db[t] = _db[t].map(r => fn(r) ? { ...r, ...changes } : r); saveJson(_db); },
  delete: (t, fn) => { if (!_db[t]) return; _db[t] = _db[t].filter(r => !fn(r)); saveJson(_db); },
};

// ── MONGODB (for Railway/production) ─────────────────────────────────────────
let mongoDb = null;
let mongoReady = false;

async function initMongo() {
  const { MongoClient } = require('mongodb');
  const client = new MongoClient(process.env.MONGODB_URI);
  await client.connect();
  mongoDb = client.db('gamezone');
  mongoReady = true;
  console.log('[+] Connected to MongoDB');
}

const mongoWrapper = {
  all: async (t) => mongoDb.collection(t).find({}).toArray(),
  get: async (t, fn) => { const all = await mongoDb.collection(t).find({}).toArray(); return all.find(fn) || null; },
  filter: async (t, fn) => { const all = await mongoDb.collection(t).find({}).toArray(); return all.filter(fn); },
  insert: async (t, row) => { await mongoDb.collection(t).insertOne(row); return row; },
  insertOrIgnore: async (t, row) => { await mongoDb.collection(t).updateOne({ id: row.id }, { $setOnInsert: row }, { upsert: true }); return row; },
  update: async (t, fn, changes) => { const all = await mongoDb.collection(t).find({}).toArray(); for (const r of all) { if (fn(r)) await mongoDb.collection(t).updateOne({ id: r.id }, { $set: changes }); } },
  delete: async (t, fn) => { const all = await mongoDb.collection(t).find({}).toArray(); for (const r of all) { if (fn(r)) await mongoDb.collection(t).deleteOne({ id: r.id }); } },
};

// ── UNIFIED ASYNC WRAPPER ─────────────────────────────────────────────────────
// Makes both DBs work the same way with async/await
const db = {
  _ready: USE_MONGO ? initMongo() : Promise.resolve(),
  all: (t) => USE_MONGO ? mongoWrapper.all(t) : Promise.resolve(localDb.all(t)),
  get: (t, fn) => USE_MONGO ? mongoWrapper.get(t, fn) : Promise.resolve(localDb.get(t, fn)),
  filter: (t, fn) => USE_MONGO ? mongoWrapper.filter(t, fn) : Promise.resolve(localDb.filter(t, fn)),
  insert: (t, row) => USE_MONGO ? mongoWrapper.insert(t, row) : Promise.resolve(localDb.insert(t, row)),
  insertOrIgnore: (t, row) => USE_MONGO ? mongoWrapper.insertOrIgnore(t, row) : Promise.resolve(localDb.insertOrIgnore(t, row)),
  update: (t, fn, changes) => USE_MONGO ? mongoWrapper.update(t, fn, changes) : Promise.resolve(localDb.update(t, fn, changes)),
  delete: (t, fn) => USE_MONGO ? mongoWrapper.delete(t, fn) : Promise.resolve(localDb.delete(t, fn)),
};

module.exports = db;
