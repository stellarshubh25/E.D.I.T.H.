'use strict';
/**
 * E.D.I.T.H. - Enhanced Digital Identity, Trust & Heuristics
 * Zero-dependency backend (only Node's built-in modules). Run:  node server.js
 *
 * Everything lives in memory. Restart the server (or press "Reset demo") to start fresh.
 */
const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;

// ---------- Tunable settings (change these to tune your demo) ----------
const WINDOW_MS = 20000;        // sliding window used to measure access rate
const SPIKE_FACTOR = 3;         // rate above (baseline x this) counts as a spike
const MIN_SPIKE_COUNT = 8;      // ignore tiny windows
const COOLDOWN_MS = 15000;      // same penalty type applies at most once per this time
const RECOVER_AFTER_MS = 20000; // quiet time before trust score starts recovering
const MISBEHAVE_MULT = 8;       // how much faster the bad app accesses data
const PENALTY = { spike: 15, newPermission: 10, unauthorized: 20 };
const SENSITIVE = new Set(['contacts', 'location', 'microphone']);

// ---------- The three demo apps ----------
const APP_DEFS = [
  {
    id: 'photoeditor', name: 'PhotoEditor', purpose: 'Edits and filters your photos',
    perms: ['files', 'camera'], used: ['files', 'camera'], rate: 6, // normal accesses per minute
    reasons: { files: 'Open photo to edit', camera: 'Take a new photo' },
  },
  {
    id: 'notesapp', name: 'NotesApp', purpose: 'Keeps your personal notes',
    perms: ['files', 'location'], used: ['files'], rate: 4, // has location but never uses it
    reasons: { files: 'Save note' },
  },
  {
    id: 'fitnesstracker', name: 'FitnessTracker', purpose: 'Tracks your runs and workouts',
    perms: ['location'], used: ['location'], rate: 5,
    reasons: { location: 'Record running route' },
  },
];

let state;

function reset() {
  state = {
    startedAt: Date.now(),
    misbehaving: false,
    tick: 0,
    logs: [],   // every access attempt
    events: [], // alerts and permission changes
    apps: APP_DEFS.map((d) => ({
      id: d.id, name: d.name, purpose: d.purpose, baseline: d.rate, def: d,
      score: 100, status: 'active',
      perms: Object.fromEntries(d.perms.map((r) => [r, { status: 'granted', uses: 0, recent: [] }])),
      window: [],          // timestamps of recent access attempts (sliding window)
      lastPenalty: {},     // penalty type -> time last applied
      lastPenaltyAt: 0,
      acc: 0,              // simulator accumulator
      history: [100],      // trust score over time (1 point per second)
    })),
  };
}

// ---------- Helpers ----------
const band = (s) => (s >= 80 ? 'safe' : s >= 50 ? 'watch' : 'risky');
const findApp = (id) => state.apps.find((a) => a.id === id);

function addEvent(kind, app, severity, message) {
  state.events.unshift({ ts: Date.now(), kind, app: app.name, severity, message });
  if (state.events.length > 60) state.events.pop();
}

// Apply a penalty, at most once per COOLDOWN_MS for each penalty type.
function penalize(app, type, severity, message) {
  const now = Date.now();
  if (now - (app.lastPenalty[type] || 0) < COOLDOWN_MS) return;
  app.lastPenalty[type] = now;
  app.lastPenaltyAt = now;
  app.score = Math.max(0, app.score - PENALTY[type]);
  addEvent('alert', app, severity, `${message} (trust score -${PENALTY[type]})`);
}

// ---------- Core: an app tries to access a resource ----------
function handleAccess(appId, resource, reason) {
  const app = findApp(appId);
  if (!app) return { error: 'Unknown app' };
  const now = Date.now();

  // Sliding window: drop old timestamps, add this attempt.
  app.window.push(now);
  while (app.window.length && now - app.window[0] > WINDOW_MS) app.window.shift();

  let allowed = false;
  let note = '';

  if (app.status === 'suspended') {
    note = 'App is suspended';
  } else {
    const p = app.perms[resource];
    if (!p) {
      // Rule 2: app asks for a permission it never had -> create a pending request
      app.perms[resource] = { status: 'pending', uses: 0, recent: [] };
      note = 'Requested a new permission';
      penalize(app, 'newPermission', 'medium', `${app.name} requested new permission: ${resource}`);
    } else if (p.status === 'granted') {
      allowed = true;
    } else if (p.status === 'restricted') {
      // Restricted = limited to 3 uses per minute
      p.recent = p.recent.filter((t) => now - t < 60000);
      if (p.recent.length < 3) { p.recent.push(now); allowed = true; }
      else note = 'Restricted: rate limit reached';
    } else {
      // Rule 3: pending or revoked -> unauthorized attempt
      note = p.status === 'pending' ? 'Permission not approved yet' : 'Permission revoked';
      penalize(app, 'unauthorized', 'high', `${app.name} tried to access ${resource} without permission`);
    }
    if (allowed) app.perms[resource].uses++;

    // Rule 1: frequency spike versus the app's normal rate
    const ratePerMin = app.window.length * (60000 / WINDOW_MS);
    if (app.window.length >= MIN_SPIKE_COUNT && ratePerMin > app.baseline * SPIKE_FACTOR) {
      penalize(app, 'spike', 'medium',
        `${app.name} is accessing data ${Math.round(ratePerMin / app.baseline)}x more often than normal`);
    }
  }

  state.logs.unshift({ ts: now, app: app.name, resource, reason: reason || 'No reason given', allowed, note });
  if (state.logs.length > 60) state.logs.pop();
  return { allowed, note };
}

// ---------- Simulator: runs once per second ----------
function simTick() {
  state.tick++;
  const now = Date.now();
  for (const app of state.apps) {
    const bad = state.misbehaving && app.id === 'fitnesstracker';

    // Normal traffic at the app's baseline rate (deterministic, so the demo is predictable)
    app.acc += (app.baseline * (bad ? MISBEHAVE_MULT : 1)) / 60;
    while (app.acc >= 1) {
      app.acc -= 1;
      const u = app.def.used;
      const res = u[Math.floor(Math.random() * u.length)];
      handleAccess(app.id, res, app.def.reasons[res]);
    }

    // Misbehaving app also goes after data it was never given
    if (bad && state.tick % 3 === 0) {
      const targets = ['contacts', 'files', 'microphone'];
      handleAccess(app.id, targets[Math.floor(state.tick / 3) % 3], 'Unspecified');
    }

    // Slow recovery after a quiet period
    if (app.status === 'active' && app.score < 100 &&
        now - app.lastPenaltyAt > RECOVER_AFTER_MS && state.tick % 5 === 0) app.score++;

    app.history.push(app.score);
    if (app.history.length > 90) app.history.shift();
  }
}

// ---------- Recommendations (computed from current state) ----------
function recommendations() {
  const now = Date.now();
  const recs = [];
  for (const app of state.apps) {
    if (app.status === 'suspended') continue;
    for (const [res, p] of Object.entries(app.perms)) {
      if (p.status === 'pending') {
        recs.push({
          id: `deny-${app.id}-${res}`, severity: SENSITIVE.has(res) ? 'high' : 'medium',
          text: `${app.name} asked for ${res} access, which doesn't fit its purpose (${app.purpose.toLowerCase()}).`,
          actionLabel: `Deny ${res}`, action: { type: 'permission', appId: app.id, resource: res, value: 'revoke' },
        });
      }
      if (p.status === 'granted' && p.uses === 0 && now - state.startedAt > 30000) {
        recs.push({
          id: `unused-${app.id}-${res}`, severity: SENSITIVE.has(res) ? 'medium' : 'low',
          text: `${app.name} has ${res} access but has never used it. Revoking reduces your exposure.`,
          actionLabel: `Revoke ${res}`, action: { type: 'permission', appId: app.id, resource: res, value: 'revoke' },
        });
      }
    }
    if (app.score < 50) {
      recs.push({
        id: `suspend-${app.id}`, severity: 'high',
        text: `${app.name} has a trust score of ${app.score}. Suspend it until you have reviewed its activity.`,
        actionLabel: 'Suspend app', action: { type: 'status', appId: app.id, value: 'suspended' },
      });
    }
  }
  const order = { high: 0, medium: 1, low: 2 };
  return recs.sort((a, b) => order[a.severity] - order[b.severity]);
}

// ---------- Access control actions ----------
const PERM_VALUES = { approve: 'granted', restrict: 'restricted', revoke: 'revoked' };

function setPermission(appId, resource, value) {
  const app = findApp(appId);
  if (!app || !app.perms[resource] || !PERM_VALUES[value]) return { error: 'Invalid request' };
  app.perms[resource].status = PERM_VALUES[value];
  app.perms[resource].recent = [];
  addEvent('change', app, 'info', `${resource} permission for ${app.name} set to ${PERM_VALUES[value]}`);
  return { ok: true };
}

function setStatus(appId, status) {
  const app = findApp(appId);
  if (!app || !['active', 'suspended'].includes(status)) return { error: 'Invalid request' };
  app.status = status;
  addEvent('change', app, 'info', `${app.name} was ${status === 'suspended' ? 'suspended' : 'reactivated'}`);
  return { ok: true };
}

// ---------- API snapshot for the dashboard ----------
function snapshot() {
  return {
    misbehaving: state.misbehaving,
    apps: state.apps.map((a) => ({
      id: a.id, name: a.name, purpose: a.purpose, score: a.score, band: band(a.score),
      status: a.status, history: a.history,
      perms: Object.entries(a.perms).map(([resource, p]) => ({
        resource, status: p.status, uses: p.uses, sensitive: SENSITIVE.has(resource),
      })),
    })),
    logs: state.logs.slice(0, 40),
    events: state.events.slice(0, 40),
    recommendations: recommendations(),
  };
}

// ---------- Tiny HTTP server ----------
function send(res, code, data, type = 'application/json') {
  res.writeHead(code, { 'Content-Type': type });
  res.end(type === 'application/json' ? JSON.stringify(data) : data);
}

function readBody(req) {
  return new Promise((resolve) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => { try { resolve(JSON.parse(raw || '{}')); } catch { resolve({}); } });
  });
}

const server = http.createServer(async (req, res) => {
  const url = req.url.split('?')[0];

  if (req.method === 'GET' && url === '/api/state') return send(res, 200, snapshot());

  if (req.method === 'POST' && url.startsWith('/api/')) {
    const b = await readBody(req);
    if (url === '/api/access') return send(res, 200, handleAccess(b.appId, b.resource, b.reason));
    if (url === '/api/permission') return send(res, 200, setPermission(b.appId, b.resource, b.value));
    if (url === '/api/status') return send(res, 200, setStatus(b.appId, b.status || b.value));
    if (url === '/api/simulator') { state.misbehaving = !!b.misbehaving; return send(res, 200, { ok: true }); }
    if (url === '/api/reset') { reset(); return send(res, 200, { ok: true }); }
    return send(res, 404, { error: 'Not found' });
  }

  if (req.method === 'GET' && (url === '/' || url === '/index.html')) {
    return fs.readFile(path.join(__dirname, 'public', 'index.html'), (err, data) =>
      err ? send(res, 500, 'Could not load dashboard', 'text/plain') : send(res, 200, data, 'text/html; charset=utf-8'));
  }
  send(res, 404, 'Not found', 'text/plain');
});

reset();
setInterval(simTick, 1000);
server.listen(PORT, () => console.log(`E.D.I.T.H. running at http://localhost:${PORT}`));