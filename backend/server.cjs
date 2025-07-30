#!/usr/bin/env node
'use strict';

//──────────────────────────────────────────────────────────────────
// 0. Imports & Configuration
//──────────────────────────────────────────────────────────────────
const fs = require('fs');
const path = require('path');
const http = require('http');
const express = require('express');
const { Server } = require('socket.io');
const Database = require('better-sqlite3');
const dotenv = require('dotenv');

dotenv.config({ path: path.resolve(__dirname, '../.env') });

//──────────────────────────────────────────────────────────────────
// 1. Constants & Initialization
//──────────────────────────────────────────────────────────────────
const PORT = +process.env.PORT || 3000;
const DBPATH = process.env.DB_PATH || path.join(__dirname, '../data/gtag_monitor.db');
const LOGDIR = path.join(__dirname, '../gtag_logs');

// Ensure directories exist
fs.mkdirSync(path.dirname(DBPATH), { recursive: true });
fs.mkdirSync(LOGDIR, { recursive: true });

// Log file setup
const logFile = path.join(LOGDIR, `ua_${new Date().toISOString().replace(/[:T]/g, '-').split('.')[0]}.log`);
const log = fs.createWriteStream(logFile, { flags: 'a' });
console.log(`📝 UA session log → ${logFile}`);

//──────────────────────────────────────────────────────────────────
// 2. Database Setup
//──────────────────────────────────────────────────────────────────
const db = new Database(DBPATH);
db.pragma("foreign_keys = ON");
db.pragma("journal_mode = WAL");
db.pragma("synchronous = NORMAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS ua_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ua       TEXT    NOT NULL,
    is_http  INTEGER NOT NULL CHECK(is_http IN (0,1)),
    risk     INTEGER NOT NULL CHECK(risk BETWEEN 0 AND 100),
    ts       INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_ua_log_ts ON ua_log(ts);
`);

const insertUA = db.prepare(`
  INSERT INTO ua_log (ua, is_http, risk, ts)
  VALUES (@ua, @is_http, @risk, @ts)
`);

const getLastInsertId = db.prepare(`SELECT last_insert_rowid() AS id`).pluck();

//──────────────────────────────────────────────────────────────────
// 3. Threat Analysis
//──────────────────────────────────────────────────────────────────
function analyzeThreat(ua = '', isHttp = false) {
  if (!ua || typeof ua !== 'string') return 10;

  const uaLower = ua.toLowerCase();
  let risk = 10;

  // Critical patterns
  const critical = ['sqlmap', 'nmap', 'metasploit', 'hydra', 'burpsuite'];
  if (critical.some(p => uaLower.includes(p))) return 100;

  // Suspicious patterns
  const suspicious = {
    'acunetix': 85, 'netsparker': 80, 'dirbuster': 75
  };
  for (const [pattern, score] of Object.entries(suspicious)) {
    if (uaLower.includes(pattern)) risk = Math.max(risk, score);
  }

  return isHttp ? risk : Math.min(100, risk + 15);
}

//──────────────────────────────────────────────────────────────────
// 4. Server Setup
//──────────────────────────────────────────────────────────────────
const app = express();
const httpServer = http.createServer(app);

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', process.env.FRONTEND_URL || 'http://localhost:8080');
  res.header('Access-Control-Allow-Methods', 'GET, POST');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  next();
});

const io = new Server(httpServer, {
  cors: {
    origin: process.env.ALLOWED_ORIGINS || 'http://localhost:8080', // Match frontend
    methods: ['GET', 'POST']
  },
  transports: ['websocket']  // Disable HTTP long-polling fallback
});

//──────────────────────────────────────────────────────────────────
// 5. Routes
//──────────────────────────────────────────────────────────────────
app.use(express.static(path.resolve(__dirname, '../public')));

app.get('/ping', (_, res) => res.send('pong'));

app.get('/api/ua/top', (_req, res) => {
  try {
    const rows = db.prepare(`
      SELECT ua, MAX(risk) AS maxRisk, COUNT(*) AS hits
      FROM ua_log
      GROUP BY ua
      ORDER BY maxRisk DESC, hits DESC
      LIMIT 100
    `).all();
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Database query failed' });
  }
});

//──────────────────────────────────────────────────────────────────
// 6. Socket.IO Handlers
//──────────────────────────────────────────────────────────────────
io.of('/scanner').on('connection', (socket) => {
  console.log(`⚡ Client connected: ${socket.id}`);

  socket.on('uaSeen', (hit) => {
    try {
      if (!hit?.ua) throw new Error('Missing User-Agent');

      const risk = analyzeThreat(String(hit.ua).slice(0, 1024), !!hit.isHttp);
      const ts = Math.floor((hit.ts || Date.now()) / 1000);

      insertUA.run({
        ua: hit.ua,
        is_http: hit.isHttp ? 1 : 0,
        risk,
        ts
      });

      io.of('/scanner').emit('uaUpdate', {
        ...hit,
        risk,
        id: getLastInsertId.get().id
      });
    } catch (e) {
      socket.emit('uaError', { message: e.message });
    }
  });

  socket.on('disconnect', () => {
    console.log(`⚡ Client disconnected: ${socket.id}`);
  });
});

//──────────────────────────────────────────────────────────────────
// 7. Server Lifecycle
//──────────────────────────────────────────────────────────────────
httpServer.listen(PORT, () => {
  console.log(`🌐 Server running on http://localhost:${PORT}`);
});

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

function shutdown() {
  console.log('\n🛑 Shutting down...');
  httpServer.close(() => {
    log.end('\n===== Server stopped =====\n', () => db.close());
  });
}