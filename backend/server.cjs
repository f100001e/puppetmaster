#!/usr/bin/env node
'use strict';

/*─────────────────────────── 0. Imports & config ───────────────────────────*/
const fs        = require('fs');
const path      = require('path');
const http      = require('http');
const express   = require('express');
const { Server }= require('socket.io');
const Database  = require('better-sqlite3');
const dotenv    = require('dotenv');

dotenv.config({ path: path.resolve(__dirname, '../.env') });

/*──────────────────────── 1. Constants & init dirs ─────────────────────────*/
const PORT     = +process.env.BACKEND_PORT || 3000;
const FRONTEND = process.env.FRONTEND_URL  || 'http://localhost:5173';
const ORIGINS  = (process.env.ALLOWED_ORIGINS || FRONTEND).split(',');
const DBPATH   = process.env.DB_PATH || path.join(__dirname,'../data/gtag_monitor.db');
const LOGDIR   = process.env.LOG_DIR || path.join(__dirname,'../gtag_logs');

fs.mkdirSync(path.dirname(DBPATH), { recursive:true });
fs.mkdirSync(LOGDIR,            { recursive:true });

const logFile = path.join(LOGDIR,`ua_${new Date().toISOString().replace(/[:T]/g,'-').split('.')[0]}.log`);
const log     = fs.createWriteStream(logFile,{flags:'a'});
console.log(`📝 UA session log → ${logFile}`);

/*─────────────────────────── 2. SQLite schema ─────────────────────────────*/
const db = new Database(DBPATH);
db.pragma('foreign_keys = ON');
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS ua_log(
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ua       TEXT NOT NULL,
    is_http  INTEGER NOT NULL CHECK(is_http IN(0,1)),
    risk     INTEGER NOT NULL CHECK(risk BETWEEN 0 AND 100),
    ts       INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_ua_ts ON ua_log(ts);
`);
const insertUA        = db.prepare(`INSERT INTO ua_log(ua,is_http,risk,ts) VALUES(@ua,@is_http,@risk,@ts)`);
const lastInsertRowId = db.prepare(`SELECT last_insert_rowid() id`).pluck();

/*────────────────────────── 3. Threat analyser ─────────────────────────────*/
function analyzeThreat(ua='', isHttp=false){
  ua = String(ua).toLowerCase();
  if(!ua) return 10;
  if(['sqlmap','nmap','metasploit','hydra','burpsuite'].some(p=>ua.includes(p))) return 100;

  const scoreMap = { acunetix:85,netsparker:80,dirbuster:75 };
  for(const [p,score] of Object.entries(scoreMap))
    if(ua.includes(p)) return score;

  return isHttp ? 10 : 25;
}

const app        = express();
const httpServer = http.createServer(app);

app.use(express.json({ limit: '1mb' }));
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (!origin || ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin || ORIGINS[0]);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

/* 👉 static-file middleware – serves /public/index.html, css, js, etc. */
app.use(express.static(path.resolve(__dirname, '../public')));

/*───────────────────────── 5. Socket.IO namespace ─────────────────────────*/
 const io = new Server(httpServer, {
     cors: { origin: ORIGINS, methods: ['GET','POST'] },
   transports: ['websocket'],       // only WebSocket transport
     allowEIO3: true,                 // accept Engine.IO v3 (Python client)
     perMessageDeflate: false         // disable RSV1 compression bit
 });

io.of('/scanner').on('connection',socket=>{
  console.log('⚡ socket',socket.id,'connected');
  socket.on('disconnect',()=>console.log('⚡ socket',socket.id,'disconnected'));
});

// Add this middleware BEFORE your routes:
app.use((req, res, next) => {
  if (req.method === 'OPTIONS') {
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');  // Fix typo
    return res.sendStatus(204);
  }
  next();
});

/*────────────────────────────── 6. Routes ─────────────────────────────────*/
app.get('/api/ua/top',(_req,res)=>{
  const rows = db.prepare(`
    SELECT ua, MAX(risk) maxRisk, COUNT(*) hits
    FROM ua_log GROUP BY ua
    ORDER BY maxRisk DESC, hits DESC LIMIT 100
  `).all();
  res.json(rows);
});

/* <-- NEW: scanner posts here -------------------------------------------- */
app.post('/log_ua',(req,res)=>{
  try{
    const { ua='', isHttp=false, ts=Date.now() } = req.body || {};
    const risk = analyzeThreat(ua, isHttp);
    insertUA.run({ ua:ua.slice(0,1024), is_http:isHttp?1:0, risk, ts:Math.floor(ts/1000) });
    const id = lastInsertRowId.get();
    io.of('/scanner').emit('uaUpdate',{ ua, isHttp, ts, risk, id });
    log.write(`${new Date().toISOString()} ${ua} RISK:${risk}\n`);
    res.sendStatus(200);
  }catch(e){ res.status(400).json({error:e.message}); }
});
/* ----------------------------------------------------------------------- */

app.get('/ping',(_req,res)=>res.send('pong'));

/*────────────────────────── 7. lifecycle hooks ───────────────────────────*/
httpServer.listen(PORT,()=>console.log(`🌐 backend on http://localhost:${PORT}`));

process.on('SIGINT',graceful); process.on('SIGTERM',graceful);
function graceful(){
  console.log('\n🛑 shutdown'); httpServer.close(()=>db.close()); }
