#!/usr/bin/env node
/**
 * Threat-aware scanner / UI listener   (port :8888)
 */
'use strict';

/*───────────────────────── 0. Imports & .env ──────────────────────────*/
const fs      = require('fs');
const path    = require('path');
const http    = require('http');
const chalk   = require('chalk');
const dotenv  = require('dotenv');

dotenv.config({ path: path.resolve(__dirname, '../.env') });

/*───────────────────────── 1. Config from .env ─────────────────────────*/
const CONFIG = {
  HOST       : process.env.SCANNER_HOST         || 'localhost',
  PORT       : +process.env.SCANNER_LISTEN_PORT || 8888,
  LOG_DIR    : process.env.LOG_DIR              ||
    path.resolve(__dirname,'../gtag_logs'),

  RISK_DEFAULT  : +process.env.RISK_DEFAULT      || 10,
  RISK_CRITICAL : 100,
  RISK_HIGH     : 75,
  RISK_MEDIUM   : 50
};

/*────────────────────── 2. Ensure log directory ───────────────────────*/
fs.mkdirSync(CONFIG.LOG_DIR, { recursive:true });
const LOG_FILE = path.join(CONFIG.LOG_DIR,'proxy_traffic.log');

/*────────────────── 3. Threat-pattern database (unchanged) ─────────────*/
const THREAT_PATTERNS = {
  CRITICAL : [
    { pattern:'sqlmap', type:'scanner' },
    { pattern:'nmap',   type:'scanner' },
    { pattern:/union\s+select/i,       type:'sql-injection' },
    { pattern:/<script>alert/i,        type:'xss' },
    { pattern:/\.\.\/\.\.\/etc\/passwd/i, type:'lfi' }
  ],
  HIGH : [
    { pattern:'burp', type:'scanner' },
    { pattern:'zap',  type:'scanner' }
  ],
  MEDIUM : [
    { pattern:'curl',          type:'cli-tool' },
    { pattern:'wget',          type:'cli-tool' },
    { pattern:/python-urllib/i,type:'scripted' }
  ],
  SUSPICIOUS : [
    { pattern:/[^\x20-\x7E]/,           type:'binary-data' },
    { pattern:/\.(exe|dll|bat|sh)(\?|$)/i, type:'executable' }
  ]
};

/*──────────────────────── 4. Threat analyser ──────────────────────────*/
function analyse(req){
  const ua  = req.headers['user-agent'] || '';
  const url = req.url || '';
  const res = { score:CONFIG.RISK_DEFAULT, threats:[], details:[] };

  for(const [severity, rules] of Object.entries(THREAT_PATTERNS)){
    for(const {pattern,type} of rules){
      const hit = typeof pattern==='string'
        ? ua.includes(pattern) || url.includes(pattern)
        : pattern.test(ua)     || pattern.test(url);

      if(hit){
        res.threats.push(type);
        res.details.push({ type, severity, pattern:String(pattern) });
        if(severity==='CRITICAL')      res.score = CONFIG.RISK_CRITICAL;
        else if(severity==='HIGH')     res.score = Math.max(res.score, CONFIG.RISK_HIGH);
        else if(severity==='MEDIUM')   res.score = Math.max(res.score, CONFIG.RISK_MEDIUM);
      }
    }
  }
  if(ua.length>256){ res.score=Math.max(res.score,30); res.threats.push('long-ua'); }
  return res;
}

/*────────────────────────── 5. Logger ────────────────────────────────*/
function log(entry){
  fs.appendFile(LOG_FILE, JSON.stringify(entry)+'\n', ()=>{});
  const clr = entry.score>=80 ? chalk.red
    : entry.score>=50 ? chalk.yellow
      : chalk.green;
  console.log(
    chalk.cyan(entry.ts),
    entry.method, entry.url,
    clr(`RISK:${entry.score}`),
    entry.threats.length ? chalk.red(entry.threats.join(',')) : ''
  );
}

/*────────────────────────── 6. HTTP server ───────────────────────────*/
const server = http.createServer((req,res)=>{
  const analysis = analyse(req);
  const entry = {
    ts      : new Date().toISOString(),
    method  : req.method,
    url     : req.url,
    ip      : req.headers['x-forwarded-for'] || req.socket.remoteAddress,
    ua      : req.headers['user-agent'] || 'none',
    score   : analysis.score,
    threats : analysis.threats
  };
  log(entry);

  if(analysis.score>=80){
    res.writeHead(401,{
      'Content-Type':'text/plain',
      'X-Threat-Blocked':analysis.threats.join(',')
    });
    return res.end('Unauthorized – threat detected\n');
  }
  res.writeHead(200,{
    'Content-Type':'text/plain',
    'X-Risk-Score':String(analysis.score)
  });
  res.end('Request logged\n');
});

/*────────────────────────── 7. Start-up ──────────────────────────────*/
server.listen(CONFIG.PORT, CONFIG.HOST, ()=>{
  console.log(
    chalk.green.bold(
      `🛡️  Scanner live  →  http://${CONFIG.HOST}:${CONFIG.PORT}`));
  console.log(chalk.yellow(
    `Try: curl http://${CONFIG.HOST}:${CONFIG.PORT}/test --user-agent "sqlmap"`));
});
