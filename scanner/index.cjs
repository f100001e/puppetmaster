#!/usr/bin/env node
/**
 * Threat-aware scanner / UI listener (:8888)
 */
'use strict';

/*───────────────────────── 0) Imports & .env ─────────────────────────*/
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const express = require('express');
const chalk = require('chalk');
const dotenv = require('dotenv');

dotenv.config({ path: path.resolve(__dirname, '../.env') });

/*───────────────────────── 1) Config ─────────────────────────────────*/
const HOST = process.env.SCANNER_HOST || 'localhost';
const PORT = Number(process.env.SCANNER_LISTEN_PORT || 8888);

const HTTPS_ON = String(process.env.SCANNER_HTTPS_ENABLED || process.env.HTTPS_ENABLED || 'false').toLowerCase() === 'true';
const STRICT_TLS = String(process.env.SCANNER_STRICT_TLS || 'true').toLowerCase() === 'true';

const KEY_PATH  = process.env.SCANNER_KEY_PATH  || path.resolve(__dirname, '../certs/private.key');
const CERT_PATH = process.env.SCANNER_CERT_PATH || path.resolve(__dirname, '../certs/certificate.crt');

const LOG_DIR = process.env.LOG_DIR || path.resolve(__dirname, '../gtag_logs');
fs.mkdirSync(LOG_DIR, { recursive: true });
const LOG_FILE = path.join(LOG_DIR, 'proxy_traffic.log');

const RISK_DEFAULT  = Number(process.env.RISK_DEFAULT || 10);
const RISK_CRITICAL = 100, RISK_HIGH = 75, RISK_MEDIUM = 50;

/*───────────────────────── 2) Threat DB ─────────────────────────────*/
const THREAT_PATTERNS = {
  CRITICAL: [
    { pattern: 'sqlmap', type: 'scanner' },
    { pattern: 'nmap', type: 'scanner' },
    { pattern: /union\s+select/i, type: 'sql-injection' },
    { pattern: /<script>alert/i, type: 'xss' },
    { pattern: /\.\.\/\.\.\/etc\/passwd/i, type: 'lfi' },
  ],
  HIGH: [
    { pattern: 'burp', type: 'scanner' },
    { pattern: 'zap', type: 'scanner' },
  ],
  MEDIUM: [
    { pattern: 'curl', type: 'cli-tool' },
    { pattern: 'wget', type: 'cli-tool' },
    { pattern: /python-urllib/i, type: 'scripted' },
  ],
  SUSPICIOUS: [
    { pattern: /[^\x20-\x7E]/, type: 'binary-data' },
    { pattern: /\.(exe|dll|bat|sh)(\?|$)/i, type: 'executable' },
  ],
};

/*───────────────────────── 3) Analyse + log ─────────────────────────*/
function analyse(req) {
  const ua = req.headers['user-agent'] || '';
  const url = req.url || '';
  const res = { score: RISK_DEFAULT, threats: [], details: [] };

  for (const [severity, rules] of Object.entries(THREAT_PATTERNS)) {
    for (const { pattern, type } of rules) {
      const hit = typeof pattern === 'string'
        ? ua.includes(pattern) || url.includes(pattern)
        : pattern.test(ua) || pattern.test(url);

      if (hit) {
        res.threats.push(type);
        res.details.push({ type, severity, pattern: String(pattern) });
        if (severity === 'CRITICAL') res.score = RISK_CRITICAL;
        else if (severity === 'HIGH') res.score = Math.max(res.score, RISK_HIGH);
        else if (severity === 'MEDIUM') res.score = Math.max(res.score, RISK_MEDIUM);
      }
    }
  }
  if (ua.length > 256) {
    res.score = Math.max(res.score, 30);
    res.threats.push('long-ua');
  }
  return res;
}

function logEntry(entry) {
  fs.appendFile(LOG_FILE, JSON.stringify(entry) + '\n', () => {});
  const clr = entry.score >= 80 ? chalk.red : entry.score >= 50 ? chalk.yellow : chalk.green;
  console.log(
    chalk.cyan(entry.ts),
    entry.method,
    entry.url,
    clr(`RISK:${entry.score}`),
    entry.threats.length ? chalk.red(entry.threats.join(',')) : ''
  );
}

/*───────────────────────── 4) Express app ───────────────────────────*/
const app = express();

app.get('/test', (_req, res) => res.type('text/plain').send('scanner ok\n'));

// Add this route to scanner/index.cjs
app.post('/analyze', (req, res) => {
  try {
    const { ua, url, cert_behavior, cert_risk_bonus, analysis_timestamp } = req.body;

    // Perform threat analysis (your existing analyze function)
    const analysis = analyse(req);

    // Add certificate behavior to risk calculation
    const enhancedScore = analysis.score + (cert_risk_bonus || 0);

    // Create enhanced entry for backend
    const entry = {
      ts: analysis_timestamp || new Date().toISOString(),
      method: 'PROXY',
      url: url,
      ip: 'mitmproxy',
      ua: ua,
      score: enhancedScore,
      threats: analysis.threats,
      cert_behavior: cert_behavior
    };

    // Forward analyzed data to backend
    const backendUrl = process.env.BACKEND_URL || 'http://localhost:3000';
    fetch(`${backendUrl}/log_ua`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(entry)
    }).catch(err => console.error('Backend forward failed:', err));

    res.json({ status: 'analyzed', score: enhancedScore });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Place this LAST:
app.use((req, res) => {
  const analysis = analyse(req);
  const entry = {
    ts: new Date().toISOString(),
    method: req.method,
    url: req.url,
    ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress,
    ua: req.headers['user-agent'] || 'none',
    score: analysis.score,
    threats: analysis.threats,
  };
  logEntry(entry); // or rename to log(entry) if that’s your function name

  if (analysis.score >= 80) {
    return res
      .status(401)
      .set('X-Threat-Blocked', analysis.threats.join(','))
      .type('text/plain')
      .send('Unauthorized – threat detected\n');
  }

  res
    .status(200)
    .set('X-Risk-Score', String(analysis.score))
    .type('text/plain')
    .send('Request logged\n');
});

/*───────────────────────── 5) HTTP/HTTPS server ─────────────────────*/
let server;
if (HTTPS_ON) {
  const hasKey = fs.existsSync(KEY_PATH);
  const hasCert = fs.existsSync(CERT_PATH);

  if (!hasKey || !hasCert) {
    const msg = `TLS certs missing: key=${hasKey} cert=${hasCert} (KEY_PATH=${KEY_PATH}, CERT_PATH=${CERT_PATH})`;
    if (STRICT_TLS) {
      console.error(chalk.red(`❌ ${msg}`));
      process.exit(1);
    } else {
      console.warn(chalk.yellow(`⚠️  ${msg} — falling back to HTTP`));
      server = http.createServer(app);
    }
  } else {
    try {
      const opts = {
        key: fs.readFileSync(KEY_PATH),
        cert: fs.readFileSync(CERT_PATH),
        minVersion: 'TLSv1.2',
        // Per your MITM, don’t be picky:
        requestCert: false,
        honorCipherOrder: true,
      };
      server = https.createServer(opts, app);
      console.log(chalk.green('🔒 Scanner TLS enabled'));
    } catch (e) {
      if (STRICT_TLS) {
        console.error(chalk.red(`❌ Failed to load TLS certs: ${e.message}`));
        process.exit(1);
      } else {
        console.warn(chalk.yellow(`⚠️  TLS load failed (${e.message}) — falling back to HTTP`));
        server = http.createServer(app);
      }
    }
  }
}
if (!server) {
  server = http.createServer(app);
  console.log(chalk.yellow('🌐 Scanner running in HTTP mode'));
}

/*───────────────────────── 6) Listen ────────────────────────────────*/
server.listen(PORT, HOST, () => {
  const scheme = server instanceof https.Server ? 'https' : 'http';
  console.log(chalk.cyan(`🛡️  Scanner live  →  ${scheme}://${HOST}:${PORT}`));
  console.log(chalk.gray(`Try: curl -vk ${scheme}://${HOST}:${PORT}/test`));
});
