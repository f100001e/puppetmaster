#!/usr/bin/env node
/**
 * scanner.cjs – MITM Listener on 192.168.0.215:8888
 */
'use strict';

const path = require('path');
const fs = require('fs');
const http = require('http');
const https = require('https');
const chalk = require('chalk');
const dotenv = require('dotenv');
dotenv.config({ path: path.resolve(__dirname, '../.env') });

// Configuration
const PROXY_HOST = process.env.PROXY_HOST || '192.168.0.215';
const PROXY_PORT = process.env.PROXY_PORT || 8081;
const MITM_PORT = process.env.MITM_PORT || 8888;
const SCANNER_HOST = process.env.SCANNER_HOST || '127.0.0.1';
const SCANNER_PORT = process.env.SCANNER_PORT || 8081;

const LOG_DIR = path.join(process.env.HOME || process.env.USERPROFILE,
  'WebstormProjects', 'Puppetmaster', 'gtag_logs');
const LOG_FILE = 'proxy_traffic.log';
const LOG_PATH = path.join(LOG_DIR, LOG_FILE);
const LISTEN_PORT = MITM_PORT;

// Validate critical env vars
if (!PROXY_HOST || !PROXY_PORT || !MITM_PORT || !LOG_PATH) {
  console.error(chalk.red('❌ Missing critical environment configuration'));
  process.exit(1);
}

// Threat Pattern Database
const THREAT_PATTERNS = {
  CRITICAL: [
    'sqlmap', 'nmap', 'metasploit', 'hydra',
    'nikto', 'w3af', 'burp', 'zap', 'havij',
    /\x[0-9a-f]{2}/i,
    /%[0-9a-f]{2}/i,
    /\.\.\/\.\.\/etc\/passwd/i,
    /union select/i,
    /<script>alert/i
  ],
  HIGH: [
    'scanbot', 'dirbuster', 'netsparker',
    'acunetix', 'nessus', 'openvas'
  ],
  MEDIUM: [
    'headless', 'phantom', 'selenium',
    'puppeteer', 'scrapy', 'python-urllib',
    'curl', 'wget', 'java/[0-9]\\.[0-6]'
  ]
};

// Pacific Time Formatter
function getPacificTime() {
  return new Date().toLocaleString('en-US', {
    timeZone: 'America/Los_Angeles',
    hour12: false,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  }) + ' PST';
}

class MitmListener {
  constructor() {
    // Ensure log directory exists
    if (!fs.existsSync(LOG_DIR)) {
      fs.mkdirSync(LOG_DIR, { recursive: true });
    }

    this.MAX_LOG_SIZE = 10 * 1024 * 1024; // 10MB
    this.checkLogRotation();

    // Main traffic log
    this.logStream = fs.createWriteStream(LOG_PATH, { flags: 'a', encoding: 'utf8' });
    this.logStream.write(`\n===== Session started at ${getPacificTime()} =====\n`);

    // Event logging system
    this.eventLogPath = path.join(LOG_DIR, 'proxy_events.log');
    this.eventStream = fs.createWriteStream(this.eventLogPath, {
      flags: 'a',
      encoding: 'utf8'
    });

    this._logEvent({
      type: 'system',
      event: 'init',
      message: `Listener started on ${PROXY_HOST}:${LISTEN_PORT}`,
      pid: process.pid
    });

    // Verify log directory permissions
    try {
      fs.accessSync(LOG_DIR, fs.constants.W_OK | fs.constants.R_OK);
    } catch (err) {
      console.error(chalk.red(`❌ Log directory inaccessible: ${LOG_DIR}`));
      console.error(chalk.red(`Error: ${err.message}`));
      process.exit(1);
    }

    // Initialize server
    let server;
    if (process.env.HTTPS_ENABLED === 'true') {
      try {
        const options = {
          key: fs.readFileSync(path.resolve(__dirname, '../certs/private.key')),
          cert: fs.readFileSync(path.resolve(__dirname, '../certs/certificate.crt'))
        };
        server = https.createServer(options, (req, res) => {
          this._handleRequest(req, res);
        });
        console.log(chalk.green.bold('🔒 HTTPS enabled'));
      } catch (err) {
        console.error(chalk.red('❌ HTTPS setup failed:'), err.message);
        console.log(chalk.yellow('⚠️ Falling back to HTTP'));
        server = http.createServer((req, res) => {
          this._handleRequest(req, res);
        });
      }
    } else {
      server = http.createServer((req, res) => {
        this._handleRequest(req, res);
      });
    }

    this.server = server;
    console.log(chalk.green.bold(`👇 Listening on ${PROXY_HOST}:${LISTEN_PORT}`));
  }

  _analyzeThreat(ua = '') {
    if (!ua) return parseInt(process.env.RISK_DEFAULT) || 10;

    const uaLower = ua.toLowerCase();
    let risk = parseInt(process.env.RISK_DEFAULT) || 10;

    // Critical patterns (immediate max score)
    if (THREAT_PATTERNS.CRITICAL.some(p =>
      typeof p === 'string' ? uaLower.includes(p) : p.test(uaLower)
    )) {
      return 100;
    }

    // High risk patterns
    THREAT_PATTERNS.HIGH.forEach(p => {
      if (uaLower.includes(p)) {
        risk = Math.max(risk, parseInt(process.env.RISK_BAD_REGEX) || 75);
      }
    });

    // Medium risk patterns
    THREAT_PATTERNS.MEDIUM.forEach(p => {
      if (uaLower.includes(p)) {
        risk = Math.max(risk, parseInt(process.env.RISK_SUSPICIOUS_REGEX) || 50);
      }
    });

    // Additional heuristics
    if (ua.length > 256) risk = Math.max(risk, 30);
    if (/[^\x20-\x7E]/.test(ua)) risk = Math.max(risk, 40);

    return Math.min(risk, 100);
  }

  _handleRequest(req, res) {
    try {
      const entry = this._logRequest(req);
      const riskScore = entry ? entry.riskScore : 0;

      res.writeHead(200, {
        'Content-Type': 'text/plain',
        'Risk-Score': riskScore.toString()
      });
      res.end(`Request logged (Risk: ${riskScore})\n`);
    } catch (err) {
      console.error(chalk.red('⚠️ Request handling error:'), err);
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('Internal Server Error\n');
      }
    }
  }

  checkLogRotation() {
    try {
      [LOG_PATH, this.eventLogPath].forEach(logPath => {
        if (fs.existsSync(logPath) && fs.statSync(logPath).size > this.MAX_LOG_SIZE) {
          const archivePath = `${logPath}.${Date.now()}`;
          fs.renameSync(logPath, archivePath);
          this._logEvent({
            type: 'system',
            event: 'log_rotate',
            file: path.basename(logPath),
            archivedAs: path.basename(archivePath)
          });
        }
      });
    } catch (err) {
      this._logEvent({
        type: 'error',
        event: 'log_rotation_failed',
        error: err.message
      });
    }
  }

  _logEvent(eventData) {
    const entry = {
      timestamp: getPacificTime(),
      ...eventData
    };

    try {
      this.eventStream.write(JSON.stringify(entry) + '\n');

      if (process.env.DEBUG === 'true') {
        console.log(chalk.gray('[EVENT]'), entry);
      }
    } catch (err) {
      console.error(chalk.red('⚠️ Event log failed:'), err);
      this.logStream.write(`EVENT LOG FAILURE: ${err.message}\n`);
    }
  }

  _logRequest(req) {
    const entry = {
      timestamp: getPacificTime(),
      method: req.method,
      url: req.url,
      ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress,
      ua: req.headers['user-agent'] || 'none',
      isHttp: !req.connection.encrypted,
      riskScore: this._analyzeThreat(req.headers['user-agent'] || '')
    };

    this.logStream.write(JSON.stringify(entry) + '\n');
    this._logEvent({
      type: 'request',
      ...entry
    });

    return entry;
  }

  start() {
    this.server.on('request', (req, res) => {
      this._handleRequest(req, res);
    });

    this.server.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        console.error(chalk.red(`🚨 Port ${LISTEN_PORT} already in use!`));
        console.error(chalk.yellow('Try running:'));
        console.error(chalk.yellow(`lsof -i :${LISTEN_PORT} && kill -9 <PID>`));
      } else {
        console.error(chalk.red('🚨 Server error:'), err);
      }
      process.exit(1);
    });

    this.server.listen(LISTEN_PORT, PROXY_HOST, () => {
      console.log(chalk.green.bold(`📝 Logging to: ${LOG_PATH}`));
      console.log(chalk.yellow('Test with:'));
      console.log(chalk.yellow(`  curl http://${PROXY_HOST}:${LISTEN_PORT}/test --user-agent "TestAgent"`));
    });
  }

  shutdown() {
    this._logEvent({
      type: 'system',
      event: 'shutdown',
      message: 'Graceful shutdown initiated'
    });

    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => {
          [this.logStream, this.eventStream].forEach(stream => {
            if (stream) stream.end('\n===== Session ended =====\n');
          });
          resolve();
        });
      } else {
        resolve();
      }
    });
  }
}

let listener;

async function gracefulShutdown() {
  console.log(chalk.yellow('\n🛑 Stopping listener...'));
  if (listener) await listener.shutdown();
  process.exit();
}

process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);

try {
  listener = new MitmListener();
  listener.start();
} catch (err) {
  console.error(chalk.red('🔥 Fatal error:'), err);
  process.exit(1);
}