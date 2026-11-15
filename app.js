// app.js - opens the ISP Visibility Checker window and runs the audit on request.
//
// Start:  node app.js        Stop:  Control-C
//
// Safety boundary (see CLAUDE.md):
//   * The server listens on this computer only (loopback).
//   * The window can ask for one thing: the same audit scanner.js runs.
//     No request can supply a target, host, address, or port to check.
//   * This file saves nothing. scanner.js still writes only
//     sanitized-report.json and previous-sanitized-report.json.
//   * Only fixed, safe messages are printed or sent. Raw errors are dropped.

'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');

const PAGE_NAME = 'ISP Visibility Checker.html';
const PAGE_FILE = path.join(__dirname, PAGE_NAME);
const REPORT_FILE = path.join(__dirname, 'sanitized-report.json');
const PREVIOUS_FILE = path.join(__dirname, 'previous-sanitized-report.json');
const LOOPBACK = '127.0.0.1';
const FIRST_PORT = 4747;
const LAST_PORT = 4757;
const MAX_BODY_BYTES = 1024;
const SCAN_TIMEOUT_MS = 45000;

// The same fixed messages scanner.js prints. Nothing else from an error is shown.
const SAFETY_STOP = 'Safety stop: the detected default gateway is not an RFC 1918 IPv4 address.';
const BAD_DNS = '--dns must be encrypted, plaintext, or unknown';
const STOPPED = 'Audit stopped safely. No unsanitized error details were saved.';

let scanner;
try {
  scanner = require('./scanner.js');
} catch {
  console.error('Could not load scanner.js. Run "npm install" in this folder, then start the app again.');
  process.exit(1);
}
const { runAudit, parseDnsStatus } = scanner;

// A fresh secret for every start. The window gets it inside the page, and every
// request for data must send it back, so no other website can use this server.
const token = crypto.randomBytes(24).toString('hex');
let port = null;
let scanning = false;

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

function send(res, status, body, type) {
  const data = Buffer.from(body);
  res.writeHead(status, {
    'Content-Type': type,
    'Content-Length': data.length,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy': "frame-ancestors 'none'; base-uri 'none'; form-action 'none'; object-src 'none'",
  });
  res.end(data);
}

const sendJson = (res, status, value) => send(res, status, JSON.stringify(value), 'application/json; charset=utf-8');
const sendText = (res, status, text) => send(res, status, text, 'text/plain; charset=utf-8');

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Who may ask
// ---------------------------------------------------------------------------

// Only this computer's own browser, on this server's own address.
function allowedHost(req) {
  const host = req.headers.host;
  return host === `localhost:${port}` || host === `${LOOPBACK}:${port}`;
}

function sameOrigin(req) {
  const origin = req.headers.origin;
  if (origin === undefined) return true;
  return origin === `http://localhost:${port}` || origin === `http://${LOOPBACK}:${port}`;
}

function hasToken(req) {
  const given = Buffer.from(String(req.headers['x-isp-token'] || ''));
  const expected = Buffer.from(token);
  return given.length === expected.length && crypto.timingSafeEqual(given, expected);
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

function sendPage(res) {
  let html;
  try {
    html = fs.readFileSync(PAGE_FILE, 'utf8');
  } catch {
    sendText(res, 500, `"${PAGE_NAME}" is missing from this folder.`);
    return;
  }
  const tag = `<meta name="isp-app-token" content="${token}">\n`;
  const at = html.indexOf('</head>');
  send(res, 200, at === -1 ? tag + html : html.slice(0, at) + tag + html.slice(at), 'text/html; charset=utf-8');
}

function sendReports(res) {
  sendJson(res, 200, { ok: true, current: readJson(REPORT_FILE), previous: readJson(PREVIOUS_FILE) });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    if (Number(req.headers['content-length']) > MAX_BODY_BYTES) {
      reject(new Error('too large'));
      return;
    }
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error('too large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', () => reject(new Error('unreadable')));
  });
}

function withTimeout(promise, ms) {
  let timer;
  const limit = new Promise((resolve, reject) => {
    timer = setTimeout(() => reject(new Error('timeout')), ms);
  });
  return Promise.race([promise, limit]).finally(() => clearTimeout(timer));
}

// The only input is the DNS statement, checked by scanner.js itself. It is the
// same choice as the --dns flag. There is no target to pass.
async function scan(req, res) {
  let dnsStatus;
  try {
    const body = JSON.parse((await readBody(req)) || '{}');
    const stated = body && typeof body === 'object' && 'dns' in body ? body.dns : 'unknown';
    dnsStatus = parseDnsStatus(['--dns', stated]);
  } catch (error) {
    if (error && error.message === 'too large') {
      res.setHeader('Connection', 'close');
      sendJson(res, 413, { ok: false, code: 'too-large', message: 'Request too large.' });
    } else {
      sendJson(res, 400, { ok: false, code: 'bad-dns', message: BAD_DNS });
    }
    return;
  }

  if (scanning) {
    sendJson(res, 409, { ok: false, code: 'busy', message: 'A scan is already running.' });
    return;
  }

  scanning = true;
  try {
    const report = await withTimeout(runAudit({ dnsStatus, quiet: true, save: true }), SCAN_TIMEOUT_MS);
    sendJson(res, 200, { ok: true, current: report, previous: readJson(PREVIOUS_FILE) });
  } catch (error) {
    if (error && error.message === SAFETY_STOP) {
      sendJson(res, 200, { ok: false, code: 'no-private-gateway', message: SAFETY_STOP });
    } else if (error && error.message === 'timeout') {
      sendJson(res, 200, { ok: false, code: 'timeout', message: 'The scan took too long and the app stopped waiting for it.' });
    } else {
      sendJson(res, 200, { ok: false, code: 'stopped', message: STOPPED });
    }
  } finally {
    scanning = false;
  }
}

async function handle(req, res) {
  if (!allowedHost(req) || !sameOrigin(req)) {
    sendText(res, 403, 'Forbidden');
    return;
  }

  const route = String(req.url || '').split('?')[0];

  if (route === '/') {
    if (req.method !== 'GET') sendText(res, 405, 'Method not allowed');
    else sendPage(res);
    return;
  }

  if (route === '/api/report') {
    if (req.method !== 'GET') sendText(res, 405, 'Method not allowed');
    else if (!hasToken(req)) sendText(res, 403, 'Forbidden');
    else sendReports(res);
    return;
  }

  if (route === '/api/scan') {
    if (req.method !== 'POST') sendText(res, 405, 'Method not allowed');
    else if (!hasToken(req)) sendText(res, 403, 'Forbidden');
    else await scan(req, res);
    return;
  }

  sendText(res, 404, 'Not found');
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

function listen(candidate) {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      handle(req, res).catch(() => {
        if (!res.headersSent) sendText(res, 500, STOPPED);
        else res.end();
      });
    });
    server.once('error', reject);
    server.listen(candidate, LOOPBACK, () => {
      server.removeListener('error', reject);
      port = server.address().port;
      resolve(server);
    });
  });
}

function openWindow(url) {
  if (process.platform !== 'darwin' || process.argv.includes('--no-open')) return;
  const quiet = { stdio: 'ignore' };
  const chrome = spawn('open', ['-a', 'Google Chrome', url], quiet);
  chrome.once('error', () => {});
  chrome.once('exit', (code) => {
    if (code !== 0) spawn('open', [url], quiet).once('error', () => {});
  });
}

async function start() {
  let server = null;
  for (let candidate = FIRST_PORT; candidate <= LAST_PORT && !server; candidate += 1) {
    try {
      server = await listen(candidate);
    } catch (error) {
      if (!error || error.code !== 'EADDRINUSE') throw error;
    }
  }
  if (!server) server = await listen(0);

  const url = `http://localhost:${port}`;
  console.log('ISP Visibility Checker is running.');
  console.log(`Open this in your browser if it does not open by itself: ${url}`);
  console.log('Keep this Terminal window open while you use the app. Press Control-C to stop.');
  openWindow(url);
}

process.on('SIGINT', () => {
  console.log('\nApp stopped.');
  process.exit(0);
});

// A stray error from a network library must never print raw details.
process.on('uncaughtException', () => console.error(STOPPED));
process.on('unhandledRejection', () => console.error(STOPPED));

start().catch(() => {
  console.error('The app could not start. Close other copies of it and try again.');
  process.exit(1);
});
