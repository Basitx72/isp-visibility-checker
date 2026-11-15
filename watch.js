// watch.js - reruns the audit every 30 minutes and alerts only on change.
//
// The first run prints and saves a baseline. Later runs are silent unless the
// sanitized checks or the score differ from the last run, in which case the
// new report is printed and saved (the old one moves to
// previous-sanitized-report.json). Stop with Control-C.

'use strict';

const { runAudit, fingerprint, parseDnsStatus } = require('./scanner.js');

const INTERVAL_MS = 30 * 60 * 1000;

let dnsStatus;
try {
  dnsStatus = parseDnsStatus();
} catch (error) {
  console.error(error.message);
  process.exit(1);
}

let lastFingerprint = null;
let running = false;

const stamp = () => new Date().toLocaleTimeString();

async function tick() {
  if (running) return;
  running = true;
  try {
    if (lastFingerprint === null) {
      console.log(`[${stamp()}] Baseline run`);
      const report = await runAudit({ dnsStatus, quiet: false, save: true });
      lastFingerprint = fingerprint(report);
      console.log(`\nWatching. Next check in 30 minutes. Press Control-C to stop.`);
      return;
    }

    const report = await runAudit({ dnsStatus, quiet: true, save: false });
    const current = fingerprint(report);
    if (current === lastFingerprint) return; // unchanged: stay quiet

    console.log(`\n[${stamp()}] ALERT: the audit result changed since the last check.`);
    const saved = await runAudit({ dnsStatus, quiet: false, save: true });
    lastFingerprint = fingerprint(saved);
  } catch {
    console.error(`[${stamp()}] Check skipped safely (no private gateway detected, for example a VPN is on).`);
  } finally {
    running = false;
  }
}

process.on('SIGINT', () => {
  console.log('\nWatcher stopped.');
  process.exit(0);
});

tick();
setInterval(tick, INTERVAL_MS);
