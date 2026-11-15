// scanner.js - defensive, read-only audit of the home gateway.
//
// Safety boundary (see CLAUDE.md):
//   * The only target is the private default gateway detected by the OS.
//   * No option can supply a target or host.
//   * TCP checks connect and immediately close. No data is sent or read.
//   * UPnP uses getGateway() and getMappings() only.
//   * Nothing identifying is printed or saved; WAN exposure is not tested.

'use strict';

const net = require('node:net');
const fs = require('node:fs');
const path = require('node:path');
const si = require('systeminformation');
const { Client } = require('@runonflux/nat-upnp');

const REPORT_NAME = 'sanitized-report.json';
const REPORT_FILE = path.join(__dirname, REPORT_NAME);
const PREVIOUS_FILE = path.join(__dirname, 'previous-sanitized-report.json');
const TARGET_LABEL = '<private-gateway>';
const DNS_VALUES = ['encrypted', 'plaintext', 'unknown'];
const DISCLAIMER = 'Educational rubric, not a certification or proof of WAN exposure.';

const PORTS = [
  { port: 22, name: 'ssh', weight: 6, severity: 'MEDIUM' },
  { port: 23, name: 'telnet', weight: 10, severity: 'HIGH' },
  { port: 80, name: 'http', weight: 4, severity: 'LOW' },
  { port: 7547, name: 'cwmp', weight: 10, severity: 'MEDIUM' },
];

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

function parseDnsStatus(args = process.argv.slice(2)) {
  let value = 'unknown';
  for (let i = 0; i < args.length; i += 1) {
    if (args[i] === '--dns') {
      value = args[i + 1];
      i += 1;
    } else if (typeof args[i] === 'string' && args[i].startsWith('--dns=')) {
      value = args[i].slice('--dns='.length);
    }
  }
  if (!DNS_VALUES.includes(value)) {
    throw new Error('--dns must be encrypted, plaintext, or unknown');
  }
  return value;
}

// ---------------------------------------------------------------------------
// Safety boundary and redaction
// ---------------------------------------------------------------------------

function parseIPv4(address) {
  if (typeof address !== 'string') return null;
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(address.trim());
  if (!match) return null;
  const octets = match.slice(1).map(Number);
  return octets.every((n) => n >= 0 && n <= 255) ? octets : null;
}

function isPrivateGateway(address) {
  const octets = parseIPv4(address);
  if (!octets) return false;
  const [a, b] = octets;
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  return false;
}

function redactIPv4(address) {
  const octets = parseIPv4(address);
  if (!octets) return '<unknown-ip>';
  return `${octets[0]}.${octets[1]}.${octets[2]}.x`;
}

const IPV4_PATTERN = /\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}\b/g;
const MAC_PATTERN = /\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b/g;

function redactString(text) {
  return text
    .replace(MAC_PATTERN, '<redacted-mac>')
    .replace(IPV4_PATTERN, (whole, a, b, c) =>
      isPrivateGateway(whole) ? `${a}.${b}.${c}.x` : '<redacted-ip>');
}

// Single redaction boundary: every value in the report passes through here
// before it is scored, printed, or saved.
function redactValue(value) {
  if (typeof value === 'string') return redactString(value);
  if (Array.isArray(value)) return value.map(redactValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, inner]) => [key, redactValue(inner)]),
    );
  }
  return value;
}

// ---------------------------------------------------------------------------
// TCP: connect-only checks
// ---------------------------------------------------------------------------

function probePort(host, port) {
  return new Promise((resolve) => {
    let settled = false;
    const socket = net.createConnection({ host, port, timeout: 800 });
    const finish = (reachable) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ port, reachable });
    };
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
  });
}

function collectPorts(gateway) {
  return Promise.all(PORTS.map(({ port }) => probePort(gateway, port)));
}

// ---------------------------------------------------------------------------
// Wi-Fi evidence (identifiers are used for counting only, never returned)
// ---------------------------------------------------------------------------

function normalizeSecurity(value) {
  if (Array.isArray(value)) {
    return value.map((item) => String(item).trim()).filter(Boolean).join('/');
  }
  if (typeof value === 'string') return value.trim();
  return '';
}

function classifySecurity(value) {
  const text = normalizeSecurity(value).toUpperCase();
  if (!text) return 'unknown';
  const hasWpa3 = text.includes('WPA3');
  const hasWpa2 = text.includes('WPA2');
  const hasWpa1 = /WPA(?![23])/.test(text);
  if (/\bWEP\b|TKIP|\bOPEN\b|\bNONE\b/.test(text)) return 'weak';
  if (hasWpa1 && hasWpa2 && !hasWpa3) return 'weak'; // WPA/WPA2 mixed mode
  if (hasWpa1 && !hasWpa2 && !hasWpa3) return 'weak'; // WPA only
  if (hasWpa3 || hasWpa2) return 'strong';
  return 'review';
}

async function collectWifi() {
  const unknown = (reason) => ({
    state: 'unknown',
    reason,
    security: 'unknown',
    securityState: 'unknown',
    channel: null,
    sameChannelCount: null,
  });

  let connections;
  let networks;
  try {
    [connections, networks] = await Promise.all([si.wifiConnections(), si.wifiNetworks()]);
  } catch {
    return unknown('The operating system did not return Wi-Fi details.');
  }

  const current = Array.isArray(connections) ? connections[0] : null;
  if (!current) {
    return unknown('No active Wi-Fi connection was reported (wired connection, or the operating system withheld it).');
  }

  const security = normalizeSecurity(current.security);
  const securityState = classifySecurity(current.security);
  const channelNumber = Number(current.channel);
  const channel = Number.isInteger(channelNumber) && channelNumber > 0 ? channelNumber : null;

  let sameChannelCount = null;
  if (channel !== null && Array.isArray(networks) && networks.length > 0) {
    const currentBssid = current.bssid ? String(current.bssid).toLowerCase() : '';
    const currentSsid = current.ssid ? String(current.ssid) : '';
    sameChannelCount = networks.filter((network) => {
      if (Number(network.channel) !== channel) return false;
      if (currentBssid) return String(network.bssid || '').toLowerCase() !== currentBssid;
      if (currentSsid) return String(network.ssid || '') !== currentSsid;
      return true;
    }).length;
  }

  const missing = [];
  if (securityState === 'unknown') missing.push('security mode');
  if (channel === null) missing.push('channel');
  if (sameChannelCount === null) missing.push('nearby networks');

  let state = 'known';
  let reason = 'Security mode, channel, and nearby networks were reported.';
  if (missing.length === 3) {
    state = 'unknown';
    reason = 'The operating system withheld Wi-Fi security, channel, and nearby networks.';
  } else if (missing.length > 0) {
    state = 'partial';
    reason = `The operating system withheld: ${missing.join(', ')}.`;
  }

  return {
    state,
    reason,
    security: security || 'unknown',
    securityState,
    channel,
    sameChannelCount,
  };
}

// ---------------------------------------------------------------------------
// UPnP evidence (read-only: getGateway and getMappings only)
// ---------------------------------------------------------------------------

function sanitizeMapping(mapping, index) {
  const remote = mapping?.public?.host;
  let remoteHost = '<any-remote-host>';
  if (remote) {
    remoteHost = isPrivateGateway(remote) ? redactIPv4(remote) : '<remote-host>';
  }
  return {
    public: { remoteHost, port: Number(mapping?.public?.port) || null },
    private: { host: redactIPv4(mapping?.private?.host), port: Number(mapping?.private?.port) || null },
    protocol: String(mapping?.protocol || 'unknown').toLowerCase(),
    enabled: Boolean(mapping?.enabled),
    description: `<mapping-${index + 1}>`,
    ttl: Number(mapping?.ttl) || 0,
    local: mapping?.local ?? null,
  };
}

async function collectUpnp(gateway) {
  const client = new Client({ cacheGateway: true, timeout: 5000 });
  try {
    let info;
    try {
      info = await client.getGateway({ signal: AbortSignal.timeout(7000) });
    } catch {
      return {
        state: 'unknown',
        mappingCount: null,
        mappings: [],
        reason: 'No UPnP gateway answered discovery. UPnP may be off, or discovery was blocked.',
      };
    }

    let hostname = '';
    try {
      hostname = new URL(info.gateway.description).hostname;
    } catch {
      hostname = '';
    }
    if (hostname !== gateway) {
      return {
        state: 'refused',
        mappingCount: null,
        mappings: [],
        reason: 'A UPnP device answered, but it is not the default gateway, so it was not queried.',
      };
    }

    try {
      const mappings = await client.getMappings({ signal: AbortSignal.timeout(15000) });
      return {
        state: 'detected',
        mappingCount: mappings.length,
        mappings: mappings.map(sanitizeMapping),
        reason: 'The gateway answered UPnP and returned its port-mapping table.',
      };
    } catch {
      return {
        state: 'unknown',
        mappingCount: null,
        mappings: [],
        reason: 'The gateway answered UPnP discovery but did not return its mapping table.',
      };
    }
  } finally {
    client.close();
  }
}

// ---------------------------------------------------------------------------
// Scoring and findings
// ---------------------------------------------------------------------------

function scoreChecks(checks) {
  let earned = 0;
  let known = 0;

  for (const { port, weight } of PORTS) {
    const result = checks.ports.find((entry) => entry.port === port);
    if (!result || typeof result.reachable !== 'boolean') continue;
    known += weight;
    if (!result.reachable) earned += weight;
  }

  if (checks.upnp.state === 'detected') {
    known += 20;
    if (checks.upnp.mappingCount === 0) earned += 10;
  }

  if (checks.wifi.securityState !== 'unknown') {
    known += 20;
    if (checks.wifi.securityState === 'strong') earned += 20;
  }

  if (Number.isInteger(checks.wifi.sameChannelCount)) {
    known += 10;
    if (checks.wifi.sameChannelCount === 0) earned += 10;
    else if (checks.wifi.sameChannelCount <= 2) earned += 5;
  }

  if (checks.dns.state !== 'unknown') {
    known += 20;
    if (checks.dns.state === 'encrypted') earned += 20;
  }

  return {
    provisional: known > 0 ? Math.round((earned / known) * 100) : null,
    coveragePercent: known,
    earnedWeight: earned,
    knownWeight: known,
    totalWeight: 100,
    disclaimer: DISCLAIMER,
  };
}

function buildFindings(checks) {
  const findings = [];
  const add = (id, severity, message, action) => findings.push({ id, severity, message, action });

  add('target', 'INFO',
    'Only the private default gateway reported by this computer was checked. WAN exposure was not tested.',
    'No action needed.');

  const portActions = {
    22: 'If you do not use SSH on the router, disable SSH in its admin settings.',
    23: 'Disable Telnet in the router admin settings.',
    80: 'Sign in to the router admin page only from your own network, and use HTTPS if the router offers it.',
    7547: 'If the router allows it, disable TR-069/CWMP remote management, or ask your provider about it.',
  };
  for (const { port, name, severity } of PORTS) {
    const result = checks.ports.find((entry) => entry.port === port);
    if (result?.reachable) {
      add(`tcp-${port}`, severity,
        `TCP ${port} (${name}) accepts connections from inside your network. This does not show internet exposure.`,
        portActions[port]);
    } else {
      add(`tcp-${port}`, 'INFO',
        `TCP ${port} (${name}) did not accept a connection from inside your network.`,
        'No action needed.');
    }
  }

  const { upnp, wifi, dns } = checks;
  if (upnp.state === 'detected' && upnp.mappingCount > 0) {
    add('upnp', 'MEDIUM',
      `UPnP is on and the gateway lists ${upnp.mappingCount} port mapping(s) created by devices on your network.`,
      'Review the UPnP mappings in the router admin page, and disable UPnP if nothing you use needs it.');
  } else if (upnp.state === 'detected') {
    add('upnp', 'LOW',
      'UPnP is on. No port mappings are listed right now, but any device on your network can create one.',
      'Disable UPnP in the router admin page if nothing you use needs it.');
  } else if (upnp.state === 'refused') {
    add('upnp', 'REVIEW',
      'A UPnP device answered that is not your default gateway, so it was not queried.',
      'Check which device on your network is answering UPnP discovery.');
  } else {
    add('upnp', 'REVIEW',
      'UPnP status is unknown: no gateway answered discovery.',
      'Check the UPnP setting in the router admin page.');
  }

  if (wifi.securityState === 'weak') {
    add('wifi-security', 'HIGH',
      `Wi-Fi security is reported as ${wifi.security}, which is weak.`,
      'Set Wi-Fi security to WPA3 Personal, or WPA2/WPA3 Transitional if older devices need it.');
  } else if (wifi.securityState === 'strong') {
    add('wifi-security', 'INFO', `Wi-Fi security is reported as ${wifi.security}.`, 'No action needed.');
  } else if (wifi.securityState === 'review') {
    add('wifi-security', 'REVIEW',
      `Wi-Fi security is reported as ${wifi.security}, which this tool does not recognise.`,
      'Check the Wi-Fi security mode in the router admin page.');
  } else {
    add('wifi-security', 'REVIEW',
      'Wi-Fi security mode is unknown: the operating system did not report it.',
      'Check the Wi-Fi security mode in the router admin page (aim for WPA2 or WPA3).');
  }

  if (!Number.isInteger(wifi.sameChannelCount)) {
    add('wifi-channel', 'REVIEW',
      'Channel congestion is unknown: the operating system did not report nearby networks.',
      'Check the Wi-Fi channel setting in the router admin page.');
  } else if (wifi.sameChannelCount >= 3) {
    add('wifi-channel', 'LOW',
      `${wifi.sameChannelCount} other networks share your Wi-Fi channel.`,
      'Set the Wi-Fi channel to Auto in the router admin page.');
  } else if (wifi.sameChannelCount > 0) {
    add('wifi-channel', 'INFO',
      `${wifi.sameChannelCount} other network(s) share your Wi-Fi channel.`,
      'No action needed.');
  } else {
    add('wifi-channel', 'INFO', 'No other networks were seen on your Wi-Fi channel.', 'No action needed.');
  }

  if (dns.state === 'plaintext') {
    add('dns', 'MEDIUM',
      'DNS lookups are reported as plaintext, so your internet provider can see the site names you look up.',
      'Enable DNS over HTTPS or DNS over TLS in your browser, operating system, or router.');
  } else if (dns.state === 'encrypted') {
    add('dns', 'INFO', 'DNS lookups are reported as encrypted.', 'No action needed.');
  } else {
    add('dns', 'REVIEW',
      'DNS privacy is unknown: no evidence was supplied.',
      'Check your browser or operating system DNS settings, then rerun with --dns encrypted or --dns plaintext.');
  }

  add('privacy', 'INFO',
    'This report contains no network names, hardware addresses, device names, or complete private addresses.',
    'No action needed.');

  return findings;
}

function selectTopFixes(findings) {
  const rank = { HIGH: 4, MEDIUM: 3, LOW: 2, REVIEW: 1, INFO: 0 };
  const sorted = [...findings].sort((a, b) => rank[b.severity] - rank[a.severity]);
  const fixes = [];
  for (const finding of sorted) {
    if (finding.severity === 'INFO') continue;
    if (fixes.includes(finding.action)) continue;
    fixes.push(finding.action);
    if (fixes.length === 3) break;
  }
  return fixes;
}

// ---------------------------------------------------------------------------
// Persistence and output
// ---------------------------------------------------------------------------

function readJson(path) {
  try {
    return JSON.parse(fs.readFileSync(path, 'utf8'));
  } catch {
    return null;
  }
}

function saveSanitizedReport(report) {
  const previous = readJson(REPORT_FILE);
  if (previous) {
    fs.renameSync(REPORT_FILE, PREVIOUS_FILE);
    const previousScore = previous?.score?.provisional;
    const currentScore = report.score.provisional;
    if (typeof previousScore === 'number' && typeof currentScore === 'number') {
      report.comparison = {
        previousScore,
        currentScore,
        delta: currentScore - previousScore,
      };
    }
  }
  fs.writeFileSync(REPORT_FILE, `${JSON.stringify(report, null, 2)}\n`);
  return report;
}

function fingerprint(report) {
  return JSON.stringify({ checks: report.checks, score: report.score });
}

function printReport(report, { saved = true } = {}) {
  const { score } = report;
  const shown = score.provisional === null ? 'Unknown' : `${score.provisional}/100`;
  console.log('Home Network Privacy Check');
  console.log(`Target: ${report.target}`);
  console.log('WAN exposure was not tested. Results describe what is reachable from inside your network.');
  console.log(`Provisional score: ${shown} | Evidence coverage: ${score.coveragePercent}%`);
  for (const finding of report.findings) {
    console.log(`[${finding.severity}] ${finding.message}`);
  }
  if (report.comparison) {
    const { previousScore, currentScore, delta } = report.comparison;
    console.log(`Before/after: ${previousScore} -> ${currentScore} (${delta >= 0 ? '+' : ''}${delta})`);
  }
  console.log('Top actions:');
  if (report.topFixes.length === 0) {
    console.log('None. No confirmed finding needs a change.');
  } else {
    report.topFixes.forEach((fix, index) => console.log(`${index + 1}. ${fix}`));
  }
  console.log(score.disclaimer);
  if (saved) console.log(`Saved: ${REPORT_NAME}`);
}

async function runAudit({ dnsStatus = 'unknown', quiet = false, save = true } = {}) {
  const gateway = await si.networkGatewayDefault();
  if (!isPrivateGateway(gateway)) {
    throw new Error('Safety stop: the detected default gateway is not an RFC 1918 IPv4 address.');
  }

  const [ports, wifi, upnp] = await Promise.all([
    collectPorts(gateway),
    collectWifi(),
    collectUpnp(gateway),
  ]);

  const dnsBasis = {
    encrypted: 'You stated that DNS is encrypted (--dns encrypted).',
    plaintext: 'You stated that DNS is plaintext (--dns plaintext).',
    unknown: 'No DNS evidence was supplied.',
  };

  // Everything collected passes through the redaction boundary before use.
  const checks = redactValue({
    ports,
    upnp,
    wifi,
    dns: { state: dnsStatus, basis: dnsBasis[dnsStatus] },
  });

  const score = scoreChecks(checks);
  const findings = buildFindings(checks);

  const report = redactValue({
    generatedAt: new Date().toISOString(),
    platform: process.platform,
    target: TARGET_LABEL,
    checks,
    score,
    findings,
    topFixes: selectTopFixes(findings),
    privacy: {
      rawReportSaved: false,
      ssidsSaved: false,
      bssidsOrMacsSaved: false,
      completePrivateIpsSaved: false,
      deviceNamesSaved: false,
    },
  });

  if (save) saveSanitizedReport(report);
  if (!quiet) printReport(report, { saved: save });
  return report;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

const SAFE_MESSAGES = [
  'Safety stop: the detected default gateway is not an RFC 1918 IPv4 address.',
  '--dns must be encrypted, plaintext, or unknown',
];

async function main() {
  try {
    await runAudit({ dnsStatus: parseDnsStatus() });
  } catch (error) {
    if (SAFE_MESSAGES.includes(error?.message)) console.error(error.message);
    console.error('Audit stopped safely. No unsanitized error details were saved.');
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = { runAudit, fingerprint, parseDnsStatus };
