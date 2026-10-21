'use strict';
const https = require('node:https');
const net = require('node:net');
const tls = require('node:tls');
const os = require('node:os');
const fs = require('node:fs');
const { canonicalIpv6, verifier, parseCidr, allowedClient } = require('./protocol');

function boundAddresses() {
  return Object.values(os.networkInterfaces()).flat().filter(Boolean).filter(x => x.family === 'IPv6' && !x.internal)
    .map(x => { try { return canonicalIpv6(x.address); } catch { return null; } }).filter(Boolean);
}
function validateConfig(config) {
  if (!/^[a-zA-Z0-9_-]{1,80}$/.test(config.hostId || '') || !/^[a-f0-9]{64}$/.test(config.secret || '') ||
    !Number.isInteger(config.port) || config.port < 1024 || config.port > 65535 || net.isIP(config.ipv4) !== 4) throw new Error('Invalid gateway identity/secret/port/IPv4');
  config.primaryIpv6 = canonicalIpv6(config.primaryIpv6);
  config.addresses = [...new Set((config.addresses || []).map(canonicalIpv6))];
  if (config.addresses.length !== 15 || config.addresses.includes(config.primaryIpv6)) throw new Error('Exactly 15 non-primary addresses required');
  if (!Array.isArray(config.allowedCidrs) || !config.allowedCidrs.length) throw new Error('AWS source allowlist is required');
  config.allowedCidrs.forEach(parseCidr);
  return config;
}
async function diagnoseAddress(sourceIpv6) {
  const observedIpv6 = await new Promise((resolve, reject) => {
    const req = https.get({ hostname: 'one.one.one.one', path: '/cdn-cgi/trace', family: 6, localAddress: sourceIpv6, agent: false, timeout: 8000 }, res => {
      let body = '';
      res.on('data', chunk => { body += chunk; if (body.length > 64_000) res.destroy(new Error('Response too large')); });
      res.on('error', reject); res.on('end', () => {
        try { if (res.statusCode !== 200) throw new Error('Echo request failed'); resolve(canonicalIpv6(/^ip=(.+)$/m.exec(body)?.[1] || '')); }
        catch (err) { reject(err); }
      });
    });
    req.on('timeout', () => req.destroy(new Error('Echo timed out'))); req.on('error', reject);
  });
  const kiteTls = await new Promise((resolve) => {
    const socket = tls.connect({ host: 'api.kite.trade', port: 443, family: 6, localAddress: sourceIpv6,
      servername: 'api.kite.trade', rejectUnauthorized: true });
    socket.setTimeout(8000, () => socket.destroy(new Error('TLS timeout')));
    socket.once('secureConnect', () => { resolve(socket.authorized); socket.destroy(); });
    socket.once('error', () => { resolve(false); socket.destroy(); });
  });
  return { sourceIpv6, observedIpv6, kiteTls };
}
function createGateway(config, dependencies = {}) {
  validateConfig(config);
  const verify = verifier(config.secret);
  const cidrs = config.allowedCidrs.map(parseCidr);
  const addresses = dependencies.boundAddresses || boundAddresses;
  const connect = dependencies.connect || net.connect;
  const diagnose = dependencies.diagnoseAddress || diagnoseAddress;
  const authorize = req => allowedClient(req.socket.remoteAddress, cidrs) && verify(req);
  let diagnosticsRunning = false;
  let active = 0;
  const server = https.createServer({ key: config.key, cert: config.cert, minVersion: 'TLSv1.2',
    requestTimeout: 10_000, headersTimeout: 10_000, maxHeaderSize: 8192 }, async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    if (!authorize(req)) { res.writeHead(403).end(); return; }
    if (req.method !== 'GET' || !['/health', '/diagnostics'].includes(req.url)) { res.writeHead(404).end(); return; }
    if (req.url === '/health') {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ hostId: config.hostId, addresses: config.addresses.filter(ip => addresses().includes(ip)) })); return;
    }
    if (diagnosticsRunning) { res.writeHead(409).end(); return; }
    diagnosticsRunning = true;
    try {
      const checks = [];
      for (let i = 0; i < config.addresses.length; i += 3) {
        checks.push(...await Promise.all(config.addresses.slice(i, i + 3).map(async ip => {
          try { return await diagnose(ip); } catch { return { sourceIpv6: ip, observedIpv6: null, kiteTls: false }; }
        })));
      }
      res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ hostId: config.hostId, checks }));
    } finally { diagnosticsRunning = false; }
  });
  server.on('connect', (req, client, head) => {
    // CONNECT removes the HTTP parser; rejected clients can still reset TLS.
    client.on('error', () => {});
    const deny = code => client.end(`HTTP/1.1 ${code}\r\nConnection: close\r\n\r\n`);
    if (!authorize(req)) { deny('403 Forbidden'); return; }
    const source = req.headers['x-peakalgo-source'];
    if (req.url !== 'api.kite.trade:443' || head.length || typeof source !== 'string' ||
      !config.addresses.includes(source) || !addresses().includes(source)) { deny('403 Forbidden'); return; }
    if (active >= 512) { deny('503 Service Unavailable'); return; }
    active++;
    let opened = false;
    const upstream = connect({ host: 'api.kite.trade', port: 443, family: 6, localAddress: source, autoSelectFamily: false });
    const timer = setTimeout(() => upstream.destroy(new Error('Connection timeout')), 8000);
    upstream.once('connect', () => {
      clearTimeout(timer); opened = true;
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      upstream.pipe(client); client.pipe(upstream);
    });
    upstream.setTimeout(30_000, () => upstream.destroy());
    client.setTimeout(30_000, () => client.destroy());
    upstream.on('error', () => { if (!opened) deny('502 Bad Gateway'); else client.destroy(); });
    upstream.on('close', () => { clearTimeout(timer); active--; client.destroy(); });
    client.on('error', () => upstream.destroy()); client.on('close', () => upstream.destroy());
  });
  server.on('clientError', (_err, socket) => socket.destroy());
  server.on('tlsClientError', () => {});
  return server;
}
if (require.main === module) {
  const path = process.env.PEAKALGO_CONFIG || '/etc/peakalgo-egress/config.json';
  const config = JSON.parse(fs.readFileSync(path, 'utf8'));
  config.key = fs.readFileSync(config.keyPath); config.cert = fs.readFileSync(config.certPath);
  const server = createGateway(config);
  server.listen(config.port, '0.0.0.0', () => console.log(`PeakAlgo gateway ${config.hostId} listening on ${config.port}`));
  const stop = () => { server.close(); setTimeout(() => process.exit(0), 5000).unref(); };
  process.on('SIGTERM', stop); process.on('SIGINT', stop);
}
module.exports = { createGateway, validateConfig, boundAddresses, diagnoseAddress };
