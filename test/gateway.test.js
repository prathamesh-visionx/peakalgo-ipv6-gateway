'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { mkdtempSync, readFileSync, rmSync } = require('node:fs');
const os = require('node:os'); const path = require('node:path');
const { execFileSync } = require('node:child_process');
const https = require('node:https'); const net = require('node:net'); const tls = require('node:tls');
const { once } = require('node:events');
const { verifier, signedHeaders, parseCidr, allowedClient, canonicalIpv6 } = require('../src/protocol');
const { createGateway } = require('../src/server');
const secret = 'ab'.repeat(32);
const primary = '2001:db8::1';
const addresses = Array.from({ length: 16 }, (_, i) => `2001:db8::${i.toString(16)}`).filter(x => x !== primary).map(canonicalIpv6);
let directory, key, cert;
before(() => {
  directory = mkdtempSync(path.join(os.tmpdir(), 'peakalgo-gateway-test-'));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-keyout', path.join(directory, 'key.pem'), '-out', path.join(directory, 'cert.pem'), '-subj', '/CN=fixture', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:api.kite.trade'], { stdio: 'ignore' });
  key = readFileSync(path.join(directory, 'key.pem')); cert = readFileSync(path.join(directory, 'cert.pem'));
});
after(() => rmSync(directory, { recursive: true, force: true }));
const config = () => ({ hostId: 'fixture', ipv4: '127.0.0.1', primaryIpv6: primary, port: 8443, secret,
  addresses: [...addresses], allowedCidrs: ['127.0.0.1/32'], key, cert });
async function start(server) { server.listen(0, '127.0.0.1'); await once(server, 'listening'); return server.address().port; }
async function stop(server) { server.closeAllConnections?.(); await new Promise(resolve => server.close(resolve)); }
function request(port, endpoint, headers = signedHeaders(secret, 'GET', endpoint)) {
  return new Promise((resolve, reject) => {
    https.get({ hostname: '127.0.0.1', port, path: endpoint, ca: cert, headers }, res => {
      let raw = ''; res.on('data', data => raw += data); res.on('end', () => resolve({ status: res.statusCode, raw }));
    }).on('error', reject);
  });
}
function connect(port, target, source) {
  return new Promise((resolve, reject) => {
    const req = https.request({ hostname: '127.0.0.1', port, method: 'CONNECT', path: target, ca: cert,
      headers: signedHeaders(secret, 'CONNECT', target, source) });
    req.on('error', reject); req.on('connect', (res, socket) => { socket.on('error', () => {}); resolve({ status: res.statusCode, socket }); }); req.end();
  });
}

test('authentication rejects expired, replayed, malformed and tampered requests', () => {
  const now = Date.now(); const verify = verifier(secret, () => now);
  const req = { method: 'CONNECT', url: 'api.kite.trade:443', headers: signedHeaders(secret, 'CONNECT', 'api.kite.trade:443', addresses[0], now) };
  assert.equal(verify({ ...req, headers: { ...req.headers, 'x-peakalgo-time': String(now - 31_000) } }), false);
  assert.equal(verify({ ...req, url: 'evil.example:443' }), false);
  assert.equal(verify(req), true); assert.equal(verify(req), false);
  assert.equal(verify({ ...req, headers: {} }), false);
});

test('AWS source CIDRs reject open allowlists and unrelated addresses', () => {
  assert.throws(() => parseCidr('0.0.0.0/0'));
  assert.throws(() => parseCidr('not-an-ip'));
  const cidrs = ['203.0.113.4/32', '10.10.1.0/24'].map(parseCidr);
  assert.equal(allowedClient('::ffff:203.0.113.4', cidrs), true);
  assert.equal(allowedClient('203.0.113.5', cidrs), false);
  assert.equal(allowedClient('10.10.1.45', cidrs), true);
  assert.equal(allowedClient('::1', cidrs), false);
});

test('health is authenticated, read-only and lists only configured, bound pool addresses', async () => {
  let probes = 0;
  const server = createGateway(config(), { boundAddresses: () => [primary, addresses[0]], diagnoseAddress: async () => { probes++; } });
  const port = await start(server);
  try {
    assert.equal((await request(port, '/health', {})).status, 403);
    const result = await request(port, '/health');
    assert.equal(result.status, 200); assert.deepEqual(JSON.parse(result.raw).addresses, [addresses[0]]); assert.equal(probes, 0);
    assert.equal((await request(port, '/other')).status, 404);
  } finally { await stop(server); }
});

test('CONNECT rejects arbitrary destinations, reserved primary and unbound addresses', async () => {
  let outboundCalls = 0;
  const server = createGateway(config(), { boundAddresses: () => [addresses[0]], connect: () => { outboundCalls++; throw new Error('Must not run'); } });
  const port = await start(server);
  try {
    for (const [target, source] of [['example.com:443', addresses[0]], ['api.kite.trade:80', addresses[0]], ['api.kite.trade:443', primary], ['api.kite.trade:443', addresses[1]]]) {
      const result = await connect(port, target, source); assert.equal(result.status, 403); result.socket.destroy();
    }
    assert.equal(outboundCalls, 0);
  } finally { await stop(server); }
});

test('CONNECT preserves opaque broker TLS and requests exact IPv6 binding without fallback', async () => {
  const broker = https.createServer({ key, cert }, (_req, res) => res.end('broker-fixture'));
  const brokerPort = await start(broker); const outbound = [];
  const gateway = createGateway(config(), { boundAddresses: () => addresses,
    connect: options => { outbound.push(options); return net.connect({ host: '127.0.0.1', port: brokerPort }); } });
  const gatewayPort = await start(gateway);
  try {
    const result = await connect(gatewayPort, 'api.kite.trade:443', addresses[0]);
    assert.equal(result.status, 200);
    const inner = tls.connect({ socket: result.socket, servername: 'api.kite.trade', ca: cert });
    await once(inner, 'secureConnect');
    assert.equal(inner.authorized, true);
    inner.write('GET / HTTP/1.1\r\nHost: api.kite.trade\r\nConnection: close\r\n\r\n');
    let response = ''; for await (const chunk of inner) response += chunk;
    assert.match(response, /broker-fixture/);
    assert.deepEqual(outbound, [{ host: 'api.kite.trade', port: 443, family: 6, localAddress: addresses[0], autoSelectFamily: false }]);
  } finally { await stop(gateway); await stop(broker); }
});

test('diagnostics run only on explicit request and return source-bound results', async () => {
  const calls = [];
  const server = createGateway(config(), { boundAddresses: () => addresses,
    diagnoseAddress: async source => { calls.push(source); return { sourceIpv6: source, observedIpv6: source, kiteTls: true }; } });
  const port = await start(server);
  try {
    await request(port, '/health'); assert.equal(calls.length, 0);
    const response = await request(port, '/diagnostics');
    assert.equal(JSON.parse(response.raw).checks.length, 15); assert.deepEqual(calls.sort(), [...addresses].sort());
  } finally { await stop(server); }
});

test('untrusted TLS certificate is rejected by clients', async () => {
  const server = createGateway(config(), { boundAddresses: () => addresses }); const port = await start(server);
  try {
    await assert.rejects(new Promise((resolve, reject) => https.get({ hostname: '127.0.0.1', port, path: '/health' }, resolve).on('error', reject)), /self-signed/);
  } finally { await stop(server); }
});
