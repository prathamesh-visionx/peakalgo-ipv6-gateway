'use strict';
const { createHmac, timingSafeEqual, randomBytes } = require('node:crypto');
const { isIP } = require('node:net');
function canonicalIpv6(value) {
  if (isIP(value) !== 6 || value.includes('%')) throw new Error('Invalid IPv6');
  const ip = new URL(`http://[${value}]/`).hostname.slice(1, -1);
  if (!/^[23]/.test(ip)) throw new Error('Public IPv6 required');
  return ip;
}
function safeEqual(a, b) {
  const aa = Buffer.from(a); const bb = Buffer.from(b);
  return aa.length === bb.length && timingSafeEqual(aa, bb);
}
function signedHeaders(secret, method, path, source = '', now = Date.now(), nonce = randomBytes(24).toString('hex')) {
  const time = String(now);
  return { 'x-peakalgo-source': source, 'x-peakalgo-time': time, 'x-peakalgo-nonce': nonce,
    'x-peakalgo-signature': createHmac('sha256', secret).update([method, path, source, time, nonce].join('\n')).digest('hex') };
}
function verifier(secret, clock = Date.now) {
  const nonces = new Map();
  return (req) => {
    const h = req.headers;
    const source = h['x-peakalgo-source'] || '';
    const time = h['x-peakalgo-time']; const nonce = h['x-peakalgo-nonce']; const signature = h['x-peakalgo-signature'];
    if (typeof source !== 'string' || typeof time !== 'string' || !/^\d{13}$/.test(time) ||
      typeof nonce !== 'string' || !/^[a-f0-9]{48}$/.test(nonce) || typeof signature !== 'string' || !/^[a-f0-9]{64}$/.test(signature) ||
      Math.abs(clock() - Number(time)) > 30_000) return false;
    for (const [key, expiry] of nonces) if (expiry < clock()) nonces.delete(key);
    if (nonces.has(nonce) || nonces.size >= 20_000) return false;
    const expected = signedHeaders(secret, req.method, req.url, source, Number(time), nonce)['x-peakalgo-signature'];
    if (!safeEqual(signature, expected)) return false;
    nonces.set(nonce, Number(time) + 30_000); return true;
  };
}
function ipv4Number(value) { return value.split('.').reduce((acc, v) => (acc << 8n) | BigInt(v), 0n); }
function parseCidr(cidr) {
  const [ip, bits] = String(cidr).split('/'); const prefix = Number(bits);
  if (isIP(ip) !== 4 || bits === undefined || !Number.isInteger(prefix) || prefix < 1 || prefix > 32) throw new Error('Use explicit IPv4 AWS source CIDRs, preferably /32');
  const mask = (0xffffffffn << BigInt(32-prefix)) & 0xffffffffn;
  return { network: ipv4Number(ip) & mask, mask };
}
function allowedClient(remote, cidrs) {
  const ip = (remote || '').replace(/^::ffff:/, '');
  if (isIP(ip) !== 4) return false;
  const value = ipv4Number(ip);
  return cidrs.some(({ network, mask }) => (value & mask) === network);
}
module.exports = { canonicalIpv6, safeEqual, signedHeaders, verifier, parseCidr, allowedClient };
