#!/usr/bin/env node
'use strict';
// Explicitly invoked by the operator. This sends read-only IPv6 connectivity probes.
const fs = require('node:fs');
const https = require('node:https');
const { signedHeaders } = require('../src/protocol');
const config = JSON.parse(fs.readFileSync(process.env.PEAKALGO_CONFIG || '/etc/peakalgo-egress/config.json', 'utf8'));
const path = process.argv.includes('--health') ? '/health' : '/diagnostics';
const req = https.get({ hostname: config.ipv4, port: config.port, path, ca: fs.readFileSync(config.certPath),
  headers: signedHeaders(config.secret, 'GET', path), timeout: 90_000 }, res => {
  let body = ''; res.on('data', chunk => body += chunk); res.on('end', () => {
    try {
      if (res.statusCode !== 200) throw new Error(`Gateway returned ${res.statusCode}`);
      const result = JSON.parse(body);
      const ok = result.checks ? result.checks.every(x => x.observedIpv6 === x.sourceIpv6 && x.kiteTls) : result.addresses.length === 15;
      if (process.argv.includes('--json')) console.log(JSON.stringify(result, null, 2));
      else {
        console.log(`Gateway: ${result.hostId}`);
        for (const x of result.checks || []) console.log(`${x.sourceIpv6}: observed=${x.observedIpv6 || 'FAILED'} Kite TLS=${x.kiteTls ? 'OK' : 'FAILED'}`);
        console.log(ok ? 'PASS' : 'FAIL — inspect networking; no trades were placed.');
      }
      process.exitCode = ok ? 0 : 1;
    } catch (err) { console.error(err.message); process.exitCode = 1; }
  });
});
req.on('timeout', () => req.destroy(new Error('Diagnostics timed out')));
req.on('error', err => { console.error(err.message); process.exitCode = 1; });
