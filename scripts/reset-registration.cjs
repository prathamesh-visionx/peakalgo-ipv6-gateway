#!/usr/bin/env node
'use strict';
// Offline backend administrator tool. No reset API is exposed on the internet.
const fs = require('node:fs');
const path = require('node:path');
const { parseArgs } = require('node:util');
const { randomUUID } = require('node:crypto');

const HELP = `Reset one gateway's Mongo registration using the BACKEND server's database configuration.

Run on the backend server, with its installed Node dependencies and .env:
  node reset-registration.cjs --backend-dir /home/ubuntu/dev-algo-backend- --host-id do-123
  node reset-registration.cjs --backend-dir /home/ubuntu/dev-algo-backend- --host-id do-123 \\
    --apply --confirm-host-id do-123 --release-assignments --backup-file /secure/host-backup.json

Options:
  --backend-dir DIR       Backend repository containing .env and node_modules (required)
  --host-id ID            Exact gateway ID, never a Mongo filter (required)
  --apply                Delete only that host and its IPv6 rows; default is preview
  --confirm-host-id ID    Must equal --host-id for deletion; no repeated prompts
  --release-assignments  Explicitly clear assigned/reserved IPv6 and whitelist confirmations
  --backup-file FILE     New absolute file for a mode-600 Extended JSON backup (required on apply)
  --help                 Show this help without connecting to MongoDB

Checks live positions, pending orders and active broker attempts. Locks affected users and
trading accounts, disables their engines, rechecks, and deletes in one Mongo transaction.
User credentials, orders, positions and unrelated gateways remain. No decryption key needed.
Transactions are required; no unsafe non-transactional fallback. Database credentials never print.
When using another database, disable this host in the previous backend first. Remove old Kite
whitelist entries before assigning released addresses to a different broker client.
`;

function options(args) {
  const { values: v } = parseArgs({ args, options: {
    'backend-dir': { type: 'string' }, 'host-id': { type: 'string' }, apply: { type: 'boolean' },
    'confirm-host-id': { type: 'string' }, 'release-assignments': { type: 'boolean' },
    'backup-file': { type: 'string' }, help: { type: 'boolean' },
  } });
  if (v.help) return { help: true };
  if (!v['backend-dir'] || !/^[a-zA-Z0-9_-]{1,80}$/.test(v['host-id'] || '')) throw new Error('Provide --backend-dir and one exact --host-id.');
  if (v.apply && (v['confirm-host-id'] !== v['host-id'] || !v['backup-file'] || !path.isAbsolute(v['backup-file']))) {
    throw new Error('Apply requires --confirm-host-id matching --host-id and an absolute --backup-file.');
  }
  return { backendDir: path.resolve(v['backend-dir']), hostId: v['host-id'], apply: !!v.apply,
    releaseAssignments: !!v['release-assignments'], backupFile: v['backup-file'] };
}

function sameAddresses(rows) {
  return JSON.stringify(rows.map(a => [String(a._id), a.sourceIpv6, String(a.userId || ''), a.clientCode || '',
    a.assignedAt ? new Date(a.assignedAt).toISOString() : null,
    a.whitelistConfirmedAt ? new Date(a.whitelistConfirmedAt).toISOString() : null]).sort((a, b) => a[0].localeCompare(b[0])));
}

async function snapshot(db, hostId, session) {
  const opt = session ? { session } : {};
  const host = await db.collection('egresshosts').findOne({ hostId }, opt);
  const addresses = await db.collection('egressaddresses').find({ hostId }, opt).toArray();
  const ids = addresses.map(a => a.userId).filter(Boolean);
  const codes = [...new Set(addresses.map(a => a.clientCode).filter(Boolean))];
  const users = await db.collection('users').find({ $or: [{ _id: { $in: ids } }, { zerodhaClientCode: { $in: codes } }] },
    { ...opt, projection: { _id: 1, engineEnabled: 1, brokerOperation: 1 } }).toArray();
  const allIds = [...new Map([...ids, ...users.map(u => u._id)].map(id => [String(id), id])).values()];
  const exposure = {
    livePositions: await db.collection('livepositions').countDocuments({ userId: { $in: allIds }, dryRun: false, status: { $ne: 'closed' } }, opt),
    pendingOrders: await db.collection('liveorders').countDocuments({ userId: { $in: allIds }, dryRun: false,
      status: { $nin: ['COMPLETE', 'REJECTED', 'CANCELLED', 'DRY_RUN'] } }, opt),
    activeAttempts: await db.collection('brokerorderattempts').countDocuments({ active: true,
      $or: [{ userId: { $in: allIds } }, { clientCode: { $in: codes } }] }, opt),
  };
  return { host, addresses, users, allIds, exposure };
}

function assertNoExposure(state) {
  if (Object.values(state.exposure).some(Boolean)) throw new Error('Live positions, pending orders or active broker attempts exist. Nothing deleted.');
}

async function resetRegistration(db, client, args, backup) {
  const before = await snapshot(db, args.hostId);
  const assigned = before.addresses.filter(a => a.userId || a.clientCode);
  const preview = { mode: args.apply ? 'apply' : 'preview', database: db.databaseName, hostId: args.hostId,
    found: !!before.host, addressCount: before.addresses.length, assignedCount: assigned.length,
    assignments: assigned.map(a => ({ sourceIpv6: a.sourceIpv6, clientCode: a.clientCode, userId: a.userId })),
    affectedEngines: before.users.filter(u => u.engineEnabled).length, exposure: before.exposure };
  if (!args.apply || (!before.host && !before.addresses.length)) return preview;
  assertNoExposure(before);
  if (assigned.length && !args.releaseAssignments) throw new Error('Assigned/reserved addresses exist. Explicit --release-assignments is required. Nothing deleted.');
  if (before.users.some(u => u.brokerOperation)) throw new Error('A broker operation is in progress. Nothing deleted.');
  await backup({ format: 'peakalgo-gateway-reset-v1', database: db.databaseName, createdAt: new Date(), hostId: args.hostId,
    host: before.host, addresses: before.addresses, users: before.users });
  const token = 'gateway-reset-' + randomUUID();
  const locked = [];
  let session;
  try {
    // Same fence used by the broker transport, acquired before checking exposure again.
    for (const user of before.users) {
      const result = await db.collection('users').updateOne({ _id: user._id, brokerOperation: null }, { $set: { brokerOperation: token } });
      if (result.modifiedCount !== 1) throw new Error('A broker operation started. Nothing deleted.');
      locked.push(user._id);
    }
    session = client.startSession();
    let deleted;
    await session.withTransaction(async () => {
      const current = await snapshot(db, args.hostId, session);
      if (sameAddresses(current.addresses) !== sameAddresses(before.addresses) ||
          String(current.host?._id || '') !== String(before.host?._id || '') ||
          current.host?.secretEncrypted !== before.host?.secretEncrypted ||
          current.users.length !== before.users.length || current.users.some(u => u.brokerOperation !== token)) {
        throw new Error('Gateway assignments/identity or user ownership changed. Nothing deleted; run a new preview.');
      }
      for (const id of before.allIds) {
        const account = await db.collection('tradingaccounts').findOne({ _id: String(id) }, { session });
        if (account?.lock && account.lockUntil && account.lockUntil > new Date()) throw new Error('A trading account operation is in progress. Nothing deleted.');
        await db.collection('tradingaccounts').updateOne({ _id: String(id) },
          { $set: { lock: token, lockUntil: new Date(Date.now() + 60000) } }, { session, upsert: true });
      }
      assertNoExposure(await snapshot(db, args.hostId, session));
      if (before.users.length) await db.collection('users').updateMany({ _id: { $in: locked }, brokerOperation: token },
        { $set: { engineEnabled: false } }, { session });
      const addresses = await db.collection('egressaddresses').deleteMany({ hostId: args.hostId }, { session });
      const host = await db.collection('egresshosts').deleteOne({ hostId: args.hostId }, { session });
      if (addresses.deletedCount !== before.addresses.length || host.deletedCount !== (before.host ? 1 : 0)) throw new Error('Reset counts changed; transaction rolled back.');
      deleted = { hosts: host.deletedCount, addresses: addresses.deletedCount };
    });
    return { ...preview, deleted, enginesDisabled: locked.length, backupFile: args.backupFile };
  } finally {
    if (session) await session.endSession();
    await db.collection('users').updateMany({ _id: { $in: locked }, brokerOperation: token }, { $set: { brokerOperation: null } });
    await db.collection('tradingaccounts').updateMany({ _id: { $in: before.allIds.map(String) }, lock: token }, { $set: { lock: null, lockUntil: null } });
  }
}

async function main() {
  const args = options(process.argv.slice(2));
  if (args.help) { console.log(HELP); return; }
  const resolve = name => require.resolve(name, { paths: [args.backendDir] });
  require(resolve('dotenv')).config({ path: path.join(args.backendDir, '.env'), quiet: true });
  const mongoose = require(resolve('mongoose'));
  if (!process.env.MONGO_URI) throw new Error('MONGO_URI is required in the backend environment/.env.');
  await mongoose.connect(process.env.MONGO_URI, { autoIndex: false, serverSelectionTimeoutMS: 10000 });
  try {
    const result = await resetRegistration(mongoose.connection.db, mongoose.connection.getClient(), args, async data => {
      // Exclusive create refuses symlinks/existing backups. Never overwrite a previous recovery file.
      const fd = fs.openSync(args.backupFile, 'wx', 0o600);
      try {
        fs.writeFileSync(fd, mongoose.mongo.BSON.EJSON.stringify(data, null, 2, { relaxed: false }));
        fs.fsyncSync(fd);
      } finally { fs.closeSync(fd); }
    });
    console.log(JSON.stringify(result, null, 2));
  } finally { await mongoose.disconnect(); }
}

module.exports = { options, sameAddresses, snapshot, resetRegistration, assertNoExposure };
if (require.main === module) main().catch(error => {
  // Never emit driver connection strings, credentials or ciphertext in errors.
  const message = String(error.message).replace(/mongodb(?:\+srv)?:\/\/[^\s]+/g, '[redacted Mongo URI]');
  console.error('Gateway reset stopped: ' + message); process.exitCode = 1;
});
