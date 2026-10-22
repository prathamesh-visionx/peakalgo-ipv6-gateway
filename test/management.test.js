'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { options, resetRegistration } = require('../scripts/reset-registration.cjs');

const same = (a, b) => String(a) === String(b);
function match(row, filter) {
  return Object.entries(filter).every(([key, value]) => {
    if (key === '$or') return value.some(clause => match(row, clause));
    if (value && typeof value === 'object' && !(value instanceof Date)) {
      if ('$in' in value) return value.$in.some(x => same(row[key], x));
      if ('$nin' in value) return !value.$nin.some(x => same(row[key], x));
      if ('$ne' in value) return !same(row[key], value.$ne);
    }
    return value == null ? row[key] == null : same(row[key], value);
  });
}
function fixture() {
  let data = {
    egresshosts: [{ _id: 'h', hostId: 'do-test', enabled: true, secretEncrypted: 'never-log-this' }, { _id: 'other', hostId: 'do-other' }],
    egressaddresses: [{ _id: 'a', hostId: 'do-test', sourceIpv6: '2001:4860::1', userId: 'u', clientCode: 'CLIENT', whitelistConfirmedAt: new Date() },
      { _id: 'other-address', hostId: 'do-other', clientCode: 'OTHER' }],
    users: [{ _id: 'u', engineEnabled: true, zerodhaClientCode: 'CLIENT', brokerOperation: null, brokerApiSecret: 'preserve' },
      { _id: 'other-user', engineEnabled: true }], tradingaccounts: [], livepositions: [], liveorders: [], brokerorderattempts: [],
  };
  const db = { databaseName: 'fixture', collection(name) {
    const rows = () => data[name] ||= [];
    const change = (filter, update, multiple, opt = {}) => {
      let found = rows().filter(row => match(row, filter));
      if (!multiple) found = found.slice(0, 1);
      if (!found.length && opt.upsert) { const row = { ...filter }; rows().push(row); found = [row]; }
      for (const row of found) Object.assign(row, update.$set || {});
      return { modifiedCount: found.length };
    };
    return {
      findOne: async filter => structuredClone(rows().find(row => match(row, filter)) || null),
      find: filter => ({ toArray: async () => structuredClone(rows().filter(row => match(row, filter))) }),
      countDocuments: async filter => rows().filter(row => match(row, filter)).length,
      updateOne: async (f, u, opt) => change(f, u, false, opt), updateMany: async (f, u) => change(f, u, true),
      deleteMany: async filter => { const count = rows().filter(row => match(row, filter)).length; data[name] = rows().filter(row => !match(row, filter)); return { deletedCount: count }; },
      deleteOne: async filter => { const i = rows().findIndex(row => match(row, filter)); if (i < 0) return { deletedCount: 0 }; rows().splice(i, 1); return { deletedCount: 1 }; },
    };
  } };
  const client = { startSession: () => ({ withTransaction: async work => {
    const before = structuredClone(data);
    try { await work(); } catch (err) { data = before; throw err; }
  }, endSession: async () => {} }) };
  return { db, client, rows: name => data[name], args: { hostId: 'do-test', apply: true, releaseAssignments: true, backupFile: '/private/backup.json' } };
}

test('reset defaults to preview and requires a target confirmation plus backup for apply', () => {
  assert.equal(options(['--backend-dir', '/backend', '--host-id', 'do-test']).apply, false);
  assert.deepEqual(options(['--help']), { help: true });
  assert.throws(() => options(['--backend-dir', '/backend', '--host-id', 'do-test', '--apply']), /confirm-host-id/);
  assert.throws(() => options(['--backend-dir', '/backend', '--host-id', '{"$ne":null}']), /exact/);
});

test('preview never locks, deletes, disables engines or writes backups', async () => {
  const f = fixture();
  const result = await resetRegistration(f.db, f.client, { ...f.args, apply: false }, () => { throw new Error('must not back up'); });
  assert.equal(result.assignedCount, 1);
  assert.equal(f.rows('egresshosts').length, 2);
  assert.equal(f.rows('users')[0].engineEnabled, true);
  assert.equal(f.rows('users')[0].brokerOperation, null);
});

test('apply backs up then removes exactly the targeted gateway and addresses; engines pause and credentials survive', async () => {
  const f = fixture(); let backup;
  const result = await resetRegistration(f.db, f.client, f.args, async value => { backup = value; assert.equal(f.rows('egresshosts').length, 2); });
  assert.deepEqual(result.deleted, { hosts: 1, addresses: 1 });
  assert.equal(backup.host.secretEncrypted, 'never-log-this');
  assert.equal(backup.users[0].engineEnabled, true);
  assert.equal(f.rows('egresshosts')[0].hostId, 'do-other');
  assert.equal(f.rows('egressaddresses')[0].hostId, 'do-other');
  assert.equal(f.rows('users')[0].brokerApiSecret, 'preserve');
  assert.equal(f.rows('users')[0].engineEnabled, false);
  assert.equal(f.rows('users')[0].brokerOperation, null);
  assert.equal(f.rows('users')[1].engineEnabled, true);
  assert.equal(f.rows('tradingaccounts')[0].lock, null);
  assert.ok(!JSON.stringify(result).includes('never-log-this'));
});

test('live exposure and missing assignment-release authorization refuse deletion', async () => {
  for (const [collection, row] of [
    ['livepositions', { userId: 'u', dryRun: false, status: 'open' }],
    ['liveorders', { userId: 'u', dryRun: false, status: 'OPEN' }],
    ['brokerorderattempts', { clientCode: 'CLIENT', active: true }],
  ]) {
    const f = fixture(); f.rows(collection).push(row);
    await assert.rejects(resetRegistration(f.db, f.client, f.args, async () => {}), /Nothing deleted/);
    assert.equal(f.rows('egresshosts').length, 2);
  }
  const f = fixture();
  await assert.rejects(resetRegistration(f.db, f.client, { ...f.args, releaseAssignments: false }, async () => {}), /release-assignments/);
});

test('exposure appearing after preview is rechecked under locks and the transaction rolls back', async () => {
  const f = fixture();
  await assert.rejects(resetRegistration(f.db, f.client, f.args, async () => {
    f.rows('liveorders').push({ userId: 'u', dryRun: false, status: 'OPEN' });
  }), /Nothing deleted/);
  assert.equal(f.rows('egresshosts').length, 2);
  assert.equal(f.rows('users')[0].engineEnabled, true);
  assert.equal(f.rows('users')[0].brokerOperation, null);
});

test('assignment race and backup failure stop without deleting records', async () => {
  const f = fixture();
  await assert.rejects(resetRegistration(f.db, f.client, f.args, async () => { f.rows('egressaddresses')[0].clientCode = 'CHANGED'; }), /changed/);
  assert.equal(f.rows('egresshosts').length, 2);
  assert.equal(f.rows('users')[0].brokerOperation, null);
  const g = fixture();
  await assert.rejects(resetRegistration(g.db, g.client, g.args, async () => { throw new Error('disk full'); }), /disk full/);
  assert.equal(g.rows('users')[0].brokerOperation, null);
  assert.equal(g.rows('egressaddresses').length, 2);
});
