import assert from 'node:assert/strict';
import test from 'node:test';
import { networkGrants, originGrants, parseConfig } from '../src/config.js';

test('defaults to no private origin grants', () => {
  const config = parseConfig({});

  assert.deepEqual(config, {
    chromePath: null,
    allowedOrigins: [],
    allowedNetworks: [],
    allowReservedNetworks: [],
    discoverDevServers: false,
  });
  assert.deepEqual(originGrants(config.allowedOrigins), []);
});

test('normalizes explicit origins into exact host and port grants', () => {
  const config = parseConfig({
    chromePath: '/opt/chrome',
    allowedOrigins: ['http://localhost:3000', 'https://device.example'],
  });

  assert.equal(config.chromePath, '/opt/chrome');
  assert.deepEqual(originGrants(config.allowedOrigins), [
    { host: 'localhost', port: 3000, protocol: 'http:' },
    { host: 'device.example', port: 443, protocol: 'https:' },
  ]);
});

test('rejects allowlist entries that are not exact http origins', () => {
  assert.throws(
    () => parseConfig({ allowedOrigins: ['http://localhost:3000/private'] }),
    /must be an http\(s\) origin/,
  );
  assert.throws(
    () => parseConfig({ allowedOrigins: ['file:///tmp/page.html'] }),
    /must be an http\(s\) origin/,
  );
});

test('parses private network blocks with explicit ports and ranges', () => {
  const config = parseConfig({ allowedNetworks: [{ cidr: '192.168.1.0/24', ports: [3000, '5173-5199', '8080'] }] });
  const [grant] = networkGrants(config.allowedNetworks);

  assert.deepEqual(config.allowedNetworks[0].ports, [[3000, 3000], [5173, 5199], [8080, 8080]]);
  assert.equal(grant.block.check('192.168.1.20', 'ipv4'), true);
  assert.equal(grant.block.check('192.168.2.20', 'ipv4'), false);
});

test('rejects network blocks that are public, too broad, or missing explicit ports', () => {
  for (const network of [
    { cidr: '8.8.8.0/24', ports: [3000] },
    { cidr: '10.0.0.0/7', ports: [3000] },
    { cidr: '192.168.1.0/24' },
    { cidr: '192.168.1.0/24', ports: ['*'] },
    { cidr: '192.168.1.0/24', ports: ['3000-2000'] },
  ]) {
    assert.throws(() => parseConfig({ allowedNetworks: [network] }), /config\.allowedNetworks\[0\]/);
  }
});


test('takes a listed reserved range out of the permanent deny tier', () => {
  const config = parseConfig({ allowReservedNetworks: ['100.64.0.0/10', 'fd7a:115c:a1e0::/48'] });

  assert.deepEqual(config.allowReservedNetworks.map((entry) => entry.cidr), ['100.64.0.0/10', 'fd7a:115c:a1e0::/48']);
  assert.deepEqual(config.allowReservedNetworks.map((entry) => entry.family), ['ipv4', 'ipv6']);
});

test('lets a reserved override carry an allowedNetworks block for its range', () => {
  const config = parseConfig({
    allowReservedNetworks: ['100.64.0.0/10'],
    allowedNetworks: [{ cidr: '100.70.0.0/16', ports: [443] }],
  });
  const [grant] = networkGrants(config.allowedNetworks);

  assert.equal(grant.block.check('100.70.46.55', 'ipv4'), true);
  // Without the override the same block is still refused as a public range.
  assert.throws(
    () => parseConfig({ allowedNetworks: [{ cidr: '100.70.0.0/16', ports: [443] }] }),
    /config\.allowedNetworks\[0\]/,
  );
});

test('rejects reserved overrides that are malformed, too broad, or not reserved', () => {
  for (const network of ['100.64.0.0', '100.64.0.0/4', '8.8.8.0/24', 'not-a-cidr/10', 42]) {
    assert.throws(() => parseConfig({ allowReservedNetworks: [network] }), /config\.allowReservedNetworks\[0\]/);
  }
  // Ranges that protect against SSRF and loopback bypass cannot be listed at all.
  for (const network of ['169.254.0.0/16', '0.0.0.0/8', '224.0.0.0/4', 'fe80::/16', 'ff00::/16']) {
    assert.throws(() => parseConfig({ allowReservedNetworks: [network] }), /config\.allowReservedNetworks\[0\]/);
  }
  assert.throws(() => parseConfig({ allowReservedNetworks: '100.64.0.0/10' }), /must be an array/);
});

test('turns development-server discovery on only with an explicit boolean', () => {
  assert.equal(parseConfig({ discoverDevServers: true }).discoverDevServers, true);
  assert.throws(() => parseConfig({ discoverDevServers: 'yes' }), /discoverDevServers must be true or false/);
});