import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import http from 'node:http';
import net from 'node:net';
import test from 'node:test';
import { classifyProxyTarget, createPolicyProxy, createReservedOverrides } from '../src/policy-proxy.js';

const listen = (server) => new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(0, '127.0.0.1', () => resolve(server.address().port));
});

const close = (server) => new Promise((resolve) => server.close(resolve));

test('denies private destinations unless their exact host and port are allowed', async () => {
  const lookup = async () => [{ address: '127.0.0.1', family: 4 }];

  const denied = await classifyProxyTarget('http://local.test:4123/', { lookup });
  const allowed = await classifyProxyTarget('http://local.test:4123/', {
    lookup,
    grants: [{ host: 'local.test', port: 4123, protocol: 'http:' }],
  });
  const wrongScheme = await classifyProxyTarget('https://local.test:4123/', {
    lookup,
    grants: [{ host: 'local.test', port: 4123, protocol: 'http:' }],
  });
  const websocket = await classifyProxyTarget('ws://local.test:4123/socket', {
    lookup,
    grants: [{ host: 'local.test', port: 4123, protocol: 'http:' }],
  });

  assert.equal(denied.allowed, false);
  assert.equal(denied.reason, 'Private or loopback address requires an allowed origin');
  assert.equal(allowed.allowed, true);
  assert.equal(allowed.address, '127.0.0.1');
  assert.equal(wrongScheme.allowed, false);
  assert.equal(websocket.allowed, true);
});

test('allows a private network block only on its listed ports', async () => {
  const block = new net.BlockList();
  block.addSubnet('192.168.1.0', 24, 'ipv4');
  const grants = [{ block, ports: [[3000, 3200]] }];

  const allowed = await classifyProxyTarget('https://192.168.1.20:3100/', { grants });
  const otherPort = await classifyProxyTarget('http://192.168.1.20:22/', { grants });
  const otherNetwork = await classifyProxyTarget('http://192.168.2.20:3100/', { grants });
  const loopback = await classifyProxyTarget('http://localhost:3100/', {
    grants,
    lookup: async () => [{ address: '127.0.0.1', family: 4 }],
  });

  assert.equal(allowed.allowed, true);
  assert.deepEqual([otherPort.allowed, otherNetwork.allowed, loopback.allowed], [false, false, false]);
});

test('makes an overridden reserved range grantable without allowing it outright', async () => {
  // Given an overlay network, such as Tailscale, addressing its peers in CGNAT space.
  const reservedOverrides = createReservedOverrides([{ address: '100.64.0.0', prefix: 10, family: 'ipv4' }]);
  const lookup = async () => [{ address: '100.70.46.55', family: 4 }];

  // When the name has a grant, then it resolves like any other private target.
  const granted = await classifyProxyTarget('https://peer.test/', {
    lookup,
    reservedOverrides,
    grants: [{ host: 'peer.test', port: 443, protocol: 'https:' }],
  });
  assert.deepEqual([granted.allowed, granted.address], [true, '100.70.46.55']);

  // When it has none, then the override alone does not open it.
  const ungranted = await classifyProxyTarget('https://peer.test/', { lookup, reservedOverrides });
  assert.deepEqual(
    [ungranted.allowed, ungranted.reason, ungranted.grantable],
    [false, 'Private or loopback address requires an allowed origin', true],
  );

  // When nothing is overridden, then the range stays permanently denied.
  const withoutOverride = await classifyProxyTarget('https://peer.test/', {
    lookup,
    grants: [{ host: 'peer.test', port: 443, protocol: 'https:' }],
  });
  assert.equal(withoutOverride.allowed, false);
  assert.equal(withoutOverride.grantable, undefined);
});

test('keeps other reserved ranges denied when one is overridden', async () => {
  const reservedOverrides = createReservedOverrides([{ address: '100.64.0.0', prefix: 10, family: 'ipv4' }]);
  const grants = [{ host: 'peer.test', port: 80, protocol: 'http:' }];

  for (const [address, expected] of [
    ['169.254.169.254', 'IPv4 link-local addresses are denied'],
    ['224.0.0.1', 'Unspecified, link-local, transition, multicast, CGNAT, or reserved addresses are denied'],
    ['::ffff:100.70.46.55', 'IPv4-mapped addresses are denied'],
  ]) {
    const decision = await classifyProxyTarget('http://peer.test/', {
      grants,
      reservedOverrides,
      lookup: async () => [{ address, family: net.isIP(address) }],
    });
    assert.deepEqual([decision.allowed, decision.reason], [false, expected], address);
  }

  // Cloud metadata stays denied by name even inside an overridden range.
  const metadata = await classifyProxyTarget('http://metadata.google.internal/', { grants, reservedOverrides });
  assert.equal(metadata.reason, 'Cloud metadata host is denied');
});

test('clears a dual-stack answer whose IPv6 record is in an overridden range', async () => {
  // Given a tailnet name answering with both families, IPv6 first, since one
  // denied answer fails the whole request however the other family is listed.
  const reservedOverrides = createReservedOverrides([
    { address: '100.64.0.0', prefix: 10, family: 'ipv4' },
    { address: 'fd7a:115c:a1e0::', prefix: 48, family: 'ipv6' },
  ]);
  const lookup = async () => [
    { address: 'fd7a:115c:a1e0::3b35:4741', family: 6 },
    { address: '100.70.46.55', family: 4 },
  ];

  const decision = await classifyProxyTarget('https://peer.test/docs', {
    lookup,
    reservedOverrides,
    grants: [{ host: 'peer.test', port: 443, protocol: 'https:' }],
  });
  assert.deepEqual([decision.allowed, decision.address], [true, 'fd7a:115c:a1e0::3b35:4741']);

  // When only IPv4 is listed, then the IPv6 answer still blocks the request.
  const v4Only = await classifyProxyTarget('https://peer.test/docs', {
    lookup,
    reservedOverrides: createReservedOverrides([{ address: '100.64.0.0', prefix: 10, family: 'ipv4' }]),
    grants: [{ host: 'peer.test', port: 443, protocol: 'https:' }],
  });
  assert.equal(v4Only.allowed, false);
});

test('refuses to reopen metadata, unspecified, and multicast ranges however they are listed', async () => {
  // Given an operator who lists over-broad blocks covering protected ranges.
  const reservedOverrides = createReservedOverrides([
    { address: '0.0.0.0', prefix: 8, family: 'ipv4' },
    { address: '169.254.0.0', prefix: 16, family: 'ipv4' },
    { address: '224.0.0.0', prefix: 4, family: 'ipv4' },
    { address: 'fe80::', prefix: 10, family: 'ipv6' },
  ]);
  const grants = [{ host: 'evil.test', port: 80, protocol: 'http:' }];

  for (const address of ['169.254.169.254', '0.0.0.0', '224.0.0.1', 'fe80::1']) {
    const decision = await classifyProxyTarget('http://evil.test/', {
      grants,
      reservedOverrides,
      lookup: async () => [{ address, family: net.isIP(address) }],
    });
    assert.equal(decision.allowed, false, address);
    assert.equal(decision.grantable, undefined, address);
  }
});

test('denies a hostname when any DNS answer is unsafe', async () => {
  const lookup = async () => [
    { address: '93.184.216.34', family: 4 },
    { address: '169.254.169.254', family: 4 },
  ];

  const decision = await classifyProxyTarget('https://rebinding.test/', { lookup });

  assert.equal(decision.allowed, false);
  assert.equal(decision.reason, 'IPv4 link-local addresses are denied');
});

test('explains how to allow a blocked private origin', async (context) => {
  const proxy = createPolicyProxy({ configPath: '/extension/config.json' });
  const proxyAddress = await proxy.listen();
  context.after(() => proxy.close());
  const proxyPort = Number(proxyAddress.split(':').at(-1));
  const response = await new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port: proxyPort, path: 'http://192.168.1.21:3100/app' }, resolve).once('error', reject);
  });
  response.setEncoding('utf8');
  let body = '';
  for await (const chunk of response) body += chunk;

  assert.equal(response.statusCode, 403);
  assert.match(response.headers['content-type'], /^text\/html/);
  assert.match(response.headers['content-security-policy'], /default-src 'none'/);
  assert.match(body, /<title>Blocked: http:\/\/192\.168\.1\.21:3100<\/title>/);
  assert.ok(body.includes('<code>/extension/config.json</code>'));
  assert.ok(body.includes('[&#34;http://192.168.1.21:3100&#34;]'));
});

test('closes an HTTP upstream when its browser connection aborts', async (context) => {
  const upstreamAccepted = Promise.withResolvers();
  const upstreamClosed = Promise.withResolvers();
  const upstream = http.createServer(() => {});
  upstream.on('connection', (socket) => {
    upstreamAccepted.resolve();
    socket.once('close', () => upstreamClosed.resolve());
  });
  const upstreamPort = await listen(upstream);
  context.after(() => close(upstream));
  const proxy = createPolicyProxy({ grants: [{ host: '127.0.0.1', port: upstreamPort, protocol: 'http:' }] });
  const proxyAddress = await proxy.listen();
  context.after(() => proxy.close());
  const proxyPort = Number(proxyAddress.split(':').at(-1));
  const request = http.request({
    host: '127.0.0.1', port: proxyPort, method: 'GET',
    path: `http://127.0.0.1:${upstreamPort}/never-finishes`,
  });
  request.on('error', () => {});
  request.end();

  await upstreamAccepted.promise;
  request.destroy();

  await upstreamClosed.promise;
  assert.equal(request.destroyed, true);
});

test('does not open an upstream after the browser aborts during DNS lookup', async (context) => {
  const lookupStarted = Promise.withResolvers();
  const lookupResult = Promise.withResolvers();
  let upstreamConnections = 0;
  const upstream = net.createServer((socket) => {
    upstreamConnections += 1;
    socket.destroy();
  });
  const upstreamPort = await listen(upstream);
  context.after(() => close(upstream));
  const proxy = createPolicyProxy({
    grants: [{ host: 'deferred.test', port: upstreamPort, protocol: 'http:' }],
    lookup: async () => {
      lookupStarted.resolve();
      return lookupResult.promise;
    },
  });
  const proxyAddress = await proxy.listen();
  context.after(() => proxy.close());
  const proxyPort = Number(proxyAddress.split(':').at(-1));
  const request = http.request({
    host: '127.0.0.1', port: proxyPort, method: 'GET',
    path: `http://deferred.test:${upstreamPort}/deferred`,
  });
  request.on('error', () => {});
  request.end();

  await lookupStarted.promise;
  const requestClosed = new Promise((resolve) => request.once('close', resolve));
  request.destroy();
  await requestClosed;
  await new Promise((resolve) => setImmediate(resolve));
  lookupResult.resolve([{ address: '127.0.0.1', family: 4 }]);
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(upstreamConnections, 0);
});

test('closes a CONNECT upstream when its browser socket closes', async (context) => {
  const upstreamAccepted = Promise.withResolvers();
  const upstreamClosed = Promise.withResolvers();
  const upstream = net.createServer((socket) => {
    upstreamAccepted.resolve();
    socket.once('close', () => upstreamClosed.resolve());
  });
  const upstreamPort = await listen(upstream);
  context.after(() => close(upstream));
  const proxy = createPolicyProxy({ grants: [{ host: '127.0.0.1', port: upstreamPort, protocol: 'https:' }] });
  const proxyAddress = await proxy.listen();
  context.after(() => proxy.close());
  const proxyPort = Number(proxyAddress.split(':').at(-1));
  const client = net.connect({ host: '127.0.0.1', port: proxyPort });
  const connected = Promise.withResolvers();
  client.on('data', (chunk) => {
    if (chunk.toString().includes('200 Connection Established')) connected.resolve();
  });
  client.write(`CONNECT 127.0.0.1:${upstreamPort} HTTP/1.1\r\nHost: 127.0.0.1:${upstreamPort}\r\n\r\n`);

  await upstreamAccepted.promise;
  await connected.promise;
  client.destroy();

  await upstreamClosed.promise;
  assert.equal(client.destroyed, true);
});

test('survives repeated CONNECT aborts while the upstream is writing', { timeout: 10_000 }, async (context) => {
  const fixture = new URL('./fixtures/policy-proxy-epipe.js', import.meta.url);
  const child = spawn(process.execPath, [fixture.pathname], { stdio: ['ignore', 'pipe', 'pipe'] });
  context.after(() => {
    if (child.exitCode === null) child.kill();
  });
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', (chunk) => { stdout += chunk; });
  child.stderr.on('data', (chunk) => { stderr += chunk; });

  const code = await new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', resolve);
  });

  assert.equal(code, 0, stderr);
  assert.match(stdout, /completed without uncaught socket error/);
});


test('grants discovered development servers on loopback and asks for them only when needed', async () => {
  // Given a dev server on IPv4 5173 and another only on IPv6 4321.
  const scans = [];
  const devServerGrants = async () => {
    scans.push('scan');
    return [{ host: '127.0.0.1', port: 5173 }, { host: '::1', port: 4321 }];
  };
  const bothFamilies = async () => [{ address: '::1', family: 6 }, { address: '127.0.0.1', family: 4 }];

  // When a public site loads, then nothing is scanned.
  const publicSite = await classifyProxyTarget('https://example.test/', {
    devServerGrants,
    lookup: async () => [{ address: '93.184.216.34', family: 4 }],
  });
  assert.equal(publicSite.allowed, true);
  assert.deepEqual(scans, []);

  // When localhost is requested, then it pins to whichever loopback family has the server.
  const vite = await classifyProxyTarget('http://localhost:5173/', { devServerGrants, lookup: bothFamilies });
  const ipv6Only = await classifyProxyTarget('http://localhost:4321/', { devServerGrants, lookup: bothFamilies });
  const undiscovered = await classifyProxyTarget('http://127.0.0.1:37737/', { devServerGrants });
  assert.deepEqual([vite.allowed, vite.address], [true, '127.0.0.1']);
  assert.deepEqual([ipv6Only.allowed, ipv6Only.address], [true, '::1']);
  assert.equal(undiscovered.allowed, false);
});

test('matches host grants against the requested name, never the address it resolves to', async () => {
  // Given a loopback server granted by address, and a domain that resolves or rebinds to it.
  const origin = { grants: [{ host: '127.0.0.1', port: 5173, protocol: 'http:' }] };
  const discovery = { devServerGrants: async () => [{ host: '127.0.0.1', port: 5173 }] };
  const lookup = async () => [{ address: '127.0.0.1', family: 4 }];

  for (const policy of [origin, discovery]) {
    // When a page asks for the domain, then it stays blocked like any other private target.
    const alias = await classifyProxyTarget('http://rebind.test:5173/', { ...policy, lookup });
    assert.deepEqual([alias.allowed, alias.reason], [false, 'Private or loopback address requires an allowed origin']);

    // When it names the address, or localhost, which the proxy resolves itself, then the grant applies.
    const literal = await classifyProxyTarget('http://127.0.0.1:5173/', policy);
    const localhost = await classifyProxyTarget('http://localhost:5173/', { ...policy, lookup });
    assert.deepEqual([literal.allowed, localhost.allowed, localhost.address], [true, true, '127.0.0.1']);
  }

  // When a name resolves into a listed network block, then the block still allows it by address.
  const block = new net.BlockList();
  block.addSubnet('192.168.1.0', 24, 'ipv4');
  const nas = await classifyProxyTarget('http://nas.test:3100/', {
    grants: [{ block, ports: [[3000, 3200]] }],
    lookup: async () => [{ address: '192.168.1.20', family: 4 }],
  });
  assert.equal(nas.allowed, true);
});

test('points a blocked loopback address at development-server discovery', async (context) => {
  for (const [devServerGrants, expected] of [[null, /"discoverDevServers": true/], [async () => [], /discovery is on/]]) {
    const proxy = createPolicyProxy({ devServerGrants });
    const proxyAddress = await proxy.listen();
    context.after(() => proxy.close());
    const response = await new Promise((resolve, reject) => {
      http.get({ host: '127.0.0.1', port: Number(proxyAddress.split(':').at(-1)), path: 'http://127.0.0.1:3999/' }, resolve).once('error', reject);
    });
    response.setEncoding('utf8');
    let body = '';
    for await (const chunk of response) body += chunk;
    assert.match(body, expected);
  }
});