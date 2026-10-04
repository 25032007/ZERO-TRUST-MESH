import assert from 'node:assert/strict';
import test from 'node:test';
import { INTERNAL_HEADER, INTERNAL_SECRET, createDownstreamRouter } from '../src/downstream/mockServices.js';
import { createApp } from '../src/server.js';
import { loadConfig } from '../src/config.js';
import { ServiceClient } from '../src/identity/serviceClient.js';

function buildTopology(n: number): { edges: [string, string][] } {
  const edges: [string, string][] = [];
  let next = 1;
  const queue: number[] = [0];
  while (next < n && queue.length > 0) {
    const parent = queue.shift()!;
    for (let child = 0; child < 2 && next < n; child++, next++) {
      edges.push([`svc-${parent}`, `svc-${next}`]);
      queue.push(next);
    }
  }
  return { edges };
}

test('load test topology builds connected tree for N services', () => {
  const { edges } = buildTopology(20);
  assert.equal(edges.length, 19, 'a tree of 20 nodes has exactly 19 edges');
  assert.equal(edges[0][0], 'svc-0');
  assert.equal(edges[0][1], 'svc-1');

  const seen = new Set<string>(['svc-0']);
  for (const [src, dst] of edges) {
    assert.ok(seen.has(src), `source ${src} must already be in the tree`);
    seen.add(dst);
  }
  assert.equal(seen.size, 20, 'all 20 services are part of the tree');
});

test('downstream router provides generic fallback for dynamic services with internal secret', async () => {
  const app = await createApp(loadConfig({ ADMIN_API_KEY: 'test-admin' }));
  const port = await app.listen(0);

  try {
    // 1. Direct call without internal secret is rejected (security invariant)
    const directNoSecret = await fetch(`http://127.0.0.1:${port}/downstream/svc-99/custom-path`);
    assert.equal(directNoSecret.status, 403);

    // 2. Direct call with internal secret succeeds with generic response
    const directWithSecret = await fetch(`http://127.0.0.1:${port}/downstream/svc-99/custom-path`, {
      headers: {
        [INTERNAL_HEADER]: INTERNAL_SECRET,
        'x-zt-source': 'svc-0',
      },
    });
    assert.equal(directWithSecret.status, 200);
    const body = (await directWithSecret.json()) as { service: string; receivedFrom: string; ok: boolean; action: string };
    assert.equal(body.service, 'svc-99');
    assert.equal(body.receivedFrom, 'svc-0');
    assert.equal(body.ok, true);
    assert.equal(body.action, 'GET /custom-path');
  } finally {
    await app.close();
  }
});
