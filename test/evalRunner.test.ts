import test from 'node:test';
import assert from 'node:assert';
import { generateTraffic, BEHAVIORAL_ATTACKS, HARD_FAIL_ATTACKS } from '../src/eval/trafficGenerator.js';
import { runDetector } from '../src/eval/runner.js';
import { computeMetrics } from '../src/eval/metrics.js';
import { createDemoMesh } from '../src/demoMesh.js';
import { loadConfig } from '../src/config.js';
import { createMesh } from '../src/mesh.js';

test('Eval runner', async (t) => {
  // Use a small 3-minute traffic snippet for tests
  const traffic = generateTraffic({ seed: 42, durationMs: 180_000, loadScale: 1.0 });
  const clock = () => Date.now();
  const config = loadConfig();
  const mesh = createMesh(config, { clock });
  const clients = await createDemoMesh(mesh);

  await t.test('identity/policy attacks get 100% recall', async () => {
    const res = await runDetector({ name: 'test', rate: 'baseline', payloadZ: false, workflows: true }, traffic, clients);
    const metrics = computeMetrics(res.outcomes, res.episodes);
    for (const attack of HARD_FAIL_ATTACKS) {
      assert.strictEqual(metrics.perClass[attack].eventRecall, 1, `${attack} recall should be 100%`);
    }
  });

  await t.test('replays are rejected and first use is not blocked', async () => {
    const res = await runDetector({ name: 'test', rate: 'baseline', payloadZ: false, workflows: true }, traffic, clients);
    const replays = res.outcomes.filter(o => o.event.tokenKind === 'replay');
    for (const r of replays) {
      assert.strictEqual(r.reason, 'TOKEN_REPLAY');
      const original = res.outcomes.find(o => o.event.id === r.event.replayOf);
      assert.ok(original);
      assert.notStrictEqual(original.reason, 'TOKEN_REPLAY');
    }
  });

  await t.test('lateral movement behavior with workflows OFF', async () => {
    const resOff = await runDetector({ name: 'test', rate: 'baseline', payloadZ: false, workflows: false }, traffic, clients);
    const fpOff = resOff.outcomes.filter(o => o.event.label === 'normal' && o.reason === 'LATERAL_MOVEMENT');
    assert.ok(fpOff.length > 6, `Should have many LATERAL_MOVEMENT false positives, found ${fpOff.length}`);
  });

  await t.test('lateral movement behavior with workflows ON', async () => {
    const resOn = await runDetector({ name: 'test', rate: 'baseline', payloadZ: false, workflows: true }, traffic, clients);
    const fpOn = resOn.outcomes.filter(o => o.event.label === 'normal' && o.reason === 'LATERAL_MOVEMENT');
    assert.strictEqual(fpOn.length, 0, `Should have 0 LATERAL_MOVEMENT false positives with workflows ON, found ${fpOn.length}`);
  });

  await t.test('lateral-slow is missed by detector', async () => {
    const res = await runDetector({ name: 'test', rate: 'baseline', payloadZ: false, workflows: true }, traffic, clients);
    const slowEvents = res.outcomes.filter(o => o.event.label === 'lateral-slow');
    const flagged = slowEvents.filter(o => o.decision !== 'ALLOW');
    assert.strictEqual(flagged.length, 0, `lateral-slow should be missed completely, but ${flagged.length} events were flagged`);
  });
});
