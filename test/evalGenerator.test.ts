import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Rng } from '../src/eval/rng.js';
import { BEHAVIORAL_ATTACKS, HARD_FAIL_ATTACKS, generateTraffic } from '../src/eval/trafficGenerator.js';

const opts = { seed: 7, durationMs: 600_000, loadScale: 1 };

test('Rng is deterministic per seed and differs across seeds', () => {
  const a = new Rng(1), b = new Rng(1), c = new Rng(2);
  const sa = Array.from({ length: 5 }, () => a.next());
  assert.deepEqual(sa, Array.from({ length: 5 }, () => b.next()));
  assert.notDeepEqual(sa, Array.from({ length: 5 }, () => c.next()));
  assert.ok(sa.every((x) => x >= 0 && x < 1));
});

test('Rng.poisson has roughly the requested mean, lognormal the requested median', () => {
  const r = new Rng(3);
  const n = 20000;
  const mean = Array.from({ length: n }, () => r.poisson(4)).reduce((a, b) => a + b, 0) / n;
  assert.ok(Math.abs(mean - 4) < 0.15, `poisson mean ${mean}`);
  const big = Array.from({ length: n }, () => r.poisson(100)).reduce((a, b) => a + b, 0) / n;
  assert.ok(Math.abs(big - 100) < 1, `large-lambda mean ${big}`);
  const sorted = Array.from({ length: n }, () => r.lognormal(450, 0.4)).sort((a, b) => a - b);
  assert.ok(Math.abs(sorted[n / 2] - 450) < 20, `median ${sorted[n / 2]}`);
});

test('the same seed generates identical traffic; a different seed does not', () => {
  const a = generateTraffic(opts).events;
  const b = generateTraffic(opts).events;
  assert.equal(a.length, b.length);
  assert.deepEqual(a.slice(0, 50), b.slice(0, 50));
  assert.notEqual(generateTraffic({ ...opts, seed: 8 }).events.length, a.length);
});

test('events are time ordered, ids are unique, and every event has a label', () => {
  const { events } = generateTraffic(opts);
  for (let i = 1; i < events.length; i++) assert.ok(events[i].t >= events[i - 1].t);
  assert.equal(new Set(events.map((e) => e.id)).size, events.length);
  assert.ok(events.every((e) => e.label === 'normal' || [...BEHAVIORAL_ATTACKS, ...HARD_FAIL_ATTACKS].includes(e.label)));
});

test('every attack class is present, with episodes, and normal traffic dominates', () => {
  const { events, episodes } = generateTraffic(opts);
  for (const cls of [...BEHAVIORAL_ATTACKS, ...HARD_FAIL_ATTACKS]) {
    assert.ok(events.some((e) => e.label === cls), `no events for ${cls}`);
    assert.ok(episodes.some((e) => e.cls === cls), `no episode for ${cls}`);
  }
  const normal = events.filter((e) => e.label === 'normal').length;
  assert.ok(normal > events.length * 0.4);
  assert.ok(events.filter((e) => e.episode !== undefined).every((e) => e.label !== 'normal' || e.tokenKind === 'valid'));
});

test('replay events point at an EARLIER normal event from the same service (regression: replayOf id)', () => {
  const { events } = generateTraffic(opts);
  const byId = new Map(events.map((e) => [e.id, e]));
  const replays = events.filter((e) => e.tokenKind === 'replay');
  assert.ok(replays.length >= 6);
  for (const r of replays) {
    const orig = byId.get(r.replayOf!)!;
    assert.ok(orig, 'replayOf must reference an existing event');
    assert.equal(orig.label, 'normal');
    assert.equal(orig.source, r.source);
    assert.ok(orig.t < r.t && r.t - orig.t < 60_000, 'original must be recent enough for its token to still be valid');
  }
});

test('lateral episodes use three distinct allowed edges; the slow variant is spread over 8 s, the fast one inside 1 s', () => {
  const { events, episodes } = generateTraffic(opts);
  for (const cls of ['lateral-chain', 'lateral-slow'] as const) {
    for (const ep of episodes.filter((e) => e.cls === cls)) {
      const hops = events.filter((e) => e.episode === ep.id);
      assert.equal(hops.length, 3);
      assert.equal(new Set(hops.map((h) => h.traceId)).size, 1);
      assert.equal(new Set(hops.map((h) => `${h.source}>${h.destination}`)).size, 3);
      const span = hops[2].t - hops[0].t;
      if (cls === 'lateral-chain') assert.ok(span < 1000);
      else assert.ok(span >= 7000);
    }
  }
});

test('normal traffic contains legitimate 3-hop chains and batch ramps (the false-positive traps)', () => {
  const { events } = generateTraffic(opts);
  const traces = new Map<string, string[]>();
  for (const e of events.filter((x) => x.label === 'normal' && x.traceId.startsWith('chain-'))) traces.set(e.traceId, [...(traces.get(e.traceId) ?? []), e.source]);
  assert.ok(traces.size > 20, `only ${traces.size} legit chains`);
  assert.ok([...traces.values()].every((s) => s.length === 3));

  // the batch job makes orders->users busier at some point than its base rate would allow
  const perWindow = new Map<number, number>();
  for (const e of events.filter((x) => x.label === 'normal' && x.source === 'orders-service' && x.destination === 'users-service')) perWindow.set(Math.floor(e.t / 5000), (perWindow.get(Math.floor(e.t / 5000)) ?? 0) + 1);
  assert.ok(Math.max(...perWindow.values()) > 15, 'batch ramp not visible');
});

test('loadScale multiplies normal traffic', () => {
  const normal = (s: number) => generateTraffic({ ...opts, loadScale: s }).events.filter((e) => e.label === 'normal').length;
  const ratio = normal(3) / normal(1);
  assert.ok(ratio > 2.6 && ratio < 3.4, `ratio ${ratio}`);
});
