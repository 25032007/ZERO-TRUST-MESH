import assert from 'node:assert/strict';
import { test } from 'node:test';
import { PairBaseline, type BaselineParams } from '../src/risk/baseline.js';

const W = 5000;
const params = (over: Partial<BaselineParams> = {}): BaselineParams => ({
  windowMs: W, alpha: 0.2, minWindows: 6, minSpikeCount: 10, minRelativeStd: 0.25, clampZ: 3, zWarn: 3, zHigh: 6, ...over,
});

/**
 * Feed `perWindow` requests into each of `windows` consecutive windows, starting at
 * window `from`. Requests are spread evenly INSIDE the window so a large count can
 * never spill into the next one.
 */
function feed(b: PairBaseline, pair: string, from: number, windows: number, perWindow: number) {
  let last;
  for (let w = 0; w < windows; w++) {
    for (let i = 0; i < perWindow; i++) last = b.observe(pair, (from + w) * W + Math.floor((i * W) / perWindow));
  }
  return last!;
}

test('nothing is scored while learning (warm-up), even for a huge first burst', () => {
  const b = new PairBaseline(params());
  const r = feed(b, 'a->b', 0, 1, 500);
  assert.equal(r.warm, false);
  assert.equal(r.level, 'none');
});

test('steady traffic never alarms after warm-up', () => {
  const b = new PairBaseline(params());
  feed(b, 'a->b', 0, 10, 20);
  const r = feed(b, 'a->b', 10, 1, 22); // normal wobble
  assert.equal(r.warm, true);
  assert.equal(r.level, 'none');
});

test('a sudden spike far above the pair\'s own baseline is flagged high', () => {
  const b = new PairBaseline(params());
  feed(b, 'a->b', 0, 10, 20);
  const r = feed(b, 'a->b', 10, 1, 120);
  assert.equal(r.level, 'high');
  assert.ok(r.z >= 6);
});

test('the SAME count is normal on a busy edge and an attack on a quiet one (per-pair baselines)', () => {
  const b = new PairBaseline(params());
  feed(b, 'busy->x', 0, 10, 100);
  feed(b, 'quiet->x', 0, 10, 5);
  assert.equal(feed(b, 'busy->x', 10, 1, 110).level, 'none');
  assert.notEqual(feed(b, 'quiet->x', 10, 1, 110).level, 'none');
});

test('tiny absolute counts never count as a spike (minSpikeCount guard)', () => {
  const b = new PairBaseline(params());
  feed(b, 'a->b', 0, 10, 1);
  const r = feed(b, 'a->b', 10, 1, 8); // 8x the mean, but only 8 requests
  assert.ok(r.z > 6);
  assert.equal(r.level, 'none');
});

test('silent windows lower the baseline instead of being ignored', () => {
  const b = new PairBaseline(params());
  feed(b, 'a->b', 0, 8, 30);
  const before = b.peek('a->b')!.mean;
  b.observe('a->b', 40 * W); // 32 silent windows later
  assert.ok(b.peek('a->b')!.mean < before / 2);
});

test('winsorised learning: one huge window cannot drag the baseline up by much', () => {
  const clamped = new PairBaseline(params());
  const naive = new PairBaseline(params({ clampZ: 1e9 }));
  for (const b of [clamped, naive]) {
    feed(b, 'a->b', 0, 10, 20);
    feed(b, 'a->b', 10, 1, 2000); // attack window
    b.observe('a->b', 12 * W); // close the attack window
  }
  assert.ok(clamped.peek('a->b')!.mean < 40, `clamped mean ${clamped.peek('a->b')!.mean}`);
  assert.ok(naive.peek('a->b')!.mean > 300, `naive mean ${naive.peek('a->b')!.mean}`);
});

test('state is bounded and pairs are independent', () => {
  const b = new PairBaseline(params());
  feed(b, 'a->b', 0, 10, 20);
  assert.equal(b.peek('c->d'), undefined);
  assert.equal(feed(b, 'c->d', 0, 1, 50).level, 'none'); // c->d is still warming up
});
