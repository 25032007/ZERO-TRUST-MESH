/**
 * Labeled traffic generator for evaluating the detector.
 *
 * It produces a time-ordered list of requests where EVERY request carries a
 * ground-truth label: 'normal' or the attack class that created it. Running the
 * real pipeline over this list yields precision / recall / false-positive rate.
 *
 * IMPORTANT — what this is and is not
 *   This is SYNTHETIC traffic written by the same person who wrote the detector.
 *   It cannot prove real-world accuracy. What it CAN do honestly:
 *     • compare detector variants on IDENTICAL traffic (before/after, ablations),
 *     • tune on one random seed and report on DIFFERENT seeds (no peeking),
 *     • expose weaknesses (some attacks are included precisely because the
 *       detector is expected to miss them: see `lateral-slow`).
 *
 * "Normal" deliberately contains the things that make detectors raise false alarms:
 *   • daily-rhythm load modulation and Poisson noise,
 *   • heavy-tailed payload sizes (occasional legitimately big requests),
 *   • legitimate batch jobs that multiply one edge's traffic several-fold,
 *   • legitimate deep call chains (frontend → orders → payments → database).
 */
import { Rng } from './rng.js';

export type AttackClass =
  | 'rate-flood'
  | 'rate-slow-ramp'
  | 'payload-anomaly'
  | 'lateral-chain'
  | 'lateral-slow'
  | 'unauthorized-edge'
  | 'token-tampering'
  | 'token-replay';

/** Attacks that only behavioural signals can catch (the interesting ones). */
export const BEHAVIORAL_ATTACKS: AttackClass[] = ['rate-flood', 'rate-slow-ramp', 'payload-anomaly', 'lateral-chain', 'lateral-slow'];
/** Attacks that identity/policy checks reject deterministically. */
export const HARD_FAIL_ATTACKS: AttackClass[] = ['unauthorized-edge', 'token-tampering', 'token-replay'];

export interface EvalEvent {
  id: number;
  /** Milliseconds since the start of the simulation. */
  t: number;
  source: string;
  destination: string;
  method: string;
  path: string;
  payloadBytes: number;
  /** Optional body (only used when its SHAPE matters). */
  body?: unknown;
  ip: string;
  traceId: string;
  label: 'normal' | AttackClass;
  /** Attack episode this event belongs to (one flood, one chain, ...). */
  episode?: number;
  /** 'tampered': edit the signed token; 'replay': re-send the token used by event `replayOf`. */
  tokenKind: 'valid' | 'tampered' | 'replay';
  replayOf?: number;
}

export interface Episode {
  id: number;
  cls: AttackClass;
  startT: number;
  endT: number;
}

export interface TrafficOptions {
  seed: number;
  durationMs: number;
  /** Multiplies every normal edge's rate (use >1 to simulate a busier system). */
  loadScale: number;
}

interface EdgeSpec {
  source: string;
  destination: string;
  /** Requests per second at loadScale 1. */
  rate: number;
  /** Request variants: weight, method, path, median payload (0 = no body). */
  variants: Array<{ weight: number; method: string; path: string; medianBytes: number }>;
}

/** The normal workload. Chosen so the busiest source sends ~3.5 req/s (≈17 per 5 s window). */
const EDGES: EdgeSpec[] = [
  { source: 'frontend-service', destination: 'orders-service', rate: 3.0, variants: [
    { weight: 0.7, method: 'GET', path: '/orders/list', medianBytes: 0 },
    { weight: 0.3, method: 'POST', path: '/orders/create', medianBytes: 450 },
  ] },
  { source: 'frontend-service', destination: 'auth-service', rate: 0.5, variants: [{ weight: 1, method: 'POST', path: '/auth/login', medianBytes: 160 }] },
  { source: 'orders-service', destination: 'payments-service', rate: 0.8, variants: [{ weight: 1, method: 'POST', path: '/payments/charge', medianBytes: 220 }] },
  { source: 'orders-service', destination: 'users-service', rate: 1.2, variants: [{ weight: 1, method: 'GET', path: '/users/me', medianBytes: 0 }] },
  { source: 'auth-service', destination: 'users-service', rate: 0.5, variants: [{ weight: 1, method: 'GET', path: '/users/lookup', medianBytes: 0 }] },
  { source: 'payments-service', destination: 'database-service', rate: 0.8, variants: [{ weight: 1, method: 'POST', path: '/database/query', medianBytes: 300 }] },
];

/** The one legitimate multi-hop workflow (declared in the evaluation's policy set). */
export const LEGIT_WORKFLOW = ['frontend-service', 'orders-service', 'payments-service', 'database-service'];

const SERVICE_IP: Record<string, string> = {
  'frontend-service': '10.0.0.1',
  'orders-service': '10.0.0.2',
  'payments-service': '10.0.0.3',
  'users-service': '10.0.0.4',
  'auth-service': '10.0.0.5',
  'database-service': '10.0.0.6',
};
const ATTACKER_IP = '203.0.113.7';

export function generateTraffic(opts: TrafficOptions): { events: EvalEvent[]; episodes: Episode[] } {
  const rng = new Rng(opts.seed);
  const dur = opts.durationMs;
  const events: Omit<EvalEvent, 'id'>[] = [];
  const episodes: Episode[] = [];
  let traceCounter = 0;
  const trace = (prefix: string) => `${prefix}-${opts.seed}-${traceCounter++}`;

  // ── Normal traffic ───────────────────────────────────────────────────────
  // Two legitimate batch jobs: one edge's traffic ramps to 4x, holds, ramps down.
  const batchStarts = [rng.range(0.15, 0.3) * dur, rng.range(0.6, 0.75) * dur];
  const batchFactor = (edge: EdgeSpec, t: number) => {
    if (edge.destination !== 'users-service' || edge.source !== 'orders-service') return 1;
    for (const start of batchStarts) {
      const x = t - start;
      if (x < 0 || x > 120_000) continue;
      if (x < 30_000) return 1 + 3 * (x / 30_000); // ramp up
      if (x < 90_000) return 4; // hold
      return 4 - 3 * ((x - 90_000) / 30_000); // ramp down
    }
    return 1;
  };

  for (const edge of EDGES) {
    for (let sec = 0; sec < dur / 1000; sec++) {
      const t0 = sec * 1000;
      // Gentle "daily rhythm": +-30% over a 10-minute cycle.
      const rhythm = 1 + 0.3 * Math.sin((2 * Math.PI * t0) / 600_000);
      const n = rng.poisson(edge.rate * opts.loadScale * rhythm * batchFactor(edge, t0));
      for (let i = 0; i < n; i++) {
        const r = rng.next();
        let acc = 0;
        let v = edge.variants[edge.variants.length - 1];
        for (const cand of edge.variants) {
          acc += cand.weight;
          if (r < acc) { v = cand; break; }
        }
        let bytes = v.medianBytes === 0 ? 0 : Math.round(rng.lognormal(v.medianBytes, 0.4));
        if (bytes > 0 && rng.next() < 0.015) bytes *= 6; // heavy tail: a legitimately big request
        events.push({
          t: t0 + rng.range(0, 1000),
          source: edge.source, destination: edge.destination, method: v.method, path: v.path,
          payloadBytes: bytes, body: bytes > 0 ? { n: 1 } : undefined,
          ip: SERVICE_IP[edge.source], traceId: trace('n'), label: 'normal', tokenKind: 'valid',
        });
      }
    }
  }

  // Legitimate 3-hop chains: realistic per-hop processing time keeps the whole chain under a second.
  for (let sec = 5; sec < dur / 1000 - 2; sec++) {
    if (rng.next() > 0.12) continue; // ~0.12 chains per second
    const id = trace('chain');
    let t = sec * 1000 + rng.range(0, 1000);
    const hops: Array<[number, string, string, string, string]> = [
      [0, 'frontend-service', 'orders-service', 'GET', '/orders/list'],
      [1, 'orders-service', 'payments-service', 'POST', '/payments/charge'],
      [2, 'payments-service', 'database-service', 'POST', '/database/query'],
    ];
    for (const [i, src, dst, method, path] of hops) {
      if (i > 0) t += rng.range(100, 250);
      events.push({ t, source: src, destination: dst, method, path, payloadBytes: method === 'GET' ? 0 : Math.round(rng.lognormal(250, 0.3)), body: method === 'GET' ? undefined : { n: 1 }, ip: SERVICE_IP[src], traceId: id, label: 'normal', tokenKind: 'valid' });
    }
  }

  // ── Attacks ──────────────────────────────────────────────────────────────
  const addEpisode = (cls: AttackClass, startT: number, endT: number) => {
    const id = episodes.length;
    episodes.push({ id, cls, startT, endT });
    return id;
  };

  // Place attacks in separate time zones so they do not overlap each other.
  const zone = (from: number, to: number) => rng.range(from, to) * dur;

  // rate-flood: compromised frontend hammers orders at 12x its normal edge rate for 40 s.
  {
    const start = zone(0.35, 0.42);
    const ep = addEpisode('rate-flood', start, start + 40_000);
    const extraRate = 12 * 3.0 * opts.loadScale;
    for (let sec = 0; sec < 40; sec++) {
      const n = rng.poisson(extraRate);
      for (let i = 0; i < n; i++) {
        events.push({ t: start + sec * 1000 + rng.range(0, 1000), source: 'frontend-service', destination: 'orders-service', method: 'GET', path: '/orders/list', payloadBytes: 0, ip: SERVICE_IP['frontend-service'], traceId: trace('a'), label: 'rate-flood', episode: ep, tokenKind: 'valid' });
      }
    }
  }

  // rate-slow-ramp: "boil the frog" — extra traffic climbs from 0 to 5x the edge rate over 4 minutes.
  {
    const start = zone(0.5, 0.52);
    const len = 240_000;
    const ep = addEpisode('rate-slow-ramp', start, start + len);
    for (let sec = 0; sec < len / 1000; sec++) {
      const extra = 5 * 3.0 * opts.loadScale * (sec / (len / 1000));
      const n = rng.poisson(extra);
      for (let i = 0; i < n; i++) {
        events.push({ t: start + sec * 1000 + rng.range(0, 1000), source: 'frontend-service', destination: 'orders-service', method: 'GET', path: '/orders/list', payloadBytes: 0, ip: SERVICE_IP['frontend-service'], traceId: trace('a'), label: 'rate-slow-ramp', episode: ep, tokenKind: 'valid' });
      }
    }
  }

  // payload-anomaly: 2 episodes of 20 oversized (but below the hard 100 KB rule) bodies, one every 3 s.
  for (const z of [zone(0.08, 0.12), zone(0.78, 0.84)]) {
    const ep = addEpisode('payload-anomaly', z, z + 60_000);
    for (let i = 0; i < 20; i++) {
      events.push({ t: z + i * 3000, source: 'frontend-service', destination: 'orders-service', method: 'POST', path: '/orders/create', payloadBytes: Math.round(rng.range(9_000, 15_000)), body: { n: 1 }, ip: SERVICE_IP['frontend-service'], traceId: trace('a'), label: 'payload-anomaly', episode: ep, tokenKind: 'valid' });
    }
  }

  // lateral-chain: undeclared 3-edge traversal inside ~600 ms (4 episodes).
  for (let k = 0; k < 4; k++) {
    const z = zone(0.1 + k * 0.2, 0.15 + k * 0.2);
    const id = trace('pivot');
    const ep = addEpisode('lateral-chain', z, z + 600);
    const hops: Array<[string, string, string, string]> = [
      ['frontend-service', 'orders-service', 'GET', '/orders/list'],
      ['frontend-service', 'auth-service', 'POST', '/auth/login'],
      ['orders-service', 'users-service', 'GET', '/users/me'],
    ];
    hops.forEach(([src, dst, method, path], i) => {
      events.push({ t: z + i * 250, source: src, destination: dst, method, path, payloadBytes: method === 'GET' ? 0 : 160, body: method === 'GET' ? undefined : { n: 1 }, ip: SERVICE_IP[src], traceId: id, label: 'lateral-chain', episode: ep, tokenKind: 'valid' });
    });
  }

  // lateral-slow: the same traversal stretched over 8 s. Detector is EXPECTED to miss this (1 s window).
  for (let k = 0; k < 4; k++) {
    const z = zone(0.12 + k * 0.2, 0.17 + k * 0.2);
    const id = trace('slowpivot');
    const ep = addEpisode('lateral-slow', z, z + 8000);
    const hops: Array<[string, string, string, string]> = [
      ['frontend-service', 'orders-service', 'GET', '/orders/list'],
      ['frontend-service', 'auth-service', 'POST', '/auth/login'],
      ['orders-service', 'users-service', 'GET', '/users/me'],
    ];
    hops.forEach(([src, dst, method, path], i) => {
      events.push({ t: z + i * 4000, source: src, destination: dst, method, path, payloadBytes: method === 'GET' ? 0 : 160, body: method === 'GET' ? undefined : { n: 1 }, ip: SERVICE_IP[src], traceId: id, label: 'lateral-slow', episode: ep, tokenKind: 'valid' });
    });
  }

  // Hard-fail attacks from an external IP: 6 episodes each.
  for (let k = 0; k < 6; k++) {
    const z = zone(0.05 + k * 0.15, 0.1 + k * 0.15);
    const ep = addEpisode('unauthorized-edge', z, z + 5000);
    for (let i = 0; i < 5; i++) {
      events.push({ t: z + i * 1000, source: 'frontend-service', destination: 'database-service', method: 'POST', path: '/database/query', payloadBytes: 120, body: { n: 1 }, ip: ATTACKER_IP, traceId: trace('a'), label: 'unauthorized-edge', episode: ep, tokenKind: 'valid' });
    }
  }
  for (let k = 0; k < 6; k++) {
    const z = zone(0.07 + k * 0.15, 0.12 + k * 0.15);
    const ep = addEpisode('token-tampering', z, z + 3000);
    for (let i = 0; i < 3; i++) {
      events.push({ t: z + i * 1000, source: 'frontend-service', destination: 'orders-service', method: 'GET', path: '/orders/list', payloadBytes: 0, ip: ATTACKER_IP, traceId: trace('a'), label: 'token-tampering', episode: ep, tokenKind: 'tampered' });
    }
  }

  // Assign ids in time order, THEN add replay pairs (they need the id of their original).
  events.sort((a, b) => a.t - b.t);
  const withIds: EvalEvent[] = events.map((e, i) => ({ ...e, id: i }));

  const replays: Omit<EvalEvent, 'id'>[] = [];
  for (let k = 0; k < 6; k++) {
    const z = zone(0.06 + k * 0.15, 0.11 + k * 0.15);
    const ep = addEpisode('token-replay', z + 500, z + 1500);
    // The first use is legitimate traffic (label normal); the replay is the attack.
    const firstId = withIds.length + replays.length; // index the first event is about to get
    replays.push({ t: z, source: 'orders-service', destination: 'users-service', method: 'GET', path: '/users/me', payloadBytes: 0, ip: SERVICE_IP['orders-service'], traceId: trace('r'), label: 'normal', tokenKind: 'valid' });
    replays.push({ t: z + 500, source: 'orders-service', destination: 'users-service', method: 'GET', path: '/users/me', payloadBytes: 0, ip: ATTACKER_IP, traceId: trace('r'), label: 'token-replay', episode: ep, tokenKind: 'replay', replayOf: firstId });
  }
  const all = [...withIds, ...replays.map((e, i) => ({ ...e, id: withIds.length + i }))];
  all.sort((a, b) => a.t - b.t || a.id - b.id);
  return { events: all, episodes };
}
