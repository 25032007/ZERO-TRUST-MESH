import { loadConfig } from '../config.js';
import { createMesh } from '../mesh.js';
import { DEFAULT_POLICIES } from '../policy/policyEngine.js';
import type { ServiceClient } from '../identity/serviceClient.js';
import { type EvalEvent, type Episode, LEGIT_WORKFLOW } from './trafficGenerator.js';
import { type Outcome } from './metrics.js';

export interface DetectorConfig {
  name: string;
  rate: 'fixed' | 'baseline';
  payloadZ: boolean;
  workflows: boolean;
  params?: {
    alpha?: number;
    zWarn?: number;
    spikeHighPoints?: number;
    zScorePoints?: number;
  };
}

export async function runDetector(
  detectorConfig: DetectorConfig,
  traffic: { events: EvalEvent[]; episodes: Episode[] },
  clients: Map<string, ServiceClient>
): Promise<{ outcomes: Outcome[]; episodes: Episode[] }> {
  // Start at 10:00 UTC (inside business hours)
  let currentTimeMs = Date.UTC(2026, 0, 15, 10, 0, 0);
  const clock = () => currentTimeMs;

  const config = loadConfig({
    RATE_LIMIT_MAX_REQUESTS: '10000000', // essentially disabled
    QUARANTINE_MS: '1', // effectively off so FPR and recall measure judgement
    RISK_MODE: detectorConfig.rate
  });

  if (detectorConfig.params) {
    if (detectorConfig.params.alpha !== undefined) config.baseline.alpha = detectorConfig.params.alpha;
    if (detectorConfig.params.zWarn !== undefined) config.baseline.zWarn = detectorConfig.params.zWarn;
    if (detectorConfig.params.spikeHighPoints !== undefined) config.points.rateSpikeHigh = detectorConfig.params.spikeHighPoints;
    if (detectorConfig.params.zScorePoints !== undefined) config.payload.zScorePoints = detectorConfig.params.zScorePoints;
  }
  
  if (!detectorConfig.payloadZ) {
    config.payload.zScorePoints = 0;
  }

  const mesh = createMesh(config, { clock, policies: DEFAULT_POLICIES });

  for (const client of clients.values()) {
    await mesh.registry.register({
      serviceId: client.serviceId,
      displayName: client.serviceId,
      publicJwk: client.publicJwk,
      kid: client.kid,
    });
  }

  if (detectorConfig.workflows) {
    mesh.policies.setAllowedWorkflows([LEGIT_WORKFLOW]);
  }

  const outcomes: Outcome[] = [];
  const tokens = new Map<number, string>();

  for (const event of traffic.events) {
    // Advance clock to event timestamp
    currentTimeMs = Date.UTC(2026, 0, 15, 10, 0, 0) + event.t;
    const nowSec = Math.floor(currentTimeMs / 1000);

    const client = clients.get(event.source);
    let token = '';

    if (client) {
      if (event.tokenKind === 'replay' && event.replayOf !== undefined) {
        token = tokens.get(event.replayOf) || '';
      } else {
        token = await client.signToken({ nowSec, lifetimeSec: 60 });
        if (event.tokenKind === 'tampered') {
          const parts = token.split('.');
          const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
          payload.exp += 3600;
          parts[1] = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
          token = parts.join('.');
        }
      }
      tokens.set(event.id, token);
    }

    const res = await mesh.pipeline.evaluate({
      requestId: `req-${event.id}`,
      traceId: event.traceId,
      ip: event.ip,
      method: event.method,
      path: event.path,
      destination: event.destination,
      claimedService: event.source,
      authorization: token ? `Bearer ${token}` : undefined,
      body: event.body,
      payloadBytes: event.payloadBytes,
    });

    outcomes.push({
      event,
      decision: res.decision,
      reason: res.reason,
      riskScore: res.riskScore,
    });
  }

  return { outcomes, episodes: traffic.episodes };
}
