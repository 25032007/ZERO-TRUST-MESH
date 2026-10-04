/** Shared test helpers: a mesh with a controllable fake clock. */
import { loadConfig } from '../src/config.js';
import { createDemoMesh } from '../src/demoMesh.js';
import { createMesh } from '../src/mesh.js';

export function fakeClock(startMs = Date.UTC(2026, 0, 15, 12, 0, 0)) {
  let t = startMs;
  const clock = () => t;
  clock.advance = (ms: number) => void (t += ms);
  clock.set = (ms: number) => void (t = ms);
  return clock;
}

/** Fresh, isolated mesh + service identities for each test. */
export async function setup(envOverrides: Record<string, string> = {}) {
  const clock = fakeClock();
  const config = loadConfig({ ADMIN_API_KEY: 'test-key', ...envOverrides });
  const mesh = createMesh(config, { clock });
  const clients = await createDemoMesh(mesh);
  const nowSec = () => Math.floor(clock() / 1000);
  return { clock, config, mesh, clients, nowSec };
}

/** Build a PipelineInput with sensible defaults. */
export function input(over: Partial<import('../src/types.js').PipelineInput> = {}): import('../src/types.js').PipelineInput {
  return {
    requestId: Math.random().toString(36).slice(2),
    traceId: Math.random().toString(36).slice(2),
    ip: '10.0.0.1',
    method: 'GET',
    path: '/orders/list',
    destination: 'orders-service',
    body: undefined,
    payloadBytes: 0,
    ...over,
  };
}
