/**
 * Demo mesh bootstrap: creates an identity for each of the five demo services
 * and registers their PUBLIC keys with the proxy.
 *
 * The returned ServiceClient objects hold the PRIVATE keys and play the role of
 * "the services themselves" for the simulator, the benchmark and the tests. In a
 * real deployment each service would generate its own key and only send us the
 * public half through the admin API.
 */
import { ServiceClient } from './identity/serviceClient.js';
import type { Mesh } from './mesh.js';

export const DEMO_SERVICES: Array<{ id: string; name: string }> = [
  { id: 'frontend-service', name: 'Frontend' },
  { id: 'orders-service', name: 'Orders' },
  { id: 'payments-service', name: 'Payments' },
  { id: 'users-service', name: 'Users' },
  { id: 'auth-service', name: 'Auth' },
  { id: 'database-service', name: 'Database' },
];

export async function createDemoMesh(mesh: Mesh): Promise<Map<string, ServiceClient>> {
  const clients = new Map<string, ServiceClient>();
  for (const svc of DEMO_SERVICES) {
    const client = await ServiceClient.create(svc.id, { audience: mesh.config.audience });
    await mesh.registry.register({ serviceId: svc.id, displayName: svc.name, publicJwk: client.publicJwk, kid: client.kid });
    clients.set(svc.id, client);
  }
  return clients;
}
