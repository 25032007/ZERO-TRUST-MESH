/**
 * `npm run demo` — start the mesh in-process, run every attack scenario through
 * the real pipeline, and print a table. Exit code 1 if any defence failed.
 */
import { loadConfig } from '../src/config.js';
import { createApp } from '../src/server.js';
import { runAll } from '../src/simulator/attacks.js';

const app = await createApp(loadConfig({ ...process.env, PORT: '0' }));
const port = await app.listen(0);
const results = await runAll({ mesh: app.mesh, clients: app.clients, baseUrl: () => `http://127.0.0.1:${port}` });

const pad = (s: string, n: number) => (s.length > n ? s.slice(0, n - 1) + '…' : s.padEnd(n));
console.log(`\n${pad('SCENARIO', 30)} ${pad('RESULT', 7)} OBSERVED (decision / reason / risk)`);
console.log('-'.repeat(100));
for (const r of results) {
  const observed = r.steps.map((s) => `${s.decision}/${s.reason}/${s.riskScore ?? '-'}`).join('  →  ');
  console.log(`${pad(r.title, 30)} ${pad(r.passed ? 'PASS' : 'FAIL', 7)} ${observed}`);
}
const failed = results.filter((r) => !r.passed).length;
console.log(`\n${results.length - failed}/${results.length} scenarios behaved as expected`);

await app.close();
process.exit(failed === 0 ? 0 : 1);
