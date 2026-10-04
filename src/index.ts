/** Entry point: load config, build the app, listen, shut down cleanly. */
import { loadConfig } from './config.js';
import { createApp } from './server.js';

const config = loadConfig();
const app = await createApp(config);
const port = await app.listen(config.port);

console.log(`Zero-Trust Mesh listening on http://localhost:${port}`);
console.log(`  dashboard : http://localhost:${port}/`);
console.log(`  proxy     : http://localhost:${port}/api/proxy/<path>  (needs Bearer token)`);
if (config.adminKeyGenerated) {
  console.log(`  admin key : ${config.adminApiKey}   (generated for this run — set ADMIN_API_KEY to make it stable)`);
}
if (!config.publicDashboard) console.log('  dashboard is PRIVATE: send the admin key in the x-admin-key header');

// Graceful shutdown so in-flight requests finish (important for containers).
for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, async () => {
    console.log(`\n${signal} received, shutting down…`);
    await app.close();
    process.exit(0);
  });
}
