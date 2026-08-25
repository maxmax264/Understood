// Startup wrapper for running MeshCentral as a Render web service.
//
// Why this file exists: MeshCentral's config normally comes from a
// meshcentral-data/config.json file living on a persistent disk. Render's
// free tier has no persistent disk, so instead we pass everything it needs
// as CLI-style arguments built from Render environment variables, and point
// it at MongoDB Atlas for storage (which IS persistent, unlike Render's
// filesystem) - see README.md in this folder for the required env vars.

const requiredEnvVars = ['MONGO_URL'];
const missing = requiredEnvVars.filter((name) => !process.env[name]);
if (missing.length > 0) {
  console.error('[sionyx-remote-control] Missing required environment variable(s): ' + missing.join(', '));
  console.error('[sionyx-remote-control] Set these in the Render dashboard under Environment, then redeploy.');
  process.exit(1);
}

// Render assigns the port to listen on via process.env.PORT - MeshCentral
// must bind to exactly this port for Render's health checks to succeed.
const port = process.env.PORT || '443';

// Render terminates HTTPS at its own edge and proxies plain HTTP to us, so
// MeshCentral must NOT try to manage its own TLS certificate (it would fail
// - Render doesn't expose port 80/443 directly to the app for ACME
// challenges). --tlsoffload tells MeshCentral to trust the proxy and treat
// the connection as already secure.
const args = [
  '--port', port,
  '--mongodb', process.env.MONGO_URL,
  '--tlsoffload',
];

process.argv = [process.argv[0], process.argv[1], ...args];

console.log('[sionyx-remote-control] Starting MeshCentral on port ' + port + ' with MongoDB storage...');

require('meshcentral').mainStart();
