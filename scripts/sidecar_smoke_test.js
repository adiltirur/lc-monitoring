#!/usr/bin/env node
// Read-only smoke test for the Principa SideCar reporting DB (production — never writes).
//
//   node scripts/sidecar_smoke_test.js            # via an SSM tunnel through 10.0.13.173 (from this Mac)
//
// Needs SIDECAR_DB_USER / SIDECAR_DB_PASSWORD in helper/.env (see .env.example), the AWS CLI
// with session-manager-plugin, and SSM access to lc-core-serverpod-staging.
// Exit codes: 0 ok · 2 credentials missing · 3 tunnel / source host · 4 timeout (network path)
//             5 authentication (read-only user) · 6 other error
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const sidecar = require('../lib/sidecar');

const EXIT = { NO_CREDS: 2, WRONG_SOURCE: 3, TUNNEL: 3, PORT_BUSY: 3, TIMEOUT: 4, AUTH: 5 };

function out(line = '') { process.stdout.write(line + '\n'); }

async function main() {
  const c = sidecar.cfg();
  out(`SideCar ${c.host}:${c.port}/${c.database} (sslmode=${c.sslmode}) via SSM through ${c.instanceTag} (${c.sourceIp}) → 127.0.0.1:${c.localPort}`);
  const missing = sidecar.missingCreds();
  if (missing.length) {
    out(`\n✗ Missing ${missing.join(' and ')} in helper/.env — waiting on read-only credentials from Planorg.`);
    out('\nOnce they exist, the equivalent psql one-liner (run on 10.0.13.173):');
    out(`  ${sidecar.psqlOneLiners().onHost}`);
    return EXIT.NO_CREDS;
  }
  let client;
  try {
    out('… opening SSM tunnel');
    await sidecar.openTunnel();
    out(`… connecting (timeout 10 s, default_transaction_read_only=on)`);
    client = await sidecar.connect();
    const r = await sidecar.smokeTest(client);
    out(`\n✓ Connected as ${r.user} to ${r.database} (${r.ssl ? 'TLS' : 'no TLS'}, read-only session)`);
    out(`  ${r.version}`);
    out(`\n${r.tables.length} tables/views visible${r.truncated ? ' (first 5000)' : ''}:`);
    const w = Math.max(10, ...r.tables.map(t => `${t.schema}.${t.table}`.length));
    for (const t of r.tables) out(`  ${`${t.schema}.${t.table}`.padEnd(w)}  ${String(t.type).padEnd(10)}  ~${t.approx_rows ?? '?'} rows`);
    out('\npsql one-liners:');
    out(`  on 10.0.13.173:  ${sidecar.psqlOneLiners().onHost}`);
    out(`  via the tunnel:  ${sidecar.psqlOneLiners().viaTunnel}`);
    return 0;
  } catch (e) {
    out(`\n✗ ${e.message}`);
    if (e.cause_hint) out(`  Likely cause: ${e.cause_hint}`);
    return EXIT[e.code] || 6;
  } finally {
    if (client) await client.end().catch(() => {});
    sidecar.closeTunnel();
  }
}

main().then(code => process.exit(code), (e) => { out(`✗ ${e.message}`); process.exit(6); });
