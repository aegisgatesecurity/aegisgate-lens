#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Mock Backend (Day 2 test harness)
// =========================================================================
//
// A minimal HTTP server that pretends to be the AegisGate Lens backend
// at https://lens.aegisgatesecurity.io. Used by the smoke test to verify
// the APIClient's full event-send path without a real network round-trip
// and without requiring a running Go backend.
//
// Endpoints (subset of the real backend):
//   GET  /api/v1/lens/healthz           -> 200 {"status":"ok","version":"0.0.0-mock"}
//   POST /api/v1/lens/telemetry         -> 200 {"accepted":true,"id":"<uuid>"}
//   GET  /api/v1/lens/stats             -> 200 {"events24h":N,"detections24h":M}
//   GET  /api/v1/lens/check?domain=...  -> 200 {"domain_hash":"...","has_iocs":false}
//
// Every POST to /telemetry is appended, one JSON object per line, to a
// JSONL file at test/mock-output/events.jsonl. The lens-cli telemetry-tail
// reads this file. Each line is also pretty-printed to stdout with a
// timestamp so a developer running `npm run mock` can watch the stream.
//
// Usage:
//   node test/mock-backend.mjs [--port 9999] [--output PATH]
//
// =========================================================================

'use strict';

import http from 'node:http';
import url from 'node:url';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

// ----- CLI args -------------------------------------------------------------

function parseArgs(argv) {
  const out = { port: 9999, output: 'test/mock-output/events.jsonl' };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--port' && argv[i + 1]) {
      out.port = parseInt(argv[i + 1], 10);
      i++;
    } else if (argv[i] === '--output' && argv[i + 1]) {
      out.output = argv[i + 1];
      i++;
    }
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));

// Ensure the output directory exists.
fs.mkdirSync(path.dirname(args.output), { recursive: true });
// Truncate the JSONL on startup so each run is fresh.
fs.writeFileSync(args.output, '');

// ----- In-memory counters ---------------------------------------------------

let totalEvents = 0;

// ----- Helpers --------------------------------------------------------------

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
    'Access-Control-Allow-Origin': '*',
  });
  res.end(payload);
}

function logLine(prefix, msg) {
  const ts = new Date().toISOString();
  process.stdout.write(`[${ts}] ${prefix} ${msg}\n`);
}

// ----- Routes ---------------------------------------------------------------

const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const route = parsed.pathname;

  // healthz: no auth, returns OK.
  if (route === '/api/v1/lens/healthz' && req.method === 'GET') {
    return json(res, 200, { status: 'ok', version: '0.0.0-mock' });
  }

  // telemetry: auth-required POST.
  if (route === '/api/v1/lens/telemetry' && req.method === 'POST') {
    const auth = req.headers['authorization'] || '';
    if (!auth.startsWith('Bearer ')) {
      return json(res, 401, { error: 'missing bearer token' });
    }
    let body;
    try {
      body = await readBody(req);
    } catch (err) {
      return json(res, 400, { error: 'read error: ' + err.message });
    }
    let event;
    try {
      event = JSON.parse(body);
    } catch (err) {
      return json(res, 400, { error: 'invalid JSON: ' + err.message });
    }
    // Append to JSONL stream.
    fs.appendFileSync(args.output, JSON.stringify(event) + '\n');
    totalEvents++;
    const id = crypto.randomUUID();
    logLine(
      'TELEMETRY',
      `accepted event #${totalEvents} ` +
        `category=${event.category} ` +
        `severity=${event.severity} ` +
        `action=${event.user_action} ` +
        `version=${event.lens_event_version}`,
    );
    return json(res, 200, { accepted: true, id: id });
  }

  // stats: auth-required GET.
  if (route === '/api/v1/lens/stats' && req.method === 'GET') {
    return json(res, 200, {
      events24h: totalEvents,
      detections24h: totalEvents,
    });
  }

  // check: auth-required GET, returns no-IOC mock.
  if (route === '/api/v1/lens/check' && req.method === 'GET') {
    const domain = parsed.query.domain || '';
    const hash = crypto
      .createHash('sha256')
      .update(domain)
      .digest('hex')
      .slice(0, 16);
    return json(res, 200, {
      domain_hash: hash,
      has_iocs: false,
    });
  }

  // 404
  return json(res, 404, { error: 'not found: ' + route });
});

// ----- Lifecycle ------------------------------------------------------------

server.listen(args.port, '127.0.0.1', () => {
  logLine(
    'MOCK',
    `listening on http://127.0.0.1:${args.port}` +
      ` (events -> ${args.output})`,
  );
});

function shutdown(signal) {
  logLine('MOCK', `received ${signal}, shutting down after ${totalEvents} events`);
  server.close(() => process.exit(0));
  // Hard exit if server.close hangs.
  setTimeout(() => process.exit(0), 1000).unref();
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
