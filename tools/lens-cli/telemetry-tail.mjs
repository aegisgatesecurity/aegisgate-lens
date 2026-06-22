#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - lens-cli telemetry tail (Day 2)
// =========================================================================
//
// A local debugging tool that watches the JSONL stream emitted by the
// mock backend (test/mock-backend.mjs) or by the in-browser audit log
// (when copied out as JSONL by the smoke test).
//
// Usage:
//   node tools/lens-cli/telemetry-tail.mjs [--input PATH] [--follow] [--filter CATEGORY]
//
//   --input PATH    JSONL file to read (default: test/mock-output/events.jsonl)
//   --follow        Keep tailing the file as it grows (default: true)
//   --filter CAT    Only print events matching this category
//   --no-follow     Read existing file and exit
//   --quiet         Suppress the "tailing ..." startup line
//
// The CLI never sends telemetry. It is a read-only viewer for the
// privacy-preserving metadata that the Lens's own audit/mirror paths
// produce. It must NEVER be extended to read prompt content, URLs, or
// page content. If you find yourself wanting to do that, stop and
// re-read AEGISGATE-LENS-LEGAL-DEVELOPER-CONSTRAINTS.md §4.
//
// =========================================================================

'use strict';

import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';

const here = path.dirname(url.fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..', '..');

// ----- CLI args -------------------------------------------------------------

function parseArgs(argv) {
  const out = {
    input: path.join(repoRoot, 'test/mock-output/events.jsonl'),
    follow: true,
    filter: null,
    quiet: false,
  };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--input' && argv[i + 1]) {
      out.input = argv[i + 1];
      i++;
    } else if (argv[i] === '--filter' && argv[i + 1]) {
      out.filter = argv[i + 1];
      i++;
    } else if (argv[i] === '--no-follow') {
      out.follow = false;
    } else if (argv[i] === '--quiet') {
      out.quiet = true;
    } else if (argv[i] === '--help' || argv[i] === '-h') {
      console.log(
        'Usage: node tools/lens-cli/telemetry-tail.mjs ' +
          '[--input PATH] [--follow|--no-follow] [--filter CATEGORY] [--quiet]',
      );
      process.exit(0);
    }
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));

// ----- Pretty-print one event ----------------------------------------------

function ts() {
  return new Date().toISOString().replace('T', ' ').slice(0, 19);
}

const SEVERITY_COLOR = {
  critical: '\x1b[1;31m', // bold red
  high: '\x1b[31m',      // red
  medium: '\x1b[33m',    // yellow
  low: '\x1b[36m',       // cyan
  info: '\x1b[37m',      // grey
};
const RESET = '\x1b[0m';
const DIM = '\x1b[2m';

function printEvent(ev) {
  if (args.filter && ev.category !== args.filter) return;
  const sev = ev.severity || 'info';
  const sevColor = SEVERITY_COLOR[sev] || '';
  const idShort = (ev.id || '').slice(0, 8);
  process.stdout.write(
    `${DIM}[${ts()}]${RESET} ` +
      `${sevColor}${sev.toUpperCase().padEnd(8)}${RESET} ` +
      `${(ev.category || '').padEnd(18)} ` +
      `${DIM}action=${(ev.user_action || '').padEnd(12)}${RESET} ` +
      `${DIM}conf=${(ev.confidence || 0).toFixed(2)} ` +
      `domain_hash=${ev.domain_hash}${idShort ? ' ' + DIM + 'id=' + idShort : ''}` +
      `${RESET}\n`,
  );
}

// ----- Stream the file ------------------------------------------------------

function streamFile() {
  if (!fs.existsSync(args.input)) {
    process.stderr.write(`error: file not found: ${args.input}\n`);
    process.stderr.write(
      `hint: start the mock backend with: node test/mock-backend.mjs\n`,
    );
    process.exit(1);
  }

  if (!args.quiet) {
    process.stderr.write(
      `Tailing ${args.input}` +
        (args.filter ? ` (filter: ${args.filter})` : '') +
        (args.follow ? ' — Ctrl-C to stop\n' : '\n'),
    );
  }

  // Print all existing lines.
  let buf = '';
  const stat = fs.statSync(args.input);
  let pos = stat.size;

  const initial = fs.readFileSync(args.input, 'utf8');
  for (const line of initial.split('\n')) {
    if (!line) continue;
    try {
      printEvent(JSON.parse(line));
    } catch (_) {
      process.stderr.write(`${DIM}skip malformed line${RESET}\n`);
    }
  }

  if (!args.follow) {
    return;
  }

  // Poll for new bytes every 200ms. (Inotify would be cleaner but adds
  // a dependency on Linux-only APIs; 200ms polling is fine for a debug
  // tool and matches typical editor-tail latency.)
  const interval = setInterval(() => {
    let cur;
    try {
      cur = fs.statSync(args.input);
    } catch (_) {
      return; // file may have been rotated; ignore
    }
    if (cur.size <= pos) {
      // File truncated or unchanged.
      if (cur.size < pos) pos = 0;
      return;
    }
    const fd = fs.openSync(args.input, 'r');
    const len = cur.size - pos;
    const buf = Buffer.alloc(len);
    fs.readSync(fd, buf, 0, len, pos);
    fs.closeSync(fd);
    pos = cur.size;
    for (const line of buf.toString('utf8').split('\n')) {
      if (!line) continue;
      try {
        printEvent(JSON.parse(line));
      } catch (_) {
        process.stderr.write(`${DIM}skip malformed line${RESET}\n`);
      }
    }
  }, 200);

  process.on('SIGINT', () => {
    clearInterval(interval);
    process.stderr.write('\n');
    process.exit(0);
  });
}

streamFile();
