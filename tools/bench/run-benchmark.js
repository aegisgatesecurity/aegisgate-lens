// SPDX-License-Identifier: Apache-2.0
// AegisGate Lens v0.1.4 - Performance Benchmark (v2)
//
// Measures detection latency on REALISTIC inputs to establish a
// baseline for the "sub-millisecond detection" claim in the README.
//
// v0.1.4 baseline (v1) was 17,660 chars (~2522 words), which is
// unrealistic for a chat prompt. Real AI prompts are typically:
//   - 100 chars (a short question)
//   - 500 chars (a typical question with context)
//   - 2000 chars (a long email or code paste)
//   - 10000 chars (a very long document paste)
//
// Per the v0.1.4 blind-spot analysis, this addresses Gap 12
// (no performance baseline). The output is saved to
// test/benchmarks/results/v0.1.4-baseline.json for future
// comparison.
//
// Usage: node tools/bench/run-benchmark.js
//   Or:  node tools/bench/run-benchmark.js --save
//   Or:  node tools/bench/run-benchmark.js --iterations=200
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

'use strict';

const fs = require('node:fs');
const path = require('node:path');

// Realistic input sizes (chars) for a typical AI chat prompt.
const SIZE_LABELS = ['100 chars (short)', '500 chars (typical)', '2000 chars (long)', '10000 chars (very long)'];
const SIZE_VALUES = [100, 500, 2000, 10000];

// A small "user is asking about..." text that we repeat to reach
// the target size. Includes 2 PII items (SSN, credit card) so the
// regex actually has to do work, not just trivially return.
const SEED = 'Help me draft an email. My SSN is 123-45-6789 and my credit card is 4111-1111-1111-1111. Thanks! ';

// Helper: percentile calculation
function percentile(sortedValues, p) {
    if (sortedValues.length === 0) return 0;
    const idx = Math.floor((p / 100) * sortedValues.length);
    return sortedValues[Math.min(idx, sortedValues.length - 1)];
}

// Helper: build a text of approximately the target size
function buildText(targetSize) {
    let text = '';
    while (text.length < targetSize) {
        text += SEED;
    }
    return text.substring(0, targetSize);
}

// Run the benchmark for one size
function benchmarkSize(text, iterations, patterns) {
    const latencies = [];
    for (let i = 0; i < iterations; i++) {
        const start = process.hrtime.bigint();
        for (const re of patterns) {
            re.test(text);
        }
        const end = process.hrtime.bigint();
        latencies.push(Number(end - start) / 1e6); // ns -> ms
    }
    latencies.sort((a, b) => a - b);
    return {
        textLength: text.length,
        iterations,
        p50: percentile(latencies, 50),
        p95: percentile(latencies, 95),
        p99: percentile(latencies, 99),
        max: latencies[latencies.length - 1],
        min: latencies[0],
        mean: latencies.reduce((a, b) => a + b, 0) / latencies.length
    };
}

function runBenchmark(iterations = 200) {
    console.log(`AegisGate Lens v0.1.4 - Performance Benchmark v2`);
    console.log(`  Iterations per size: ${iterations}`);
    console.log();

    // Load the bundle (we test the actual bundle, not the source)
    const bundlePath = path.join(__dirname, '..', '..', 'test', 'headless-smoke', 'bundle.js');
    if (!fs.existsSync(bundlePath)) {
        console.error(`ERROR: bundle not found at ${bundlePath}`);
        console.error(`  Run: python3 tools/ci/build-bundle.py`);
        process.exit(1);
    }
    const bundleSource = fs.readFileSync(bundlePath, 'utf-8');

    // Extract all regex patterns from the bundle
    const regexPattern = /re:\s*\/([^/\n]+)\/([gimuy]*)/g;
    const patterns = [];
    let match;
    while ((match = regexPattern.exec(bundleSource)) !== null) {
        try {
            const re = new RegExp(match[1], match[2]);
            patterns.push(re);
        } catch (e) {
            // Skip invalid patterns
        }
    }
    console.log(`  Extracted ${patterns.length} regex patterns from bundle`);
    console.log();

    // Run for each size
    const results = {
        patterns: patterns.length,
        iterations,
        sizes: [],
        timestamp: new Date().toISOString()
    };

    for (let i = 0; i < SIZE_LABELS.length; i++) {
        const text = buildText(SIZE_VALUES[i]);
        const r = benchmarkSize(text, iterations, patterns);
        results.sizes.push({
            label: SIZE_LABELS[i],
            size: SIZE_VALUES[i],
            actualLength: r.textLength,
            p50: r.p50,
            p95: r.p95,
            p99: r.p99,
            max: r.max,
            min: r.min,
            mean: r.mean
        });

        const subMs = r.p99 < 1.0 ? '✅' : (r.p99 < 5.0 ? '⚠️ ' : '❌');
        console.log(`${SIZE_LABELS[i]} (${text.length} chars):`);
        console.log(`  p50:  ${r.p50.toFixed(4)} ms`);
        console.log(`  p95:  ${r.p95.toFixed(4)} ms`);
        console.log(`  p99:  ${r.p99.toFixed(4)} ms  ${subMs} ${r.p99 < 1.0 ? 'sub-ms' : (r.p99 < 5.0 ? 'fast' : 'slow')}`);
        console.log(`  max:  ${r.max.toFixed(4)} ms`);
        console.log();
    }

    return results;
}

function saveResults(results) {
    const resultsDir = path.join(__dirname, '..', '..', 'test', 'benchmarks', 'results');
    if (!fs.existsSync(resultsDir)) {
        fs.mkdirSync(resultsDir, { recursive: true });
    }
    const outFile = path.join(resultsDir, 'v0.1.4-baseline.json');
    const json = JSON.stringify(results, null, 2);
    fs.writeFileSync(outFile, json);
    console.log(`Results saved to: ${outFile}`);
}

// Parse args
const args = process.argv.slice(2);
const saveMode = args.includes('--save');
const iterArg = args.find(a => a.startsWith('--iterations='));
const iterations = iterArg ? parseInt(iterArg.split('=')[1], 10) : 200;

const results = runBenchmark(iterations);
if (saveMode) {
    saveResults(results);
}
