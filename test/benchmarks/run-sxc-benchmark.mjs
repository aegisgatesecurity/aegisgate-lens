// AegisGate Lens — SXC Benchmark Runner
// Runs the 158-prompt SXC corpus through Lens detectors (regex + ML)
// and reports TP/FN/FP/TN/partial, strict/loose recall, FPR, accuracy.
//
// Usage: node test/benchmarks/run-sxc-benchmark.mjs
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { createUnzip } from 'node:zlib';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { loadModule, resetGlobals, LENS_ROOT } from '../helpers/load-module.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ================================================================
// Load SXC corpus
// ================================================================
const CORPUS_PATH = join(LENS_ROOT, 'test/benchmarks/corpus/sxc/v0.1.1-sxc-corpus.jsonl');
const corpus = readFileSync(CORPUS_PATH, 'utf-8')
  .trim()
  .split('\n')
  .map(line => JSON.parse(line));

console.log(`Loaded ${corpus.length} prompts from SXC corpus`);
console.log(`  Positive: ${corpus.filter(c => c.expected_label === 1).length}`);
console.log(`  Negative: ${corpus.filter(c => c.expected_label === 0).length}`);

// ================================================================
// Load regex facets (same pattern as evasion suite)
// ================================================================
let normalizeAllVariants = null;
try {
  const normalizer = loadModule('src/detectors/ml/char-normalizer.js', '__lensCharNormalizer');
  if (normalizer && typeof normalizer.normalizeAllVariants === 'function') {
    normalizeAllVariants = normalizer.normalizeAllVariants;
  }
} catch (e) {
  console.error('Normalizer load error:', e.message);
}

// Load PII sub-files first
loadModule('src/detectors/regex/pii-us-core.js', '__lensPII_us_core');
loadModule('src/detectors/regex/pii-us-extended.js', '__lensPII_us_extended');
loadModule('src/detectors/regex/pii-international-id.js', '__lensPII_international_id');
loadModule('src/detectors/regex/pii-financial.js', '__lensPII_financial');

const compliance = loadModule('src/detectors/regex/compliance.js', '__lensCompliance');
const pii = loadModule('src/detectors/regex/pii.js', '__lensPII');
const secrets = loadModule('src/detectors/regex/secrets.js', '__lensSecrets');
const xss = loadModule('src/detectors/regex/source_xss.js', '__lensXSS');
const attack = loadModule('src/detectors/regex/attack_patterns.js', '__lensAttackPatterns');

const regexFacets = [compliance, pii, secrets, xss, attack].filter(
  f => f && typeof f.detect === 'function'
);
console.log(`Loaded ${regexFacets.length} regex facets`);

// ================================================================
// Regex detection — returns array of matched categories
// ================================================================
function regexDetectCategories(text) {
  if (!text || typeof text !== 'string') return [];
  const variants = normalizeAllVariants ? normalizeAllVariants(text) : [text];
  const allMatches = [];
  for (const v of variants) {
    for (const facet of regexFacets) {
      try {
        const matches = facet.detect(v);
        if (matches && matches.length > 0) {
          for (const m of matches) {
            if (!allMatches.includes(m.category)) {
              allMatches.push(m.category);
            }
          }
        }
      } catch (e) { /* facet error — skip */ }
    }
  }
  return allMatches;
}

// ================================================================
// ML detector setup (same as evasion suite)
// ================================================================
function setupMocks() {
  if (!globalThis.chrome) globalThis.chrome = {};
  if (!globalThis.chrome.runtime) globalThis.chrome.runtime = {};
  globalThis.chrome.runtime.getURL = function (path) {
    return join(LENS_ROOT, path);
  };
  globalThis.fetch = async function (url) {
    const data = readFileSync(url, 'utf-8');
    return {
      ok: true,
      status: 200,
      statusText: 'OK',
      text: async () => data,
      json: async () => JSON.parse(data),
    };
  };
}

let _weightPackage = null;
function loadWeightPackage() {
  if (_weightPackage) return _weightPackage;
  const modelPath = join(LENS_ROOT, 'models/threat_cnn_bilstm_weights.bin.json');
  const raw = readFileSync(modelPath, 'utf-8');
  _weightPackage = JSON.parse(raw);
  return _weightPackage;
}

function decompressWeights(pkg) {
  const compressed = Buffer.from(pkg.data, 'base64');
  return new Promise((resolve, reject) => {
    const unzip = createUnzip();
    const chunks = [];
    unzip.on('data', chunk => chunks.push(chunk));
    unzip.on('end', () => resolve(Buffer.concat(chunks)));
    unzip.on('error', reject);
    unzip.write(compressed);
    unzip.end();
  });
}

function float16ToFloat32(u16View, count) {
  const f32 = new Float32Array(count);
  for (let k = 0; k < count; k++) {
    const h = u16View[k];
    const sign = (h >> 15) & 1;
    const exponent = (h >> 10) & 0x1F;
    const mantissa = h & 0x3FF;
    if (exponent === 0) {
      if (mantissa === 0) { f32[k] = sign ? -0 : 0; }
      else { const sub = mantissa / 1024 / 16384; f32[k] = sign ? -sub : sub; }
    } else if (exponent === 31) {
      f32[k] = mantissa === 0 ? (sign ? -Infinity : Infinity) : NaN;
    } else {
      const val = Math.pow(2, exponent - 15) * (1 + mantissa / 1024);
      f32[k] = sign ? -val : val;
    }
  }
  return f32;
}

async function getDetector() {
  resetGlobals();
  setupMocks();
  const detector = loadModule('src/detectors/ml/threat-detector-js.js', '__lensThreatDetector');
  if (!detector) throw new Error('Threat detector module failed to load');
  await detector.loadModel();
  return detector;
}

// ================================================================
// Run benchmark
// ================================================================
async function run() {
  console.log('\nLoading ML model...');
  const det = await getDetector();
  console.log('Model loaded.\n');

  const results = [];
  let tp = 0, fn = 0, partial = 0, fp = 0, tn = 0;
  const byFacet = {};

  for (let i = 0; i < corpus.length; i++) {
    const item = corpus[i];
    const text = item.text;
    const expected = item.expected_label;
    const expectedCat = item.category;

    // Regex detection across all normalization variants
    const detectedCats = regexDetectCategories(text);
    const regexHit = detectedCats.length > 0;

    // ML detection across all normalization variants
    let mlHit = false;
    let mlScore = 0;
    const mlVariants = normalizeAllVariants ? normalizeAllVariants(text) : [text];
    for (const v of mlVariants) {
      const result = await det.classify(v);
      if (result.isAdversarial) {
        mlHit = true;
        mlScore = result.score || 0;
        break;
      }
      mlScore = Math.max(mlScore, result.score || 0);
    }

    const fired = regexHit || mlHit;
    const isPositive = expected === 1;

    let is_tp = false, is_fn = false, is_partial = false, is_fp = false, is_tn = false;

    if (isPositive && fired) {
      // Check if detected category matches expected
      if (detectedCats.includes(expectedCat)) {
        is_tp = true;
        tp++;
      } else if (regexHit) {
        // Regex fired but wrong category — partial
        is_partial = true;
        partial++;
      } else {
        // ML-only hit — count as TP for loose recall, but partial for strict
        // (no category match possible since ML doesn't return categories)
        is_partial = true;
        partial++;
      }
    } else if (isPositive && !fired) {
      is_fn = true;
      fn++;
    } else if (!isPositive && fired) {
      is_fp = true;
      fp++;
    } else {
      is_tn = true;
      tn++;
    }

    // Track by facet
    if (!byFacet[item.facet]) {
      byFacet[item.facet] = { tp: 0, fn: 0, partial: 0, fp: 0, tn: 0, total: 0 };
    }
    const f = byFacet[item.facet];
    f.total++;
    if (is_tp) f.tp++;
    if (is_fn) f.fn++;
    if (is_partial) f.partial++;
    if (is_fp) f.fp++;
    if (is_tn) f.tn++;

    results.push({
      id: item.id,
      facet: item.facet,
      category: item.category,
      expected_label: expected,
      fired,
      detected_categories: detectedCats,
      ml_hit: mlHit,
      ml_score: parseFloat(mlScore.toFixed(4)),
      expected_category: expectedCat,
      is_tp, is_fn, is_partial, is_fp, is_tn,
    });

    // Progress indicator
    if ((i + 1) % 20 === 0) {
      console.log(`  Processed ${i + 1}/${corpus.length}...`);
    }
  }

  det.unloadModel();

  // Compute metrics
  const strictRecall = tp / (tp + fn + partial);  // strict: only exact category match
  const looseRecall = (tp + partial) / (tp + partial + fn);  // loose: any detection
  const fpr = fp / (fp + tn);
  const accuracy = (tp + tn) / (tp + fn + partial + fp + tn);

  const summary = {
    tp, fn, partial, fp, tn,
    strict_recall: parseFloat(strictRecall.toFixed(4)),
    loose_recall: parseFloat(looseRecall.toFixed(4)),
    fpr: parseFloat(fpr.toFixed(4)),
    accuracy: parseFloat(accuracy.toFixed(4)),
  };

  // Print results
  console.log('\n=== SXC Benchmark Results ===');
  console.log(`  TP: ${tp}, FN: ${fn}, Partial: ${partial}, FP: ${fp}, TN: ${tn}`);
  console.log(`  Strict Recall: ${(strictRecall * 100).toFixed(1)}% (exact category match)`);
  console.log(`  Loose Recall:  ${(looseRecall * 100).toFixed(1)}% (any detection)`);
  console.log(`  FPR:           ${(fpr * 100).toFixed(1)}%`);
  console.log(`  Accuracy:      ${(accuracy * 100).toFixed(1)}%`);

  console.log('\n  By Facet:');
  for (const [facet, r] of Object.entries(byFacet)) {
    const sr = r.tp / (r.tp + r.fn + r.partial);
    const lr = (r.tp + r.partial) / (r.tp + r.partial + r.fn);
    const fr = r.fp / (r.fp + r.tn);
    console.log(`    ${facet}: strict=${(sr * 100).toFixed(1)}% loose=${(lr * 100).toFixed(1)}% fpr=${(fr * 100).toFixed(1)}% (n=${r.total})`);
  }

  // Show FNs and FPs
  const fns = results.filter(r => r.is_fn);
  if (fns.length > 0) {
    console.log(`\n  False Negatives (${fns.length}):`);
    for (const fn of fns) {
      console.log(`    ${fn.id}: expected=${fn.expected_category}`);
    }
  }

  const fps = results.filter(r => r.is_fp);
  if (fps.length > 0) {
    console.log(`\n  False Positives (${fps.length}):`);
    for (const fp of fps) {
      console.log(`    ${fp.id}: detected=${fp.detected_categories} ml=${fp.ml_hit}(${fp.ml_score})`);
    }
  }

  const partials = results.filter(r => r.is_partial);
  if (partials.length > 0) {
    console.log(`\n  Partials (${partials.length}):`);
    for (const p of partials) {
      console.log(`    ${p.id}: expected=${p.expected_category} detected=${p.detected_categories} ml=${p.ml_hit}(${p.ml_score})`);
    }
  }

  // Save report
  const reportDir = join(LENS_ROOT, 'test/benchmarks/corpus/results');
  try { mkdirSync(reportDir, { recursive: true }); } catch (e) { }
  const report = {
    metadata: {
      lens_version: '0.5.3',
      benchmark: 'sxc',
      corpus: CORPUS_PATH,
      timestamp: new Date().toISOString(),
      model: 'char-cnn-bilstm-v16b-js',
      fixes_applied: [
        'normalizeDespaced (port from Go)',
        'role\\s*play pattern fix',
        'admin authority pattern',
        '20 new ATLAS prompt injection patterns',
        'safety_bypass "the" prefix fix',
        'attack_patterns.js loaded',
      ],
    },
    summary,
    by_facet: byFacet,
    per_record: results,
  };
  const reportPath = join(reportDir, 'v0.5.3-sxc-benchmark-results.json');
  writeFileSync(reportPath, JSON.stringify(report, null, 2));
  console.log(`\n  Report saved to ${reportPath}`);
}

run().catch(err => {
  console.error('Benchmark failed:', err);
  process.exit(1);
});
