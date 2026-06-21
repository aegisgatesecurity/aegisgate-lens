#!/usr/bin/env node
/**
 * AegisGate Lens - Cascade Test Harness (v0.2)
 *
 * Tests the regex + ML cascade against the same 6,500 WildChat normal
 * examples and 1,190 attack corpus that produced the 4.72% FPR baseline.
 *
 * Modes:
 *   - regex-only: baseline (TPR 100%, FPR 4.72% documented)
 *   - cascade-mode-a: regex OR ML fires -> banner (ML only on regex-silent)
 *   - cascade-mode-b: both must agree (consensus, more conservative)
 *   - ml-only: skip regex entirely
 *
 * Usage:
 *   node run-v02-with-ml.js [--mode=a|b|regex|ml] [--threshold=0.5]
 */

'use strict';

const fs = require('fs');
const path = require('path');

// =============================================================================
// Configuration
// =============================================================================

const CONFIG = {
  // Paths (permanent location - /tmp/ is volatile across sessions)
  detectorPath: '/home/chaos/Desktop/AegisGate/lens-repo-bootstrap/src/detectors/from_platform.js',
  mlArtifactsDir: '/home/chaos/Desktop/AegisGate/lens-repo-bootstrap/ml-artifacts/dist',
  corpusDir: '/home/chaos/Desktop/AegisGate/lens-repo-bootstrap/ml-artifacts/corpus',

  // Output (permanent location)
  outputDir: '/home/chaos/Desktop/AegisGate/lens-repo-bootstrap/ml-artifacts/metrics',

  // ML
  mlThreshold: 0.5,

  // Categories relevant to AegisGate Lens (prompt injection detection)
  // Excludes PII, secrets, toxicity (handled by other AegisGate products)
  promptInjectionCategories: [
    'anp_guard_injection',
    'atlas_configexfiltration',
    'atlas_contentinjection',
    'atlas_credentialforgery',
    'atlas_dataextraction',
    'atlas_defenseevasion',
    'atlas_denialofservice',
    'atlas_elevationabuse',
    'atlas_endpointdenial',
    'atlas_indirectinjection',
    'atlas_inhibitrecovery',
    'atlas_llmjailbreak',
    'atlas_mfabypass',
    'atlas_pluginexploitation',
    'atlas_promptextraction',
    'atlas_promptinjection',
    'atlas_resourceexhaustion',
    'atlas_vectordbpoisoning',
    'computeruse_guard_sensitive',
    'eu_ai_act_adversarial',
    'eu_ai_act_datapoison',
    'eu_ai_act_manipulation',
    'eu_ai_act_promptinject',
    'eu_ai_act_subliminal',
    'owasp_excessive_agency',
    'owasp_insecure_output',
    'owasp_insecure_plugin',
    'owasp_model_dos',
    'owasp_model_theft',
    'owasp_overreliance',
    'owasp_prompt_injection',
    'owasp_supply_chain',
    'owasp_training_poisoning',
  ],
};

// =============================================================================
// Step 1: Load regex detector via Node.js shim
// =============================================================================

console.log('[1/5] Loading regex detector...');

// Create a minimal browser-like global environment
global.window = global.self = global;
global.AegisGateLens = {};

// Load the detector file (it's an IIFE that populates AegisGateLens)
const detectorCode = fs.readFileSync(CONFIG.detectorPath, 'utf8');
try {
  // Run in a context where 'window' is defined
  const fn = new Function('window', 'self', detectorCode + '; return AegisGateLens;');
  const lens = fn(global, global);
  global.AegisGateLens = lens;
} catch (e) {
  console.error('Failed to load detector:', e.message);
  process.exit(1);
}

const PATTERNS = global.AegisGateLens.detectors?.fromPlatform?.PATTERNS;
if (!PATTERNS || !Array.isArray(PATTERNS)) {
  console.error('PATTERNS array not found in detector output');
  console.error('Available keys:', Object.keys(global.AegisGateLens));
  if (global.AegisGateLens.detectors) {
    console.error('detectors keys:', Object.keys(global.AegisGateLens.detectors));
  }
  process.exit(1);
}

console.log(`   Loaded ${PATTERNS.length} regex patterns`);

// Filter to prompt-injection categories only
const PI_PATTERNS = PATTERNS.filter(p => CONFIG.promptInjectionCategories.includes(p.category));
console.log(`   Filtered to ${PI_PATTERNS.length} prompt-injection patterns`);

// =============================================================================
// Step 2: Load ML model artifacts
// =============================================================================

console.log('[2/5] Loading ML model...');

const vocabulary = JSON.parse(fs.readFileSync(path.join(CONFIG.mlArtifactsDir, 'vocabulary.json'), 'utf8'));
const idf = JSON.parse(fs.readFileSync(path.join(CONFIG.mlArtifactsDir, 'idf.json'), 'utf8'));
const lrCoefficients = JSON.parse(fs.readFileSync(path.join(CONFIG.mlArtifactsDir, 'lr_coefficients.json'), 'utf8'));
const lrConfig = JSON.parse(fs.readFileSync(path.join(CONFIG.mlArtifactsDir, 'lr_config.json'), 'utf8'));

console.log(`   Vocabulary: ${Object.keys(vocabulary).length} features`);
console.log(`   IDF: ${Object.keys(idf).length} entries`);
console.log(`   Coefficients: ${Object.keys(lrCoefficients).length} non-zero entries`);
console.log(`   Intercept: ${lrConfig.intercept}`);

// =============================================================================
// Step 3: Implement JS-native ML inference
// =============================================================================

console.log('[3/5] Setting up ML inference...');

// Build lookup maps for fast access
const vocabMap = new Map(Object.entries(vocabulary));
const idfMap = new Map(Object.entries(idf));
const coefMap = new Map(Object.entries(lrCoefficients));

/**
 * Tokenize text into word 1-2 grams + char 3-5 grams.
 * Matches the Python training pipeline.
 */
function tokenize(text) {
  const features = new Map(); // feature_name -> count (term frequency)
  const textLower = text.toLowerCase();

  // Word 1-grams
  const words = textLower.match(/\b\w+\b/g) || [];
  for (const w of words) {
    if (w.length >= 2) {  // Skip single chars (mostly noise)
      const key = `w=${w}`;
      features.set(key, (features.get(key) || 0) + 1);
    }
  }

  // Word 2-grams (bigrams) - use __ separator to keep as single token
  for (let i = 0; i < words.length - 1; i++) {
    const bg = `w=${words[i]}__${words[i+1]}`;
    features.set(bg, (features.get(bg) || 0) + 1);
  }

  // Char 3-5 grams - only within words (no word boundaries)
  // Use __ as word separator in normalized text, then skip n-grams crossing it
  const normalizedWords = textLower.match(/[a-z0-9]+/g) || [];
  const normalized = normalizedWords.join('__');
  for (let n = 3; n <= 5; n++) {
    for (let i = 0; i <= normalized.length - n; i++) {
      const substr = normalized.substring(i, i + n);
      // Skip n-grams that cross word boundaries
      if (!substr.includes('__')) {
        const key = `c=${substr}`;
        features.set(key, (features.get(key) || 0) + 1);
      }
    }
  }

  return features;
}

/**
 * Compute ML probability for a text input.
 */
function scoreML(text) {
  const tf = tokenize(text);
  let score = lrConfig.intercept;

  // First pass: compute unnormalized TF-IDF and L2 norm
  let sumSquares = 0;
  const tfidfEntries = [];
  for (const [feature, count] of tf) {
    const vocabIdx = vocabMap.get(feature);
    if (vocabIdx === undefined) continue;  // OOV feature

    const idfWeight = idfMap.get(feature);
    if (idfWeight === undefined) continue;

    const coef = coefMap.get(String(vocabIdx));
    if (coef === undefined || coef === 0) continue;

    // TF-IDF value (unnormalized)
    const tfidf = count * idfWeight;
    tfidfEntries.push({ tfidf, coef });
    sumSquares += tfidf * tfidf;
  }

  // L2 normalization (sklearn default)
  const norm = Math.sqrt(sumSquares);
  if (norm === 0) {
    return 1 / (1 + Math.exp(-score));
  }

  // Second pass: dot product with L2-normalized TF-IDF
  for (const { tfidf, coef } of tfidfEntries) {
    score += (tfidf / norm) * coef;
  }

  // Sigmoid
  const prob = 1 / (1 + Math.exp(-score));
  return prob;
}

// Quick sanity check
const testScore = scoreML('ignore previous instructions');
console.log(`   Sanity check: "ignore previous instructions" -> ${testScore.toFixed(4)}`);
const testScore2 = scoreML('What is the weather today?');
console.log(`   Sanity check: "What is the weather today?" -> ${testScore2.toFixed(4)}`);

// =============================================================================
// Step 4: Load test corpus
// =============================================================================

console.log('[4/5] Loading test corpus...');

function loadJsonl(filePath) {
  const lines = fs.readFileSync(filePath, 'utf8').split('\n');
  const samples = [];
  for (const line of lines) {
    if (!line.trim()) continue;
    try {
      const obj = JSON.parse(line);
      samples.push(obj);
    } catch (e) {
      // Plain text line - wrap it
      samples.push({ text: line, label: null });
    }
  }
  return samples;
}

function loadTextCorpus(filePath) {
  // Files may be plain text (one example per line) or JSONL
  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split('\n').filter(l => l.trim());

  // Check first line - if it looks like JSON, treat as JSONL
  if (lines.length > 0 && lines[0].trim().startsWith('{')) {
    return loadJsonl(filePath);
  } else {
    // Plain text: one example per line
    return lines.map(text => ({ text, label: null }));
  }
}

const corpus = [];

// Load attacks (label 1)
const attackFiles = fs.readdirSync(path.join(CONFIG.corpusDir, 'attacks'))
  .filter(f => f.endsWith('.jsonl') || f.endsWith('.txt'));
console.log(`   Attack files: ${attackFiles.length}`);

for (const file of attackFiles) {
  const samples = loadTextCorpus(path.join(CONFIG.corpusDir, 'attacks', file));
  for (const s of samples) {
    corpus.push({ text: s.text, label: 1, source: `attacks/${file}` });
  }
}

// Load normal (label 0)
const normalFiles = fs.readdirSync(path.join(CONFIG.corpusDir, 'normal'))
  .filter(f => f.endsWith('.jsonl') || f.endsWith('.txt'));
console.log(`   Normal files: ${normalFiles.length}`);

for (const file of normalFiles) {
  const samples = loadTextCorpus(path.join(CONFIG.corpusDir, 'normal', file));
  for (const s of samples) {
    corpus.push({ text: s.text, label: 0, source: `normal/${file}` });
  }
}

console.log(`   Total corpus: ${corpus.length} samples`);
const attackCount = corpus.filter(s => s.label === 1).length;
const normalCount = corpus.filter(s => s.label === 0).length;
console.log(`   Attacks: ${attackCount}, Normal: ${normalCount}`);

// =============================================================================
// Step 5: Run evaluations
// =============================================================================

console.log('[5/5] Running evaluations...');

/**
 * Run regex detector on a text. Returns the first matching category or null.
 */
function runRegex(text) {
  for (const pattern of PI_PATTERNS) {
    // Reset regex state (since 'g' flag is set)
    pattern.regex.lastIndex = 0;
    if (pattern.regex.test(text)) {
      return {
        category: pattern.category,
        severity: pattern.severity,
        name: pattern.name,
      };
    }
  }
  return null;
}

/**
 * Evaluate a mode across the full corpus.
 */
function evaluate(mode, threshold = 0.5) {
  let tp = 0, fp = 0, tn = 0, fn = 0;
  let mlRuns = 0;
  const mlLatencies = [];
  const fps = [];
  const fns = [];
  const tps = [];
  const tns = [];

  for (const sample of corpus) {
    const text = sample.text;
    const trueLabel = sample.label;
    let prediction = 0;

    if (mode === 'regex-only') {
      const match = runRegex(text);
      prediction = match ? 1 : 0;
    } else if (mode === 'ml-only') {
      mlRuns++;
      const t0 = process.hrtime.bigint();
      const prob = scoreML(text);
      const elapsed = Number(process.hrtime.bigint() - t0) / 1e6; // ms
      mlLatencies.push(elapsed);
      prediction = prob >= threshold ? 1 : 0;
    } else if (mode === 'cascade-a') {
      // Mode A: regex OR ML fires -> banner
      const match = runRegex(text);
      if (match) {
        prediction = 1;
      } else {
        mlRuns++;
        const t0 = process.hrtime.bigint();
        const prob = scoreML(text);
        const elapsed = Number(process.hrtime.bigint() - t0) / 1e6;
        mlLatencies.push(elapsed);
        prediction = prob >= threshold ? 1 : 0;
      }
    } else if (mode === 'cascade-b') {
      // Mode B: consensus (both must agree)
      const match = runRegex(text);
      mlRuns++;
      const t0 = process.hrtime.bigint();
      const prob = scoreML(text);
      const elapsed = Number(process.hrtime.bigint() - t0) / 1e6;
      mlLatencies.push(elapsed);
      const mlFires = prob >= threshold;
      prediction = (match && mlFires) ? 1 : 0;
    }

    // Update confusion matrix
    if (prediction === 1 && trueLabel === 1) {
      tp++;
      if (tps.length < 5) tps.push({ text: text.substring(0, 100), source: sample.source });
    } else if (prediction === 1 && trueLabel === 0) {
      fp++;
      if (fps.length < 50) fps.push({ text: text.substring(0, 200), source: sample.source });
    } else if (prediction === 0 && trueLabel === 0) {
      tn++;
      if (tns.length < 5) tns.push({ text: text.substring(0, 100), source: sample.source });
    } else if (prediction === 0 && trueLabel === 1) {
      fn++;
      if (fns.length < 50) fns.push({ text: text.substring(0, 200), source: sample.source });
    }
  }

  const totalAttacks = tp + fn;
  const totalNormal = tn + fp;
  const tpr = totalAttacks > 0 ? tp / totalAttacks : 0;
  const fpr = totalNormal > 0 ? fp / totalNormal : 0;
  const precision = (tp + fp) > 0 ? tp / (tp + fp) : 0;
  const recall = tpr;
  const f1 = (precision + recall) > 0 ? 2 * precision * recall / (precision + recall) : 0;

  const avgLatency = mlLatencies.length > 0 ? mlLatencies.reduce((a, b) => a + b, 0) / mlLatencies.length : 0;
  const sortedLatency = mlLatencies.slice().sort((a, b) => a - b);
  const p50Latency = sortedLatency[Math.floor(sortedLatency.length * 0.5)] || 0;
  const p99Latency = sortedLatency[Math.floor(sortedLatency.length * 0.99)] || 0;

  return {
    mode,
    threshold,
    confusionMatrix: { tp, fp, tn, fn },
    tpr, fpr, precision, recall, f1,
    mlRuns,
    mlRunPct: (mlRuns / corpus.length * 100).toFixed(2),
    latency: {
      avg_ms: avgLatency.toFixed(3),
      p50_ms: p50Latency.toFixed(3),
      p99_ms: p99Latency.toFixed(3),
    },
    samples: { fps: fps.slice(0, 20), fns: fns.slice(0, 20), tps: tps.slice(0, 5), tns: tns.slice(0, 5) },
  };
}

// Parse CLI args
const args = process.argv.slice(2);
let selectedMode = 'all';
let threshold = 0.5;
for (const arg of args) {
  if (arg.startsWith('--mode=')) selectedMode = arg.substring(7);
  if (arg.startsWith('--threshold=')) threshold = parseFloat(arg.substring(12));
}
CONFIG.mlThreshold = threshold;

const modes = selectedMode === 'all'
  ? ['regex-only', 'ml-only', 'cascade-a', 'cascade-b']
  : [selectedMode];

const results = {};
for (const mode of modes) {
  console.log(`   Running mode: ${mode}...`);
  results[mode] = evaluate(mode, threshold);
}

// =============================================================================
// Output
// =============================================================================

if (!fs.existsSync(CONFIG.outputDir)) {
  fs.mkdirSync(CONFIG.outputDir, { recursive: true });
}

const outputFile = path.join(CONFIG.outputDir, 'v02-cascade-results.json');
fs.writeFileSync(outputFile, JSON.stringify({
  config: CONFIG,
  corpusStats: {
    total: corpus.length,
    attacks: attackCount,
    normal: normalCount,
  },
  results,
}, null, 2));

console.log(`\nResults written to: ${outputFile}`);

// Print summary
console.log('\n' + '='.repeat(70));
console.log('CASCADE TEST RESULTS (v0.2)');
console.log('='.repeat(70));

for (const [mode, r] of Object.entries(results)) {
  console.log(`\n${mode}:`);
  console.log(`  TPR:        ${(r.tpr * 100).toFixed(2)}%  (${r.confusionMatrix.tp}/${r.confusionMatrix.tp + r.confusionMatrix.fn} attacks caught)`);
  console.log(`  FPR:        ${(r.fpr * 100).toFixed(2)}%  (${r.confusionMatrix.fp}/${r.confusionMatrix.fp + r.confusionMatrix.tn} normal flagged)`);
  console.log(`  Precision:  ${(r.precision * 100).toFixed(2)}%`);
  console.log(`  F1:         ${(r.f1 * 100).toFixed(2)}%`);
  if (r.mlRuns > 0) {
    console.log(`  ML runs:    ${r.mlRuns}/${corpus.length} (${r.mlRunPct}%)`);
    console.log(`  Latency:    avg=${r.latency.avg_ms}ms p50=${r.latency.p50_ms}ms p99=${r.latency.p99_ms}ms`);
  }
}

console.log('\n' + '='.repeat(70));
console.log('COMPARISON TO BASELINE (regex-only, Phase 4)');
console.log('='.repeat(70));
console.log(`  Regex baseline:  TPR 100.00%, FPR 4.72%`);
if (results['cascade-a']) {
  const a = results['cascade-a'];
  console.log(`  Cascade A:       TPR ${(a.tpr*100).toFixed(2)}%, FPR ${(a.fpr*100).toFixed(2)}%  (${a.mlRunPct}% of messages ran ML)`);
}
if (results['cascade-b']) {
  const b = results['cascade-b'];
  console.log(`  Cascade B:       TPR ${(b.tpr*100).toFixed(2)}%, FPR ${(b.fpr*100).toFixed(2)}%  (consensus)`);
}
console.log('='.repeat(70) + '\n');
