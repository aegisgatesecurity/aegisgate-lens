#!/usr/bin/env python3
"""
AegisGate Lens v0.1.0-beta -- Phase 5d v4: Generative LLM toxicity detection
=============================================================================

Per the user's directive (2026-07-05): "try a different family of models."
We use a generative LLM (gemma3:1b via Ollama) for toxicity detection
instead of a classifier (16-cat unitary/unbiased-toxic-roberta).

The key advantage of a generative LLM:
- It can REASON about context (a classifier just outputs probabilities)
- It can explain WHY something is toxic
- It handles subtle toxicity (sarcasm, implication, context) that
  classifiers miss

Architecture:
- Model: gemma3:1b (Apache-2.0, 1B params, ~770MB quantized)
- Runtime: Ollama on localhost:11434
- Prompt: structured JSON output request
- Threshold: detection = is_toxic==true AND confidence >= some_threshold

Validation:
- Held-out: 700 records from google/civil_comments test split
- 500 attack, 200 benign
- Target: 99% recall / 1% FPR (the user's ship gate)

This is the first attempt with a generative model. If it works, we
have a fundamentally better approach than the classifier.
"""
import json
import time
import urllib.request
import urllib.error
from pathlib import Path
from collections import Counter

LENS = Path('/home/chaos/Desktop/AegisGate/aegisgate-lens')
HELDOUT = LENS / 'corpora' / 'v01beta-raw' / 'v01beta-toxicity-heldout.jsonl'
PREDICTIONS = LENS / 'corpora' / 'v01beta-raw' / 'v01beta-toxicity-predictions-gemma.jsonl'
REPORT_PATH = LENS / 'docs' / 'PHASE-5d-GENERATIVE-LLM-REPORT.md'

OLLAMA_URL = 'http://localhost:11434/api/generate'
MODEL = 'gemma3:1b'

# Structured prompt for consistent JSON output
# Use {{ }} to escape curly braces in the f-string
PROMPT_TEMPLATE = (
    'You are a content moderation system. Analyze the following text and '
    'respond with ONLY a JSON object in this exact format: '
    '{{"is_toxic": true/false, "category": "hate|harassment|threat|sexual|self_harm|safe", '
    '"confidence": 0.0-1.0, "reason": "brief explanation"}}. '
    'Be precise. Text: "{text}"'
)


def call_ollama(text, model=MODEL, max_retries=2):
    """Call ollama and parse the JSON response."""
    prompt = PROMPT_TEMPLATE.format(text=text[:2000])  # truncate very long texts
    data = json.dumps({
        'model': model,
        'prompt': prompt,
        'stream': False,
        'options': {
            'num_predict': 300,
            'temperature': 0.0,  # deterministic
        }
    }).encode('utf-8')

    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(OLLAMA_URL, data=data, headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(req, timeout=120) as resp:
                result = json.loads(resp.read())
                response_text = result.get('response', '').strip()
                # Strip markdown ```json ... ``` blocks
                if '```' in response_text:
                    parts = response_text.split('```')
                    for p in parts:
                        p = p.strip()
                        if p.startswith('json'):
                            p = p[4:].strip()
                        if p.startswith('{'):
                            response_text = p
                            break
                # Try to parse JSON
                try:
                    parsed = json.loads(response_text)
                    return parsed
                except json.JSONDecodeError:
                    # Try to find JSON in the response
                    if '{' in response_text:
                        json_str = response_text[response_text.index('{'):response_text.rindex('}')+1]
                        try:
                            return json.loads(json_str)
                        except:
                            pass
                    if attempt < max_retries - 1:
                        continue
                    return None
        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(1)
                continue
            print(f'  ERROR: {e}')
            return None
    return None


def main():
    print(f'=== Phase 5d v4: Generative LLM toxicity detection ===')
    print(f'Model: {MODEL}')

    # Load held-out
    records = []
    for line in open(HELDOUT):
        try: records.append(json.loads(line))
        except: pass
    print(f'Held-out: {len(records)} records (500 attack + 200 benign)')

    # Run inference
    print(f'\nRunning inference on all {len(records)} records...')
    start = time.time()
    results = []
    for i, rec in enumerate(records):
        text = rec.get('text', '')
        label = rec.get('label', rec.get('expected_label'))
        rid = rec.get('id')

        parsed = call_ollama(text)
        if parsed:
            is_toxic = bool(parsed.get('is_toxic', False))
            category = parsed.get('category', 'safe')
            confidence = float(parsed.get('confidence', 0))
            reason = parsed.get('reason', '')
        else:
            is_toxic = False
            category = 'parse_error'
            confidence = 0.0
            reason = 'failed to parse'

        results.append({
            'id': rid,
            'label': label,
            'source': rec.get('source', '?'),
            'is_toxic': is_toxic,
            'category': category,
            'confidence': confidence,
            'reason': reason,
        })

        if (i + 1) % 50 == 0:
            elapsed = time.time() - start
            rate = (i + 1) / elapsed
            eta = (len(records) - i - 1) / rate
            print(f'  {i + 1}/{len(records)} done ({rate:.1f} req/s, ETA {eta:.0f}s)')

    total_time = time.time() - start
    print(f'\nTotal: {total_time:.1f}s for {len(records)} records = {len(records)/total_time:.1f} req/s')

    # Save raw predictions
    with open(PREDICTIONS, 'w') as f:
        for r in results:
            f.write(json.dumps(r) + '\n')
    print(f'Saved predictions: {PREDICTIONS}')

    # === THRESHOLD SWEEP (using confidence as the threshold) ===
    print(f'\n=== Threshold sweep (detection = is_toxic AND confidence >= threshold) ===')
    print(f'{"threshold":>10s}  {"recall":>8s}  {"fpr":>8s}  {"precision":>10s}  {"f1":>8s}  {"tp":>5s}  {"fn":>5s}  {"fp":>5s}  {"tn":>5s}')

    best_meets_gate = None
    best_f1_under_5pct = None
    for threshold_pct in range(0, 105, 5):
        threshold = threshold_pct / 100.0
        tp = fn = fp = tn = 0
        for r in results:
            label = r['label']
            # Detection: is_toxic=True AND confidence >= threshold
            detected = r['is_toxic'] and r['confidence'] >= threshold
            if label == 1 and detected: tp += 1
            elif label == 1 and not detected: fn += 1
            elif label == 0 and detected: fp += 1
            else: tn += 1
        recall = tp / max(1, tp + fn)
        fpr = fp / max(1, fp + tn)
        precision = tp / max(1, tp + fp)
        f1 = 2 * precision * recall / max(1e-9, precision + recall)
        marker = '  <-- MEETS 99%/1%!' if (recall >= 0.99 and fpr <= 0.01) else ''
        print(f'{threshold:>10.2f}  {recall:>8.4f}  {fpr:>8.4f}  {precision:>10.4f}  {f1:>8.4f}  {tp:>5d}  {fn:>5d}  {fp:>5d}  {tn:>5d}{marker}')
        if recall >= 0.99 and fpr <= 0.01:
            if best_meets_gate is None or f1 > best_meets_gate['f1']:
                best_meets_gate = {'threshold': threshold, 'recall': recall, 'fpr': fpr, 'f1': f1, 'tp': tp, 'fn': fn, 'fp': fp, 'tn': tn}

    # Best F1 with FPR <= 5%
    for threshold_pct in range(0, 100):
        threshold = threshold_pct / 100.0
        tp = fn = fp = tn = 0
        for r in results:
            label = r['label']
            detected = r['is_toxic'] and r['confidence'] >= threshold
            if label == 1 and detected: tp += 1
            elif label == 1 and not detected: fn += 1
            elif label == 0 and detected: fp += 1
            else: tn += 1
        fpr = fp / max(1, fp + tn)
        if fpr <= 0.05:
            recall = tp / max(1, tp + fn)
            precision = tp / max(1, tp + fp)
            f1 = 2 * precision * recall / max(1e-9, precision + recall)
            if best_f1_under_5pct is None or f1 > best_f1_under_5pct['f1']:
                best_f1_under_5pct = {'threshold': threshold, 'recall': recall, 'fpr': fpr, 'f1': f1, 'tp': tp, 'fn': fn, 'fp': fp, 'tn': tn}

    # === ALTERNATIVE: is_toxic alone (ignore confidence) ===
    tp = fn = fp = tn = 0
    for r in results:
        label = r['label']
        detected = r['is_toxic']  # ignore confidence
        if label == 1 and detected: tp += 1
        elif label == 1 and not detected: fn += 1
        elif label == 0 and detected: fp += 1
        else: tn += 1
    recall = tp / max(1, tp + fn)
    fpr = fp / max(1, fp + tn)
    precision = tp / max(1, tp + fp)
    f1 = 2 * precision * recall / max(1e-9, precision + recall)
    print(f'\nis_toxic alone (ignore confidence): recall={recall:.4f} fpr={fpr:.4f} f1={f1:.4f} tp={tp} fn={fn} fp={fp} tn={tn}')

    # Per-category breakdown
    print(f'\n=== Per-category breakdown (is_toxic detection only) ===')
    for cat in ['hate', 'harassment', 'threat', 'sexual', 'self_harm', 'safe']:
        tp_cat = sum(1 for r in results if r['label'] == 1 and r['category'] == cat)
        detected_as = [r['category'] for r in results if r['category'] == cat]
        print(f'  {cat}: ground_truth_attacks={tp_cat}, total_detected_as_this={len(detected_as)}')

    # === REPORT ===
    with open(REPORT_PATH, 'w') as f:
        f.write(f'# Phase 5d v4: Generative LLM toxicity detection report\n\n')
        f.write(f'**Date**: 2026-07-05\n\n')
        f.write(f'**Model**: {MODEL} (via Ollama, localhost:11434)\n\n')
        f.write(f'**Architecture**: generative LLM with structured JSON output prompt\n\n')
        f.write(f'**Held-out**: 700 records (500 attack + 200 benign) from google/civil_comments test split\n\n')
        f.write(f'**Inference time**: {total_time:.1f}s total, {len(records)/total_time:.1f} req/s\n\n')
        f.write(f'\n## Results\n\n')
        if best_meets_gate:
            f.write(f'### **SHIP GATE MET**: 99% recall / 1% FPR\n\n')
            f.write(f'Best threshold: {best_meets_gate}\n\n')
        else:
            f.write(f'### Ship gate NOT met.\n\n')
            f.write(f'Best F1 with FPR <= 5%: {best_f1_under_5pct}\n\n')
        f.write(f'\n### is_toxic alone (no confidence threshold)\n\n')
        f.write(f'recall={recall:.4f}, fpr={fpr:.4f}, f1={f1:.4f}\n\n')
    print(f'\nReport: {REPORT_PATH}')


if __name__ == '__main__':
    main()
