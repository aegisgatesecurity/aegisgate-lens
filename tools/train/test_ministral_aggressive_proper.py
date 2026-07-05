#!/usr/bin/env python3
"""
Ministral-3:3b with AGGRESSIVE prompt on PROPER held-out
"""
import json
import time
import urllib.request
from pathlib import Path

LENS = Path('/home/chaos/Desktop/AegisGate/aegisgate-lens')
HELDOUT = LENS / 'corpora' / 'v01beta-raw' / 'v01beta-toxicity-PROPER-heldout.jsonl'
PREDICTIONS = LENS / 'corpora' / 'v01beta-raw' / 'v01beta-model-eval' / 'predictions_ministral-3_3b_PROPER_AGGRESSIVE.jsonl'
REPORT = LENS / 'docs' / 'PHASE-5d-MINISTRAL-AGGRESSIVE-PROPER-RESULTS.md'

OLLAMA_URL = 'http://localhost:11434/api/generate'
MODEL = 'ministral-3:3b'

# Aggressive prompt (same one that got 97% recall on Jigsaw)
AGGRESSIVE_PROMPT = (
    'You are a STRICT content moderation system following the Civil '
    'Comments community standards. ANY of the following counts as toxic '
    'and MUST be flagged: rudeness, sarcasm, name-calling, profanity, '
    'condescension, threats, slurs, or any unfriendly/negligent/'
    'insulting/disagreeable content. Respond with ONLY a JSON object: '
    '{{"is_toxic": true/false, "confidence": 0.0-1.0}}. '
    'Be aggressive. Text: "{text}"'
)


def call_ollama(prompt, max_retries=2, timeout=60):
    data = json.dumps({
        'model': MODEL,
        'prompt': prompt,
        'stream': False,
        'options': {'num_predict': 50, 'temperature': 0.0}
    }).encode('utf-8')
    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(OLLAMA_URL, data=data, headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read()).get('response', '').strip()
        except:
            if attempt < max_retries - 1:
                time.sleep(1)
            else:
                return None


def parse_json(response):
    if not response:
        return None
    text = response
    if '```' in text:
        parts = text.split('```')
        for p in parts:
            p = p.strip()
            if p.startswith('json'):
                p = p[4:].strip()
            if p.startswith('{'):
                text = p
                break
    try:
        d = json.loads(text)
        return bool(d.get('is_toxic', False)), float(d.get('confidence', 0.5))
    except:
        pass
    if '{' in text and '}' in text:
        try:
            d = json.loads(text[text.index('{'):text.rindex('}')+1])
            return bool(d.get('is_toxic', False)), float(d.get('confidence', 0.5))
        except:
            pass
    return None


def main():
    print(f'=== Ministral-3:3b with AGGRESSIVE prompt on PROPER held-out ===')

    records = []
    for line in open(HELDOUT):
        try:
            records.append(json.loads(line))
        except:
            pass
    print(f'Loaded {len(records)} records')

    results = []
    start = time.time()
    parse_failures = 0
    for i, rec in enumerate(records):
        text = rec.get('text', '')[:1500]
        label = rec.get('label', rec.get('expected_label'))
        rid = rec.get('id')
        prompt = AGGRESSIVE_PROMPT.replace('{text}', text)
        response = call_ollama(prompt)
        parsed = parse_json(response) if response else None
        if parsed:
            is_toxic, conf = parsed
        else:
            is_toxic = False
            conf = 0.0
            parse_failures += 1
        results.append({
            'id': rid, 'label': label,
            'source': rec.get('source', '?'),
            'is_toxic': is_toxic, 'confidence': conf,
            'response_raw': (response or '')[:80],
        })
        if (i + 1) % 100 == 0:
            elapsed = time.time() - start
            rate = (i + 1) / elapsed
            eta = (len(records) - i - 1) / rate
            print(f'  {i + 1}/{len(records)} done ({rate:.1f} req/s, ETA {eta:.0f}s)')

    total_time = time.time() - start
    print(f'\nTotal: {total_time:.1f}s for {len(records)} records = {len(records)/total_time:.1f} req/s')
    print(f'Parse failures: {parse_failures}/{len(records)}')

    PREDICTIONS.parent.mkdir(parents=True, exist_ok=True)
    with open(PREDICTIONS, 'w') as f:
        for r in results:
            f.write(json.dumps(r) + '\n')

    print(f'\n=== Threshold sweep ===')
    print(f'{"thr":>6s}  {"recall":>7s}  {"fpr":>7s}  {"f1":>6s}  {"tp":>4s} {"fn":>4s} {"fp":>4s} {"tn":>4s}')

    best_gate = None
    best_f1_5pct = None
    for threshold_pct in range(0, 105, 5):
        threshold = threshold_pct / 100.0
        tp = fn = fp = tn = 0
        for r in results:
            label = r['label']
            detected = r['is_toxic'] and r['confidence'] >= threshold
            if label == 1 and detected:
                tp += 1
            elif label == 1 and not detected:
                fn += 1
            elif label == 0 and detected:
                fp += 1
            else:
                tn += 1
        recall = tp / max(1, tp + fn)
        fpr = fp / max(1, fp + tn)
        precision = tp / max(1, tp + fp)
        f1 = 2 * precision * recall / max(1e-9, precision + recall)
        marker = ' <-- GATE' if recall >= 0.99 and fpr <= 0.01 else ''
        print(f'{threshold:>6.2f}  {recall:>7.4f}  {fpr:>7.4f}  {f1:>6.3f}  {tp:>4d} {fn:>4d} {fp:>4d} {tn:>4d}{marker}')
        if recall >= 0.99 and fpr <= 0.01:
            if best_gate is None or f1 > best_gate['f1']:
                best_gate = {'threshold': threshold, 'recall': recall, 'fpr': fpr, 'f1': f1, 'tp': tp, 'fn': fn, 'fp': fp, 'tn': tn}
        if fpr <= 0.05:
            if best_f1_5pct is None or f1 > best_f1_5pct['f1']:
                best_f1_5pct = {'threshold': threshold, 'recall': recall, 'fpr': fpr, 'f1': f1, 'tp': tp, 'fn': fn, 'fp': fp, 'tn': tn}

    tp = fn = fp = tn = 0
    for r in results:
        label = r['label']
        detected = r['is_toxic']
        if label == 1 and detected:
            tp += 1
        elif label == 1 and not detected:
            fn += 1
        elif label == 0 and detected:
            fp += 1
        else:
            tn += 1
    recall = tp / max(1, tp + fn)
    fpr = fp / max(1, fp + tn)
    precision = tp / max(1, tp + fp)
    f1 = 2 * precision * recall / max(1e-9, precision + recall)
    print(f'\nis_toxic alone: recall={recall:.4f} fpr={fpr:.4f} f1={f1:.4f} tp={tp} fn={fn} fp={fp} tn={tn}')

    if best_gate:
        print(f'\nSHIP GATE MET: {best_gate}')
    else:
        print(f'\nShip gate NOT met. Best F1 with FPR <= 5%: {best_f1_5pct}')

    with open(REPORT, 'w') as f:
        f.write(f'# Phase 5d: Ministral-3:3b AGGRESSIVE on PROPER held-out\n\n')
        f.write(f'**Date**: 2026-07-05\n\n')
        f.write(f'**Model**: {MODEL} (aggressive prompt)\n\n')
        f.write(f'**Inference time**: {total_time:.1f}s = {len(records)/total_time:.1f} req/s\n\n')
        f.write(f'## Results\n\n')
        f.write(f'is_toxic alone: recall={recall:.4f}, fpr={fpr:.4f}, f1={f1:.4f}\n\n')
        if best_gate:
            f.write(f'### SHIP GATE MET: {best_gate}\n\n')
        else:
            f.write(f'### Ship gate NOT met. Best F1 with FPR <= 5%: {best_f1_5pct}\n\n')

    print(f'\nReport: {REPORT}')


if __name__ == '__main__':
    main()
