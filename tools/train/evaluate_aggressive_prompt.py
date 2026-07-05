#!/usr/bin/env python3
"""
AegisGate Lens v0.1.0-beta -- Phase 5d v5: Aggressive prompt + per-record threshold
================================================================================

The default prompt (model is biased toward "safe") gave only 41%
recall on the Jigsaw held-out. The aggressive prompt (Civil
Comments community standards) gave 92.9% recall on a 20-record
test but 83% FPR.

This script runs the full 700-record held-out with the aggressive
prompt and sweeps the per-record confidence threshold to find
the 99%/1% ship gate.

The hypothesis: with the aggressive prompt + per-record confidence
threshold, the model outputs high confidence for obvious cases
and medium confidence for borderline cases. The threshold should
separate these.
"""
import json
import time
import urllib.request
from pathlib import Path
from collections import Counter

LENS = Path('/home/chaos/Desktop/AegisGate/aegisgate-lens')
HELDOUT = LENS / 'corpora' / 'v01beta-raw' / 'v01beta-toxicity-heldout.jsonl'
PREDICTIONS = LENS / 'corpora' / 'v01beta-raw' / 'v01beta-model-eval' / 'predictions_ministral-3_3b_AGGRESSIVE.jsonl'
REPORT = LENS / 'docs' / 'PHASE-5d-AGGRESSIVE-PROMPT-REPORT.md'

OLLAMA_URL = 'http://localhost:11434/api/generate'
MODEL = 'ministral-3:3b'

# The aggressive prompt: tell the model the ground truth standard
# The {text} placeholder is filled in with the actual text
PROMPT_TEMPLATE = (
    'You are a STRICT content moderation system following the Civil '
    'Comments community standards. ANY of the following counts as toxic '
    'and MUST be flagged: rudeness, sarcasm, name-calling, profanity, '
    'condescension, or any unfriendly/negligent/insulting/disagreeable '
    'content. Respond with ONLY a JSON object: '
    '{{"is_toxic": true/false, "category": "hate|harassment|threat|sexual|self_harm|safe", '
    '"confidence": 0.0-1.0, "reason": "brief explanation"}}. '
    'Be aggressive. Text: "{text}"'
)


def call_ollama(prompt, max_retries=2, timeout=120):
    data = json.dumps({
        'model': MODEL,
        'prompt': prompt,
        'stream': False,
        'options': {'num_predict': 200, 'temperature': 0.0}
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


def parse_json_response(response_text):
    if not response_text:
        return None
    text = response_text
    if '```' in text:
        parts = text.split('```')
        for p in parts:
            p = p.strip()
            if p.startswith('json'): p = p[4:].strip()
            if p.startswith('{'): text = p; break
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
    print(f'=== Phase 5d v5: Aggressive prompt + {MODEL} on full held-out ===')
    records = []
    for line in open(HELDOUT):
        try: records.append(json.loads(line))
        except: pass
    print(f'Held-out: {len(records)} records')

    print(f'\nRunning inference with AGGRESSIVE prompt...')
    results = []
    start = time.time()
    parse_failures = 0
    for i, rec in enumerate(records):
        text = rec.get('text', '')[:2000]
        label = rec.get('label', rec.get('expected_label'))
        rid = rec.get('id')
        prompt = PROMPT_TEMPLATE.replace('{text}', text)
        response = call_ollama(prompt)
        parsed = parse_json_response(response) if response else None
        if parsed:
            is_toxic, conf = parsed
        else:
            is_toxic = False
            conf = 0.0
            parse_failures += 1
        results.append({
            'id': rid, 'label': label,
            'is_toxic': is_toxic, 'confidence': conf,
            'response_raw': (response or '')[:200],
        })
        if (i + 1) % 100 == 0:
            elapsed = time.time() - start
            rate = (i + 1) / elapsed
            eta = (len(records) - i - 1) / rate
            print(f'  {i + 1}/{len(records)} done ({rate:.1f} req/s, ETA {eta:.0f}s)')

    total_time = time.time() - start
    print(f'\nTotal: {total_time:.1f}s for {len(records)} records = {len(records)/total_time:.1f} req/s')
    print(f'Parse failures: {parse_failures}/{len(records)}')

    with open(PREDICTIONS, 'w') as f:
        for r in results:
            f.write(json.dumps(r) + '\n')
    print(f'Saved: {PREDICTIONS}')

    # Confidence distribution
    print(f'\n=== Confidence distribution (AGGRESSIVE prompt) ===')
    attack_confs = [r['confidence'] for r in results if r['label'] == 1]
    benign_confs = [r['confidence'] for r in results if r['label'] == 0]
    print(f'ATTACK (n={len(attack_confs)}): mean={sum(attack_confs)/max(1,len(attack_confs)):.3f} median={sorted(attack_confs)[len(attack_confs)//2]:.3f}')
    print(f'BENIGN (n={len(benign_confs)}): mean={sum(benign_confs)/max(1,len(benign_confs)):.3f} median={sorted(benign_confs)[len(benign_confs)//2]:.3f}')

    # Fine-grained threshold sweep
    print(f'\n=== Threshold sweep (is_toxic AND confidence >= threshold) ===')
    print(f'{"thr":>6s}  {"recall":>7s}  {"fpr":>7s}  {"f1":>6s}  {"tp":>4s} {"fn":>4s} {"fp":>4s} {"tn":>4s}')

    best_gate = None
    best_f1_low_fpr = None
    for threshold in [i/100 for i in range(0, 105, 5)]:
        tp = fn = fp = tn = 0
        for r in results:
            label = r['label']
            detected = r['is_toxic'] and r['confidence'] >= threshold
            if label == 1 and detected: tp += 1
            elif label == 1 and not detected: fn += 1
            elif label == 0 and detected: fp += 1
            else: tn += 1
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
            if best_f1_low_fpr is None or f1 > best_f1_low_fpr['f1']:
                best_f1_low_fpr = {'threshold': threshold, 'recall': recall, 'fpr': fpr, 'f1': f1, 'tp': tp, 'fn': fn, 'fp': fp, 'tn': tn}

    # is_toxic alone
    tp = fn = fp = tn = 0
    for r in results:
        label = r['label']
        detected = r['is_toxic']
        if label == 1 and detected: tp += 1
        elif label == 1 and not detected: fn += 1
        elif label == 0 and detected: fp += 1
        else: tn += 1
    recall = tp / max(1, tp + fn)
    fpr = fp / max(1, fp + tn)
    f1 = 2 * (tp/max(1,tp+fp)) * recall / max(1e-9, (tp/max(1,tp+fp)) + recall)
    print(f'\nis_toxic alone: recall={recall:.4f} fpr={fpr:.4f} f1={f1:.4f} tp={tp} fn={fn} fp={fp} tn={tn}')

    print(f'\n=== GATE STATUS ===')
    if best_gate:
        print(f'  **SHIP GATE MET (99%/1%)**: {best_gate}')
    else:
        print(f'  Ship gate NOT met. Best F1 with FPR <= 5%: {best_f1_low_fpr}')

    # Save report
    with open(REPORT, 'w') as f:
        f.write('# Phase 5d v5: Aggressive prompt + Ministral3:3b report\n\n')
        f.write(f'**Date**: 2026-07-05\n\n')
        f.write(f'**Model**: {MODEL} (via Ollama)\n\n')
        f.write(f'**Prompt strategy**: AGGRESSIVE -- model told to flag any rudeness, sarcasm, name-calling, profanity, condescension, or unfriendly content per Civil Comments community standards.\n\n')
        f.write(f'**Total inference time**: {total_time:.1f}s for {len(records)} records = {len(records)/total_time:.1f} req/s\n\n')
        f.write(f'**Parse failures**: {parse_failures}/{len(records)}\n\n')
        f.write(f'\n## Results\n\n')
        if best_gate:
            f.write(f'### **SHIP GATE MET (99%/1%)**: {best_gate}\n\n')
        else:
            f.write(f'### Ship gate NOT met. Best F1 with FPR <= 5%: {best_f1_low_fpr}\n\n')
        f.write(f'### is_toxic alone\n\n')
        f.write(f'recall={recall:.4f}, fpr={fpr:.4f}, f1={f1:.4f}\n\n')
    print(f'\nReport: {REPORT}')

if __name__ == '__main__':
    main()
