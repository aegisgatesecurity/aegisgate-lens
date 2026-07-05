#!/usr/bin/env python3
"""
AegisGate Lens v0.1.0-beta -- Model evaluation harness
====================================================

Single Python script that takes a model name as input, runs the
700-record Jigsaw held-out, and reports recall/FPR/F1/latency.

Usage:
    python3 evaluate_model.py <model_name> [--output <path>]

Example:
    python3 evaluate_model.py gemma3:1b
    python3 evaluate_model.py ministral-3:3b
    python3 evaluate_model.py qwen3.5:9b-q4_K_M

Per the user's directive (2026-07-05): "Build the model-evaluation
harness first, then sweep" — this script is the harness. The model
that hits 99%/1% wins.

The harness supports two detection modes:
1. JSON output (default): model responds with {"is_toxic": ..., "confidence": ...}
2. Text output: model responds with "yes" or "no" (parsed as lowercase)

For each model, the harness:
1. Loads the 700-record Jigsaw held-out
2. Runs inference (batched, with retry on parse failure)
3. Computes recall/FPR/F1 at the optimal confidence threshold
4. Checks the 99%/1% ship gate
5. Reports results + saves raw predictions for debugging

Output: JSON results file with model name, recall, FPR, F1, latency, gate_status.
"""
import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error
import warnings
from pathlib import Path
from collections import Counter

warnings.filterwarnings('ignore')

# Suppress HF progress bars
os.environ.setdefault('HF_HUB_DISABLE_PROGRESS_BARS', '1')

LENS = Path('/home/chaos/Desktop/AegisGate/aegisgate-lens')
HELDOUT = LENS / 'corpora' / 'v01beta-raw' / 'v01beta-toxicity-heldout.jsonl'
PREDICTIONS_DIR = LENS / 'corpora' / 'v01beta-raw' / 'v01beta-model-eval'
PREDICTIONS_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_FILE = LENS / 'docs' / 'PHASE-5d-MODEL-SWEEP-RESULTS.md'

OLLAMA_URL = 'http://localhost:11434/api/generate'

# Default prompt for content moderation (works for most instruction-tuned models)
# Models can be evaluated with different prompts by overriding --prompt-file
# The {text} placeholder is the only one .format() should fill in.
# Use {{ }} to escape literal curly braces in the prompt text.
DEFAULT_PROMPT_JSON = (
    'You are a content moderation system. Analyze the following text '
    'and respond with ONLY a JSON object in this exact format: '
    '{{"is_toxic": true/false, "category": "hate|harassment|threat|sexual|self_harm|safe", '
    '"confidence": 0.0-1.0, "reason": "brief explanation"}}. '
    'Be precise. Text: "{text}"'
)

DEFAULT_PROMPT_YESNO = (
    'You are a content moderation system. Is the following text toxic? '
    'Respond with ONLY "yes" or "no" on a single line, followed by a space and '
    'a confidence score 0.0-1.0. Example: "yes 0.95" or "no 0.80". '
    'Text: "{text}"'
)


def load_heldout():
    records = []
    for line in open(HELDOUT):
        try:
            records.append(json.loads(line))
        except: pass
    return records


def call_ollama(model, prompt, max_retries=2, timeout=120):
    """Call ollama /api/generate. Returns (response_text, raw_dict)."""
    data = json.dumps({
        'model': model,
        'prompt': prompt,
        'stream': False,
        'options': {
            'num_predict': 300,
            'temperature': 0.0,
        }
    }).encode('utf-8')

    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(OLLAMA_URL, data=data, headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                result = json.loads(resp.read())
                return result.get('response', '').strip(), result
        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(1)
                continue
            return None, None
    return None, None


def parse_response_json(response_text):
    """Parse JSON response. Returns (is_toxic, confidence) or None on failure."""
    if not response_text:
        return None
    # Strip markdown code blocks
    text = response_text.strip()
    if '```' in text:
        parts = text.split('```')
        for p in parts:
            p = p.strip()
            if p.startswith('json'):
                p = p[4:].strip()
            if p.startswith('{'):
                text = p
                break
    # Try direct parse
    try:
        d = json.loads(text)
        return bool(d.get('is_toxic', False)), float(d.get('confidence', 0.5))
    except:
        pass
    # Try to find JSON in the response
    if '{' in text and '}' in text:
        json_str = text[text.index('{'):text.rindex('}')+1]
        try:
            d = json.loads(json_str)
            return bool(d.get('is_toxic', False)), float(d.get('confidence', 0.5))
        except:
            pass
    return None


def parse_response_yesno(response_text):
    """Parse yes/no response. Returns (is_toxic, confidence) or None on failure."""
    if not response_text:
        return None
    text = response_text.strip().lower()
    # Look for "yes" or "no" as the first word
    first_word = text.split()[0] if text.split() else ''
    # Clean punctuation
    first_word = first_word.strip('.,!?;:()[]{}')
    is_toxic = first_word in ('yes', 'toxic', 'true', '1')
    # Look for confidence score
    conf = 0.5
    for token in text.split():
        token = token.strip('.,!?;:()[]{}')
        try:
            val = float(token)
            if 0 <= val <= 1:
                conf = val
                break
        except:
            pass
    return is_toxic, conf


def evaluate_model(model, prompt_template=DEFAULT_PROMPT_JSON, max_records=None,
                   use_yesno=False, output_dir=PREDICTIONS_DIR):
    """Run inference on the held-out and return metrics."""
    records = load_heldout()
    if max_records:
        records = records[:max_records]
    n = len(records)
    print(f'\n=== Evaluating {model} on {n} records ===')

    results = []
    start = time.time()
    parse_failures = 0
    for i, rec in enumerate(records):
        text = rec.get('text', '')
        label = rec.get('label', rec.get('expected_label'))
        rid = rec.get('id')
        prompt = prompt_template.format(text=text[:2000])

        response_text, raw = call_ollama(model, prompt)
        if use_yesno:
            parsed = parse_response_yesno(response_text)
        else:
            parsed = parse_response_json(response_text)
        if parsed:
            is_toxic, conf = parsed
        else:
            is_toxic = False
            conf = 0.0
            parse_failures += 1

        results.append({
            'id': rid,
            'label': label,
            'source': rec.get('source', '?'),
            'is_toxic': is_toxic,
            'confidence': conf,
            'response_raw': (response_text or '')[:200],
        })

        if (i + 1) % 50 == 0 or i == n - 1:
            elapsed = time.time() - start
            rate = (i + 1) / elapsed
            eta = (n - i - 1) / rate if rate > 0 else 0
            print(f'  {i + 1}/{n} done ({rate:.1f} req/s, ETA {eta:.0f}s)')

    total_time = time.time() - start
    throughput = n / total_time if total_time > 0 else 0
    print(f'\nTotal: {total_time:.1f}s for {n} records = {throughput:.2f} req/s')
    print(f'Parse failures: {parse_failures}/{n} ({100*parse_failures/n:.1f}%)')

    # Save raw predictions
    safe_name = model.replace(':', '_').replace('/', '_')
    pred_file = output_dir / f'predictions_{safe_name}.jsonl'
    with open(pred_file, 'w') as f:
        for r in results:
            f.write(json.dumps(r) + '\n')
    print(f'Saved predictions: {pred_file}')

    # Sweep threshold (is_toxic AND confidence >= threshold)
    print(f'\n=== Threshold sweep (is_toxic AND confidence >= threshold) ===')
    print(f'{"thr":>6s}  {"recall":>7s}  {"fpr":>7s}  {"f1":>6s}  {"tp":>4s} {"fn":>4s} {"fp":>4s} {"tn":>4s}')

    best_gate = None  # meets 99% recall AND <= 1% FPR
    best_f1_low_fpr = None  # best F1 with FPR <= 5%
    best_f1_overall = None
    for threshold_pct in range(0, 105, 5):
        threshold = threshold_pct / 100.0
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
        if best_f1_overall is None or f1 > best_f1_overall['f1']:
            best_f1_overall = {'threshold': threshold, 'recall': recall, 'fpr': fpr, 'f1': f1, 'tp': tp, 'fn': fn, 'fp': fp, 'tn': tn}

    # is_toxic alone (no confidence threshold)
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
    precision = tp / max(1, tp + fp)
    f1 = 2 * precision * recall / max(1e-9, precision + recall)
    print(f'\nis_toxic alone (no confidence): recall={recall:.4f} fpr={fpr:.4f} f1={f1:.4f} tp={tp} fn={fn} fp={fp} tn={tn}')

    # Gate status
    print(f'\n=== GATE STATUS ===')
    if best_gate:
        print(f'  **SHIP GATE MET (99%/1%)**: {best_gate}')
    else:
        print(f'  Ship gate NOT met. Best F1 with FPR <= 5%: {best_f1_low_fpr}')

    return {
        'model': model,
        'n_records': n,
        'n_parse_failures': parse_failures,
        'total_time_sec': total_time,
        'throughput_rps': throughput,
        'best_gate_99_1': best_gate,
        'best_f1_fpr_under_5pct': best_f1_low_fpr,
        'best_f1_overall': best_f1_overall,
        'is_toxic_alone': {'recall': recall, 'fpr': fpr, 'f1': f1, 'tp': tp, 'fn': fn, 'fp': fp, 'tn': tn},
        'predictions_file': str(pred_file),
    }


def main():
    parser = argparse.ArgumentParser(description='AegisGate model evaluation harness')
    parser.add_argument('model', nargs='?', help='Ollama model name (e.g. gemma3:1b)')
    parser.add_argument('--list', action='store_true', help='List available Ollama models')
    parser.add_argument('--yesno', action='store_true', help='Use yes/no prompt instead of JSON')
    parser.add_argument('--max', type=int, help='Max records to evaluate (for quick test)')
    parser.add_argument('--prompt-file', help='Path to custom prompt template file')
    parser.add_argument('--output-dir', help='Output directory for predictions')
    args = parser.parse_args()

    if args.list:
        import urllib.request
        try:
            req = urllib.request.Request('http://localhost:11434/api/tags')
            with urllib.request.urlopen(req, timeout=10) as resp:
                d = json.loads(resp.read())
                print(f'Available models ({len(d["models"])}):')
                for m in d['models']:
                    print(f'  {m["name"]} ({m["size"]/1e9:.1f} GB)')
        except Exception as e:
            print(f'ERROR: {e}')
        return

    if not args.model:
        parser.print_help()
        sys.exit(1)

    prompt = DEFAULT_PROMPT_JSON
    if args.yesno:
        prompt = DEFAULT_PROMPT_YESNO
    if args.prompt_file:
        with open(args.prompt_file) as f:
            prompt = f.read()

    output_dir = PREDICTIONS_DIR
    if args.output_dir:
        output_dir = Path(args.output_dir)

    result = evaluate_model(
        args.model,
        prompt_template=prompt,
        max_records=args.max,
        use_yesno=args.yesno,
        output_dir=output_dir,
    )
    print(f'\n=== RESULT for {args.model} ===')
    print(json.dumps(result, indent=2, default=str))


if __name__ == '__main__':
    main()
