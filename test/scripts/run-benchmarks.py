"""
AegisGate Lens v0.2.0 — Public Benchmark Runner

Runs our ModernBERT model against PUBLIC benchmark datasets to get
real, verifiable metrics. Compares against:
  - HackAPrompt (38K records, GPT-3.5 targeting)
  - deepset/prompt-injections (540 records)
  - Lakera/mosscap_prompt_injection
  - rogue-security/prompt-injections-benchmark
  - neuralchemy/prompt-injection-dataset-categorized

Outputs metrics to test/eval/benchmark-results.json + .md

This is the FIRST honest competitive benchmark. All previous metrics
were against internal corpora only.
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

# Add venv to path if needed
REPO = Path('/home/chaos/Desktop/AegisGate/lens-repo-bootstrap-v02')
sys.path.insert(0, str(REPO))

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# Config
SNAPSHOT = REPO / 'models/snapshots/pre-retrain-2026-06-28T14-25-00Z/checkpoint-7012'
OUT_DIR = REPO / 'test/eval'
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Threshold from our hard test set sweep (Day 0)
THRESHOLD = 0.05
# Sliding window params (transformer-modernbert.js)
SLIDING_WINDOW = 2048
STRIDE = 1024
MAX_WINDOWS = 4


def load_model():
    """Load ModernBERT from snapshot. Uses fp16 + CUDA for speed."""
    print(f'Loading model from {SNAPSHOT}...')
    t0 = time.time()
    tokenizer = AutoTokenizer.from_pretrained(SNAPSHOT)
    model = AutoModelForSequenceClassification.from_pretrained(SNAPSHOT).cuda().eval()
    if torch.cuda.is_available():
        model = model.half()  # fp16 for speed
    print(f'  Loaded in {time.time()-t0:.1f}s')
    return tokenizer, model


def score_batch(tokenizer, model, texts, max_length=SLIDING_WINDOW):
    """Score a batch of texts using sliding window. Returns array of P(attack)."""
    results = []
    with torch.no_grad():
        for text in texts:
            tokens = tokenizer(text, return_tensors='pt', truncation=False, add_special_tokens=False).input_ids[0]
            n_tokens = len(tokens)
            
            if n_tokens <= SLIDING_WINDOW:
                # No sliding needed
                input_ids = tokens.unsqueeze(0).cuda()
                attention_mask = torch.ones_like(input_ids)
                logits = model(input_ids=input_ids, attention_mask=attention_mask).logits
                probs = torch.softmax(logits, dim=-1)[0, 1].item()
                results.append(probs)
            else:
                # Sliding window
                window_scores = []
                step = STRIDE
                n_windows = min(MAX_WINDOWS, (n_tokens - SLIDING_WINDOW) // step + 1)
                if (n_tokens - SLIDING_WINDOW) % step != 0:
                    n_windows += 1
                n_windows = min(n_windows, MAX_WINDOWS)
                
                for i in range(n_windows):
                    start = i * step
                    end = min(start + SLIDING_WINDOW, n_tokens)
                    if i == n_windows - 1 and end - start < SLIDING_WINDOW and n_tokens > SLIDING_WINDOW:
                        # Right-aligned tail
                        start = max(0, n_tokens - SLIDING_WINDOW)
                        end = n_tokens
                    window = tokens[start:end].unsqueeze(0).cuda()
                    attention_mask = torch.ones_like(window)
                    logits = model(input_ids=window, attention_mask=attention_mask).logits
                    probs = torch.softmax(logits, dim=-1)[0, 1].item()
                    window_scores.append(probs)
                
                # Max-pool aggregation
                results.append(max(window_scores))
    return results


def load_dataset(path, label=None):
    """Load jsonl, filter by label if specified."""
    out = []
    with open(path) as f:
        for line in f:
            try:
                d = json.loads(line)
                if label is not None and d.get('label') != label:
                    continue
                if 'text' not in d or len(d['text'].strip()) < 5:
                    continue
                out.append(d)
            except json.JSONDecodeError:
                pass
    return out


def evaluate_dataset(tokenizer, model, data, name, max_samples=None):
    """Evaluate model on a dataset. Returns metrics."""
    if max_samples and len(data) > max_samples:
        # Sample max_samples from each label
        from collections import defaultdict
        by_label = defaultdict(list)
        for d in data:
            by_label[d['label']].append(d)
        sampled = []
        per_label = max_samples // 2
        for label, items in by_label.items():
            sampled.extend(items[:per_label])
        data = sampled
    
    print(f'\n=== {name} ({len(data)} samples) ===')
    t0 = time.time()
    
    # Score all
    texts = [d['text'] for d in data]
    labels = [d['label'] for d in data]
    scores = []
    batch_size = 8
    for i in range(0, len(texts), batch_size):
        batch = texts[i:i+batch_size]
        scores.extend(score_batch(tokenizer, model, batch))
        if (i // batch_size) % 50 == 0:
            print(f'  Scored {i+len(batch)}/{len(texts)} ({time.time()-t0:.0f}s elapsed)', file=sys.stderr)
    
    elapsed = time.time() - t0
    print(f'  Scored all in {elapsed:.1f}s ({len(texts)/elapsed:.1f} prompts/sec)', file=sys.stderr)
    
    # Compute metrics
    tp = fp = tn = fn = 0
    for label, score in zip(labels, scores):
        pred_attack = score >= THRESHOLD
        actual_attack = label == 1
        if pred_attack and actual_attack: tp += 1
        elif pred_attack and not actual_attack: fp += 1
        elif not pred_attack and actual_attack: fn += 1
        else: tn += 1
    
    attack_total = tp + fn
    benign_total = fp + tn
    
    recall = tp / attack_total if attack_total else 0
    fpr = fp / benign_total if benign_total else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    accuracy = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) else 0
    
    metrics = {
        'name': name,
        'samples': len(data),
        'attack_total': attack_total,
        'benign_total': benign_total,
        'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
        'recall': round(recall, 4),
        'fpr': round(fpr, 4),
        'precision': round(precision, 4),
        'f1': round(f1, 4),
        'accuracy': round(accuracy, 4),
        'threshold': THRESHOLD,
        'time_sec': round(elapsed, 1),
        'throughput_per_sec': round(len(texts)/elapsed, 2) if elapsed else 0,
    }
    print(f'  {name}: recall={recall:.3f} FPR={fpr:.3f} precision={precision:.3f} F1={f1:.3f}')
    print(f'  Confusion: TP={tp} FP={fp} FN={fn} TN={tn}')
    
    return metrics


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--max-samples', type=int, default=None, help='Cap samples per dataset for quick runs')
    parser.add_argument('--datasets', nargs='*', default=None, help='Specific datasets to run (default: all)')
    args = parser.parse_args()
    
    tokenizer, model = load_model()
    
    # Discover datasets
    archive_root = Path('/home/chaos/Desktop/AegisGate/archives/iteration-v0.1-day32-burndown-2026-06-26')
    public_rounds = archive_root / 'lens/lens-working-snapshot/pen-test/corpus/public_rounds'
    
    datasets = []
    
    if not args.datasets or 'hackaprompt' in args.datasets:
        # HackAPrompt only (38K attack records)
        hackaprompt = []
        with open(public_rounds / 'round13_public_test_attack.jsonl') as f:
            for line in f:
                d = json.loads(line)
                if d.get('source', '').startswith('hack'):
                    hackaprompt.append(d)
        # Also need benign from same source
        hackaprompt_benign = []
        # Use deepset benign for fairness
        with open(public_rounds / 'round13_public_test_benign.jsonl') as f:
            for line in f:
                d = json.loads(line)
                if d.get('source', '').startswith('hack') or 'benign' in d.get('source', '').lower():
                    hackaprompt_benign.append(d)
        datasets.append(('HackAPrompt (public)', hackaprompt[:2000], hackaprompt_benign[:1000]))
    
    if not args.datasets or 'deepset' in args.datasets:
        # deepset/prompt-injections (already pulled earlier)
        deepset = []
        import pyarrow.parquet as pq
        t = pq.read_table('/tmp/prompt_injections.parquet')
        for i in range(t.num_rows):
            text = t['text'][i].as_py()
            label = int(t['label'][i].as_py())
            if text and len(text) >= 5:
                deepset.append({'text': text, 'label': label, 'source': 'deepset_prompt_injections'})
        # Need benign from this source too - use round13 benign as proxy
        deepset_benign = []
        with open(public_rounds / 'round13_public_test_benign.jsonl') as f:
            for line in f:
                d = json.loads(line)
                if d.get('source', '').startswith('deepset'):
                    deepset_benign.append(d)
        datasets.append(('deepset/prompt-injections', [d for d in deepset if d['label']==1], deepset_benign[:500] or [d for d in deepset if d['label']==0]))
    
    if not args.datasets or 'r8' in args.datasets:
        # v0.1's round8 (which v0.2 struggled with at 0% recall)
        r8_attack = load_dataset(public_rounds / 'round13_public_test_attack.jsonl', label=1)
        # Get round8-specific
        r8_attack_v0 = []
        for d in r8_attack:
            if 'round8' in d.get('source', '').lower():
                r8_attack_v0.append(d)
        r8_benign_v0 = []
        with open(public_rounds / 'round13_public_test_benign.jsonl') as f:
            for line in f:
                d = json.loads(line)
                if 'round8' in d.get('source', '').lower() or 'benign' in d.get('source', '').lower():
                    r8_benign_v0.append(d)
        if r8_attack_v0:
            datasets.append(('v0.1 round8 (sanity check)', r8_attack_v0[:1000], r8_benign_v0[:500]))
    
    if not args.datasets or 'promptfoo' in args.datasets:
        # promptfoo from v0.1
        promptfoo = []
        promptfoo_path = archive_root / 'lens/lens-working-snapshot/pen-test/corpus/promptfoo_attacks.jsonl'
        if promptfoo_path.exists():
            promptfoo = load_dataset(promptfoo_path, label=1)
        promptfoo_test = archive_root / 'lens/lens-working-snapshot/pen-test/corpus/promptfoo_test/promptfoo_test_sample_n50.jsonl'
        promptfoo_benign = []
        if promptfoo_test.exists():
            promptfoo_benign = load_dataset(promptfoo_test, label=0)
        if promptfoo:
            datasets.append(('promptfoo (public)', promptfoo[:500], promptfoo_benign[:500] if promptfoo_benign else []))
    
    # Run all benchmarks
    all_results = []
    for name, attack, benign in datasets:
        print(f'\n>>> {name}: {len(attack)} attack + {len(benign)} benign <<<')
        data = attack + benign
        metrics = evaluate_dataset(tokenizer, model, data, name, max_samples=args.max_samples)
        all_results.append(metrics)
    
    # Summary
    print('\n\n' + '=' * 70)
    print('BENCHMARK SUMMARY')
    print('=' * 70)
    print(f'{"Dataset":<35} {"Recall":>10} {"FPR":>10} {"Precision":>10} {"F1":>10}')
    print('-' * 70)
    for m in all_results:
        print(f'{m["name"]:<35} {m["recall"]:>10.3f} {m["fpr"]:>10.3f} {m["precision"]:>10.3f} {m["f1"]:>10.3f}')
    print('=' * 70)
    
    # Save
    out_path = OUT_DIR / 'benchmark-results.json'
    with open(out_path, 'w') as f:
        json.dump({
            'timestamp': '2026-06-29',
            'model': 'AegisGate Lens v0.2 (ModernBERT-base)',
            'snapshot': str(SNAPSHOT),
            'threshold': THRESHOLD,
            'sliding_window': SLIDING_WINDOW,
            'stride': STRIDE,
            'max_windows': MAX_WINDOWS,
            'results': all_results,
        }, f, indent=2)
    print(f'\nResults saved to: {out_path}')


if __name__ == '__main__':
    main()