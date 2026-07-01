"""
Compare sliding-window inference strategies on the snapshot model.

Configs tested:
  A. max_length=2048, stride=1024, max_windows=8  → coverage 9216 tokens
  B. max_length=4096, stride=2048, max_windows=8  → coverage 18432 tokens
  C. max_length=4096, stride=1024, max_windows=8  → coverage 11264 tokens (high overlap)
  D. adaptive: single window up to 8192, then sliding 4096/2048/8

Test on r8_attack_long_context (the hardest corpus).
"""
import json
import time
import sys
from pathlib import Path

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

SNAPSHOT = Path('/home/chaos/Desktop/AegisGate/lens-repo-bootstrap-v02/models/snapshots/pre-retrain-2026-06-28T14-25-00Z/checkpoint-7012')
CORPUS = Path('/home/chaos/Desktop/AegisGate/lens-repo-bootstrap-v02/corpora/r8_attack_long_context.jsonl')

print('Loading model...')
t0 = time.time()
tokenizer = AutoTokenizer.from_pretrained(SNAPSHOT)
model = AutoModelForSequenceClassification.from_pretrained(SNAPSHOT)
model.eval()
if torch.cuda.is_available():
    model = model.cuda()
print(f'  loaded in {time.time()-t0:.1f}s, device={"cuda" if torch.cuda.is_available() else "cpu"}')

# Load corpus (sample 60 records for speed: 30 attacks + 30 benign)
import random
random.seed(42)
records = []
with open(CORPUS) as f:
    for line in f:
        records.append(json.loads(line))
attacks = [r for r in records if r['label'] == 1]
benign = [r for r in records if r['label'] == 0]
records = random.sample(attacks, 12)
benign_sample = random.sample(benign, min(8, len(benign)))
records = records + benign_sample
random.shuffle(records)
print(f'Corpus (sample for speed): {len(records)} records (12 attack + {len(benign_sample)} benign)')

def score_sliding(text, max_length, stride, max_windows, threshold=0.5):
    """Sliding-window inference. Returns P(attack) = max P(attack) across all windows."""
    enc = tokenizer(text, return_tensors='pt', add_special_tokens=False)
    ids = enc['input_ids'][0]
    if len(ids) <= max_length:
        # Single window
        chunk = ids[:max_length]
        padded = torch.cat([torch.tensor([tokenizer.cls_token_id]), chunk, torch.tensor([tokenizer.sep_token_id])])
        padded = padded.unsqueeze(0)
        attn = torch.ones_like(padded)
        if torch.cuda.is_available():
            padded, attn = padded.cuda(), attn.cuda()
        with torch.no_grad():
            logits = model(input_ids=padded, attention_mask=attn).logits
        return float(torch.softmax(logits, dim=-1)[0, 1].cpu())
    # Sliding window
    windows = []
    for start in range(0, len(ids), stride):
        end = min(start + max_length, len(ids))
        chunk = ids[start:end]
        padded = torch.cat([torch.tensor([tokenizer.cls_token_id]), chunk, torch.tensor([tokenizer.sep_token_id])])
        windows.append(padded)
        if len(windows) >= max_windows:
            break
    # Pad all to same length
    max_len = max(w.size(0) for w in windows)
    padded_batch = torch.zeros(len(windows), max_len, dtype=torch.long)
    attn_batch = torch.zeros(len(windows), max_len, dtype=torch.long)
    for i, w in enumerate(windows):
        padded_batch[i, :w.size(0)] = w
        attn_batch[i, :w.size(0)] = 1
    if torch.cuda.is_available():
        padded_batch, attn_batch = padded_batch.cuda(), attn_batch.cuda()
    with torch.no_grad():
        logits = model(input_ids=padded_batch, attention_mask=attn_batch).logits
    probs = torch.softmax(logits, dim=-1)[:, 1]
    return float(probs.max().cpu())

def evaluate(config_name, max_length, stride, max_windows):
    tp = fp = fn = tn = 0
    total_time = 0
    for r in records:
        t0 = time.time()
        score = score_sliding(r['text'], max_length, stride, max_windows)
        dt = time.time() - t0
        total_time += dt
        pred = 1 if score >= 0.5 else 0
        if r['label'] == 1 and pred == 1: tp += 1
        elif r['label'] == 0 and pred == 1: fp += 1
        elif r['label'] == 1 and pred == 0: fn += 1
        else: tn += 1
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    f1 = 2*precision*recall / (precision+recall) if (precision+recall) > 0 else 0
    coverage = (max_windows - 1) * stride + max_length if len(records) > 0 else max_length
    print(f'\n=== {config_name} ===')
    print(f'  max_length={max_length}, stride={stride}, max_windows={max_windows}')
    print(f'  theoretical coverage: {coverage} tokens')
    print(f'  TP={tp} FP={fp} FN={fn} TN={tn}')
    print(f'  recall={recall:.4f}, fpr={fpr:.4f}, precision={precision:.4f}, f1={f1:.4f}')
    print(f'  total inference time: {total_time:.1f}s ({total_time/len(records)*1000:.0f}ms per doc avg)')
    return {'recall': recall, 'fpr': fpr, 'precision': precision, 'f1': f1, 'coverage': coverage, 'time': total_time}

def evaluate_batched(config_name, max_length, stride, max_windows):
    """Batched sliding window — all windows in single forward pass."""
    tp = fp = fn = tn = 0
    total_time = 0
    for r in records:
        t0 = time.time()
        score = score_sliding_batched(r['text'], max_length, stride, max_windows)
        dt = time.time() - t0
        total_time += dt
        pred = 1 if score >= 0.5 else 0
        if r['label'] == 1 and pred == 1: tp += 1
        elif r['label'] == 0 and pred == 1: fp += 1
        elif r['label'] == 1 and pred == 0: fn += 1
        else: tn += 1
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    f1 = 2*precision*recall / (precision+recall) if (precision+recall) > 0 else 0
    coverage = (max_windows - 1) * stride + max_length if len(records) > 0 else max_length
    print(f'\n=== {config_name} (BATCHED) ===')
    print(f'  max_length={max_length}, stride={stride}, max_windows={max_windows}')
    print(f'  theoretical coverage: {coverage} tokens')
    print(f'  TP={tp} FP={fp} FN={fn} TN={tn}')
    print(f'  recall={recall:.4f}, fpr={fpr:.4f}, precision={precision:.4f}, f1={f1:.4f}')
    print(f'  total inference time: {total_time:.1f}s ({total_time/len(records)*1000:.0f}ms per doc avg)')
    return {'recall': recall, 'fpr': fpr, 'precision': precision, 'f1': f1, 'coverage': coverage, 'time': total_time}

def score_sliding_batched(text, max_length, stride, max_windows, threshold=0.5):
    """Batched sliding-window inference — single forward pass per document."""
    enc = tokenizer(text, return_tensors='pt', add_special_tokens=False)
    ids = enc['input_ids'][0]
    if len(ids) <= max_length:
        chunk = ids[:max_length]
        padded = torch.cat([torch.tensor([tokenizer.cls_token_id]), chunk, torch.tensor([tokenizer.sep_token_id])])
        padded = padded.unsqueeze(0)
        attn = torch.ones_like(padded)
        if torch.cuda.is_available():
            padded, attn = padded.cuda(), attn.cuda()
        with torch.no_grad():
            logits = model(input_ids=padded, attention_mask=attn).logits
        return float(torch.softmax(logits, dim=-1)[0, 1].cpu())
    # Sliding window - collect all, then batch
    window_ids = []
    for start in range(0, len(ids), stride):
        end = min(start + max_length, len(ids))
        chunk = ids[start:end]
        padded = torch.cat([torch.tensor([tokenizer.cls_token_id]), chunk, torch.tensor([tokenizer.sep_token_id])])
        window_ids.append(padded)
        if len(window_ids) >= max_windows:
            break
    # Batch them
    max_len = max(w.size(0) for w in window_ids)
    padded_batch = torch.zeros(len(window_ids), max_len, dtype=torch.long)
    attn_batch = torch.zeros(len(window_ids), max_len, dtype=torch.long)
    for i, w in enumerate(window_ids):
        padded_batch[i, :w.size(0)] = w
        attn_batch[i, :w.size(0)] = 1
    if torch.cuda.is_available():
        padded_batch, attn_batch = padded_batch.cuda(), attn_batch.cuda()
    with torch.no_grad():
        logits = model(input_ids=padded_batch, attention_mask=attn_batch).logits
    probs = torch.softmax(logits, dim=-1)[:, 1]
    return float(probs.max().cpu())

print('\n' + '='*80)
results = {}
results['A_2048_1024_8'] = evaluate('A: 2048/1024/8', 2048, 1024, 8)
results['A_2048_1024_8_BATCH'] = evaluate_batched('A: 2048/1024/8 (BATCHED)', 2048, 1024, 8)
results['B_4096_2048_8'] = evaluate_batched('B: 4096/2048/8 (BATCHED)', 4096, 2048, 8)
results['D_8192_single'] = evaluate('D: 8192 single window (no sliding)', 8192, 8192, 1)

print('\n' + '='*80)
print('Summary:')
print(f'{"Config":<35} {"Recall":>8} {"FPR":>8} {"Coverage":>12} {"Time/doc":>12}')
for name, r in results.items():
    print(f'{name:<35} {r["recall"]:>8.4f} {r["fpr"]:>8.4f} {r["coverage"]:>12} {r["time"]/len(records)*1000:>9.0f}ms')