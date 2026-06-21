#!/usr/bin/env python3
"""
Enterprise test harness for AegisGate Lens.

Runs the enterprise test corpus against the live 5-way ensemble and
reports per-category metrics.

Usage:
    python3 enterprise_test_harness.py \\
        --model-dir /home/chaos/Desktop/AegisGate/lens-repo-bootstrap/lens_ml_build/ml_model \\
        --corpus /home/chaos/Desktop/AegisGate/lens-repo-bootstrap/harness/test_prompts_enterprise.json \\
        --output /home/chaos/Desktop/AegisGate/lens-repo-bootstrap/harness/enterprise_results.json
"""
import argparse
import json
import re
import sys
import time
from pathlib import Path


def extract_features(text):
    features = []
    text_lower = text.lower()
    words = re.findall(r'\b\w+\b', text_lower)
    for w in words:
        if len(w) >= 2:
            features.append(f'w={w}')
    for i in range(len(words) - 1):
        features.append(f'w={words[i]}__{words[i+1]}')
    normalized_words = re.findall(r'[a-z0-9]+', text_lower)
    normalized = '__'.join(normalized_words)
    for n in range(3, 6):
        for i in range(len(normalized) - n + 1):
            substr = normalized[i:i+n]
            if '__' not in substr:
                features.append(f'c={substr}')
    return features


def main():
    parser = argparse.ArgumentParser(description='Enterprise test harness')
    parser.add_argument('--model-dir', required=True, help='Directory with model JSON files')
    parser.add_argument('--corpus', required=True, help='Test corpus JSON')
    parser.add_argument('--output', required=True, help='Output results JSON')
    parser.add_argument('--threshold', type=float, default=0.85, help='Detection threshold')
    args = parser.parse_args()

    import joblib
    import numpy as np

    # Load all 5 models from the bundle
    print(f'Loading models from {args.model_dir}...')
    config_path = Path(args.model_dir) / 'ensemble_config.json'
    with open(config_path) as f:
        config = json.load(f)
    print(f'  Strategy: {config["strategy"]}, Threshold: {config["threshold"]}')

    models = []
    for name in config['model_names']:
        model_path = Path(args.model_dir) / f'{name}_config.json'
        vocab_path = Path(args.model_dir) / f'{name}_vocabulary.json'
        idf_path = Path(args.model_dir) / f'{name}_idf.json'
        with open(model_path) as f:
            cfg = json.load(f)
        with open(vocab_path) as f:
            vocab = json.load(f)
        with open(idf_path) as f:
            idf = json.load(f)

        if cfg['type'] == 'lr':
            with open(Path(args.model_dir) / f'{name}_coefficients.json') as f:
                coefs = json.load(f)
            models.append({
                'type': 'lr',
                'vocab': vocab,
                'idf': idf,
                'coefs': coefs,
                'intercept': cfg['intercept'],
            })
        elif cfg['type'] == 'mlp':
            weights = []
            biases = []
            for j in range(cfg['n_layers']):
                with open(Path(args.model_dir) / f'{name}_weights_{j}.json') as f:
                    weights.append(json.load(f))
                with open(Path(args.model_dir) / f'{name}_biases_{j}.json') as f:
                    biases.append(json.load(f))
            models.append({
                'type': 'mlp',
                'vocab': vocab,
                'idf': idf,
                'config': cfg,
                'weights': weights,
                'biases': biases,
            })

    print(f'  Loaded {len(models)} models')

    def score_model(model, text):
        feats = extract_features(text)
        feat_str = ' '.join(feats)

        if model['type'] == 'lr':
            # L2-normalized TF-IDF dot product
            vocab = model['vocab']
            idf = model['idf']
            coefs = model['coefs']
            intercept = model['intercept']

            score = intercept
            sum_squares = 0
            entries = []
            for f in feats:
                idx = vocab.get(f)
                if idx is None:
                    continue
                idf_weight = idf.get(f)
                if idf_weight is None:
                    continue
                coef = coefs.get(str(idx))
                if coef is None or coef == 0:
                    continue
                tfidf = 1 * idf_weight  # count is 1 for our purposes
                entries.append((tfidf, coef))
                sum_squares += tfidf * tfidf

            norm = sum_squares ** 0.5
            if norm == 0:
                return 1 / (1 + np.exp(-score))
            for tfidf, coef in entries:
                score += (tfidf / norm) * coef
            return 1 / (1 + np.exp(-score))

        elif model['type'] == 'mlp':
            # Build feature vector
            vocab = model['vocab']
            idf = model['idf']
            cfg = model['config']
            weights = model['weights']
            biases = model['biases']

            # Compute L2-normalized feature vector
            features_norm = {}
            sum_squares = 0
            entries = []
            for f in feats:
                idx = vocab.get(f)
                if idx is None:
                    continue
                idf_weight = idf.get(f)
                if idf_weight is None:
                    continue
                tfidf = 1 * idf_weight
                entries.append((idx, tfidf))
                sum_squares += tfidf * tfidf
            norm = sum_squares ** 0.5
            if norm == 0:
                # All-zero vector
                activations = np.zeros(cfg['layer_sizes'][0], dtype=np.float32)
            else:
                activations = np.zeros(cfg['layer_sizes'][0], dtype=np.float32)
                for idx, tfidf in entries:
                    activations[idx] = tfidf / norm

            # Forward pass
            for layer in range(cfg['n_layers']):
                in_size = cfg['layer_sizes'][layer]
                out_size = cfg['layer_sizes'][layer + 1]
                W = weights[layer]
                b = biases[layer]
                scale = cfg['quant_scales'][layer]
                zero = cfg['quant_zeros'][layer]

                output = np.zeros(out_size, dtype=np.float32)
                # Dense format (list of lists)
                for r in range(in_size):
                    a = activations[r]
                    if a == 0:
                        continue
                    for c in range(out_size):
                        wq = W[r][c]
                        w = (wq - zero) * scale
                        output[c] += a * w
                # Add bias
                output = output + np.array(b, dtype=np.float32)
                # Activation
                if layer < cfg['n_layers'] - 1:
                    output = np.maximum(output, 0)  # ReLU
                else:
                    output = 1.0 / (1.0 + np.exp(-output))  # Sigmoid
                activations = output

            return float(activations[0])

    def predict(text):
        scores = [score_model(m, text) for m in models]
        if config['strategy'] == 'average':
            return sum(scores) / len(scores)
        elif config['strategy'] == 'min':
            return min(scores)
        elif config['strategy'] == 'max':
            return max(scores)
        elif config['strategy'] == 'product':
            prod = 1
            for s in scores:
                prod *= s
            return prod ** (1 / len(scores))

    # Load corpus
    print(f'\nLoading corpus: {args.corpus}')
    with open(args.corpus) as f:
        corpus_data = json.load(f)
    corpus = corpus_data['prompts']
    print(f'  Total prompts: {len(corpus)}')

    # Score all prompts
    print('\nScoring...')
    results = []
    threshold = args.threshold
    for i, prompt in enumerate(corpus):
        t0 = time.time()
        score = predict(prompt['text'])
        latency = time.time() - t0
        is_attack = score >= threshold
        results.append({
            'text': prompt['text'][:200],
            'expected': prompt['expected'],
            'category': prompt['category'],
            'subcategory': prompt['subcategory'],
            'severity': prompt.get('severity', 'none'),
            'score': float(score),
            'is_attack_pred': bool(is_attack),
            'latency_ms': latency * 1000,
            'correct': bool((is_attack and prompt['expected'] == 'attack') or (not is_attack and prompt['expected'] == 'normal')),
        })
        if (i + 1) % 20 == 0:
            print(f'  Scored {i+1}/{len(corpus)}')

    print(f'\nScored {len(results)} prompts')

    # Compute metrics
    print('\n=== Overall Metrics ===')
    total = len(results)
    correct = sum(1 for r in results if r['correct'])
    print(f'Accuracy: {correct}/{total} ({correct/total*100:.1f}%)')

    # TPR/FPR (excluding edge_cases)
    eval_results = [r for r in results if r['expected'] in ('attack', 'normal')]
    tp = sum(1 for r in eval_results if r['expected'] == 'attack' and r['is_attack_pred'])
    fp = sum(1 for r in eval_results if r['expected'] == 'normal' and r['is_attack_pred'])
    fn = sum(1 for r in eval_results if r['expected'] == 'attack' and not r['is_attack_pred'])
    tn = sum(1 for r in eval_results if r['expected'] == 'normal' and not r['is_attack_pred'])
    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    print(f'\nTPR: {tpr*100:.2f}% ({tp}/{tp+fn})')
    print(f'FPR: {fpr*100:.2f}% ({fp}/{fp+tn})')
    print(f'TP={tp}, FP={fp}, FN={fn}, TN={tn}')

    # Per-category metrics
    print('\n=== Per-Category Metrics ===')
    by_category = {}
    for r in results:
        cat = r['category']
        by_category.setdefault(cat, []).append(r)

    cat_metrics = {}
    for cat, cat_results in sorted(by_category.items()):
        cat_eval = [r for r in cat_results if r['expected'] in ('attack', 'normal')]
        if not cat_eval:
            print(f'\n  {cat}: (edge case only)')
            continue
        cat_tp = sum(1 for r in cat_eval if r['expected'] == 'attack' and r['is_attack_pred'])
        cat_fp = sum(1 for r in cat_eval if r['expected'] == 'normal' and r['is_attack_pred'])
        cat_fn = sum(1 for r in cat_eval if r['expected'] == 'attack' and not r['is_attack_pred'])
        cat_tn = sum(1 for r in cat_eval if r['expected'] == 'normal' and not r['is_attack_pred'])
        cat_tpr = cat_tp / (cat_tp + cat_fn) if (cat_tp + cat_fn) > 0 else 0
        cat_fpr = cat_fp / (cat_fp + cat_tn) if (cat_fp + cat_tn) > 0 else 0
        avg_score = sum(r['score'] for r in cat_results) / len(cat_results)
        cat_metrics[cat] = {
            'total': len(cat_results),
            'attack': sum(1 for r in cat_results if r['expected'] == 'attack'),
            'normal': sum(1 for r in cat_results if r['expected'] == 'normal'),
            'edge': sum(1 for r in cat_results if r['expected'] == 'edge_case'),
            'TP': cat_tp, 'FP': cat_fp, 'FN': cat_fn, 'TN': cat_tn,
            'TPR': cat_tpr, 'FPR': cat_fpr,
            'avg_score': avg_score,
        }
        marker = '⚠️' if (cat_tpr < 0.7 and cat_eval and any(r['expected'] == 'attack' for r in cat_eval)) or (cat_fpr > 0.2 and any(r['expected'] == 'normal' for r in cat_eval)) else '  '
        print(f'  {marker} {cat:<25s} TPR={cat_tpr*100:>6.1f}% FPR={cat_fpr*100:>6.1f}% n={len(cat_results):>3d} avg_score={avg_score:.3f}')

    # Worst failures
    print('\n=== Worst False Negatives (missed attacks) ===')
    fn_results = [r for r in results if r['expected'] == 'attack' and not r['is_attack_pred']]
    fn_results.sort(key=lambda x: x['score'])  # Lowest scores = worst
    for r in fn_results[:5]:
        print(f'  [{r["category"]:<25s}] score={r["score"]:.4f} text="{r["text"][:80]}"')

    print('\n=== Worst False Positives (flagged benign) ===')
    fp_results = [r for r in results if r['expected'] == 'normal' and r['is_attack_pred']]
    fp_results.sort(key=lambda x: -x['score'])  # Highest scores = worst
    for r in fp_results[:5]:
        print(f'  [{r["category"]:<25s}] score={r["score"]:.4f} text="{r["text"][:80]}"')

    # Save full results
    output = {
        'version': '1.0.0',
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'threshold': threshold,
        'strategy': config['strategy'],
        'n_models': len(models),
        'corpus': {
            'total': total,
            'attacks': sum(1 for r in results if r['expected'] == 'attack'),
            'normals': sum(1 for r in results if r['expected'] == 'normal'),
            'edge_cases': sum(1 for r in results if r['expected'] == 'edge_case'),
        },
        'overall': {
            'accuracy': correct / total,
            'TPR': tpr, 'FPR': fpr,
            'TP': tp, 'FP': fp, 'FN': fn, 'TN': tn,
        },
        'per_category': cat_metrics,
        'results': results,
    }

    with open(args.output, 'w') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f'\nFull results saved to {args.output}')


if __name__ == '__main__':
    main()
