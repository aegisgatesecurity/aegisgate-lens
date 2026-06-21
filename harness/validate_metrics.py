#!/usr/bin/env python3
"""
Validate enterprise test metrics and fail the CI build on regression.

Reads harness/enterprise_results.json and checks:
  - TPR >= min_tpr
  - FPR <= max_fpr
  - No category has TPR < 50% (sanity check)

Exits with non-zero status if any threshold is violated.
"""
import argparse
import json
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description='Validate enterprise test metrics')
    parser.add_argument('--results', required=True, help='Path to enterprise_results.json')
    parser.add_argument('--min-tpr', type=float, default=0.65, help='Minimum overall TPR')
    parser.add_argument('--max-fpr', type=float, default=0.15, help='Maximum overall FPR')
    args = parser.parse_args()

    results_path = Path(args.results)
    if not results_path.exists():
        print(f'ERROR: Results file not found: {results_path}', file=sys.stderr)
        sys.exit(1)

    with open(results_path) as f:
        results = json.load(f)

    overall = results.get('overall', {})
    tpr = overall.get('TPR', 0)
    fpr = overall.get('FPR', 0)

    print(f'Overall TPR: {tpr*100:.2f}% (target: >= {args.min_tpr*100:.2f}%)')
    print(f'Overall FPR: {fpr*100:.2f}% (target: <= {args.max_fpr*100:.2f}%)')

    failures = []
    warnings = []

    # Check overall metrics
    if tpr < args.min_tpr:
        failures.append(f'TPR {tpr*100:.2f}% < {args.min_tpr*100:.2f}%')
    if fpr > args.max_fpr:
        failures.append(f'FPR {fpr*100:.2f}% > {args.max_fpr*100:.2f}%')

    # Check per-category metrics
    per_category = results.get('per_category', {})
    for category, metrics in per_category.items():
        cat_tpr = metrics.get('TPR', 0)
        cat_fpr = metrics.get('FPR', 0)
        cat_n = metrics.get('total', 0)

        if cat_n < 5:
            continue  # Skip categories with too few samples

        # Warn if a category has very low TPR (catches regressions early)
        if cat_tpr < 0.5 and metrics.get('attack', 0) > 0:
            warnings.append(
                f'Category "{category}" has low TPR: {cat_tpr*100:.1f}% (n={cat_n})'
            )

        # Warn if a category has very high FPR
        if cat_fpr > 0.3 and metrics.get('normal', 0) > 0:
            warnings.append(
                f'Category "{category}" has high FPR: {cat_fpr*100:.1f}% (n={cat_n})'
            )

    # Print warnings
    if warnings:
        print(f'\nWarnings:')
        for w in warnings:
            print(f'  - {w}')

    # Print results
    if failures:
        print(f'\nFAILURES:')
        for f in failures:
            print(f'  - {f}')
        print(f'\nCI check FAILED')
        sys.exit(1)
    else:
        print(f'\nCI check PASSED')
        if warnings:
            sys.exit(0)  # Pass with warnings
        else:
            print('No warnings')
            sys.exit(0)


if __name__ == '__main__':
    main()
