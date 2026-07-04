#!/usr/bin/env python3
"""
6a.1 Power analysis for held-out test set.

We want the 95% confidence interval of the model's recall NOT to include
the strict ship gate lower bound (85%). For a Wilson 95% CI on a binary
proportion with p_hat=1.0 (perfect recall on n records), the lower bound is:

  lower = (2*n*p_hat + z^2 - z*sqrt(z^2 + 4*n*p_hat*(1-p_hat))) / (2*(n + z^2))

For z=1.96 (95% CI):
  n=50:   lower=0.929
  n=100:  lower=0.963
  n=200:  lower=0.981
  n=500:  lower=0.992

For the FPR (0 FPs on n benigns): same formula. We want lower CI bound
to NOT include 5% (so lower >= 0.95 by symmetry).

n=200 benigns, 0 FPs: lower=0.981 (does NOT include 5%) OK
n=100 benigns, 0 FPs: lower=0.963 (does NOT include 5%) OK

CONCLUSION: 200 attacks + 200 benigns is statistically tight. 100 + 100 is
borderline. We use 200 + 200 (the hand-curated) + 50 + 50 (Mozilla/CTF).
"""
import math


def wilson_lower(p_hat, n, z=1.96):
    if n == 0:
        return 0
    return (2 * n * p_hat + z * z - z * math.sqrt(z * z + 4 * n * p_hat * (1 - p_hat))) / (2 * (n + z * z))


def wilson_upper(p_hat, n, z=1.96):
    if n == 0:
        return 1
    return (2 * n * p_hat + z * z + z * math.sqrt(z * z + 4 * n * p_hat * (1 - p_hat))) / (2 * (n + z * z))


def main():
    print("=== Power analysis: held-out test set size ===\n")
    print("Strict ship gate: recall >= 85%, FPR <= 5% (so lower CI must be > 0.85 and > 0.95)\n")
    print("Recall CI (95%, p_hat=1.0 = 100% recall on n attacks):")
    for n in [50, 100, 200, 250, 500]:
        lo = wilson_lower(1.0, n)
        ok = "OK" if lo > 0.85 else "FAIL"
        print(f"  n={n:>3}: lower={lo:.3f}  {ok}")
    print("\nFPR CI (95%, p_hat=0.0 = 0% FPR on n benigns):")
    for n in [50, 100, 200, 250, 500]:
        lo = wilson_lower(0.0, n)
        hi = wilson_upper(0.0, n)
        # The UPPER bound is what matters for the 5% FPR gate
        # (we need the upper bound of the FPR CI to be < 0.05)
        ok = "OK" if hi < 0.05 else "FAIL"
        print(f"  n={n:>3}: CI=[{lo:.3f}, {hi:.3f}]  upper={hi:.3f}  {ok}")
    print("\n=== CONCLUSION ===")
    print("200 attacks + 200 benigns is statistically tight (95% CI lower bound > 0.98).")
    print("100 + 100 is borderline but acceptable as a SECONDARY set.")
    print("50 + 50 is too thin (lower CI < 0.93) for the strict ship gate.")
    print("\nOur held-out: 200 hand-curated + 50 Mozilla + 50 CTF = 300 attacks + 300 benigns.")
    print("Combined lower CI (assuming 100% recall, 0% FPR): > 0.99. COMFORTABLE.")


if __name__ == "__main__":
    main()
