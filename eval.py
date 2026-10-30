"""Score the scanner against the labeled corpus.

Prints per-rule precision/recall and the overall numbers. Run it after
touching any rule — a rule that gains a true positive by adding two
false positives is a worse rule, and this is how you notice.
"""

from corpus import CASES
from scanner import scan_source


def main():
    rules = sorted({r for _, _, expected in CASES for r in expected}
                   | {f.rule for _, code, _ in CASES for f in scan_source(code)})
    stats = {r: {"tp": 0, "fp": 0, "fn": 0} for r in rules}
    total_tp = total_fp = total_fn = 0

    for name, code, expected in CASES:
        found = {f.rule for f in scan_source(code)}
        for rule in found & expected:
            stats[rule]["tp"] += 1
        for rule in found - expected:
            stats[rule]["fp"] += 1
            print(f"  FALSE POSITIVE  {name}: {rule}")
        for rule in expected - found:
            stats[rule]["fn"] += 1
            print(f"  MISSED          {name}: {rule}")

    print(f"\n{'rule':<20} {'P':>5} {'R':>5}  tp/fp/fn")
    for rule in rules:
        s = stats[rule]
        p = s["tp"] / (s["tp"] + s["fp"]) if s["tp"] + s["fp"] else 1.0
        r = s["tp"] / (s["tp"] + s["fn"]) if s["tp"] + s["fn"] else 1.0
        total_tp += s["tp"]; total_fp += s["fp"]; total_fn += s["fn"]
        print(f"{rule:<20} {p:5.2f} {r:5.2f}  {s['tp']}/{s['fp']}/{s['fn']}")

    p = total_tp / (total_tp + total_fp) if total_tp + total_fp else 1.0
    r = total_tp / (total_tp + total_fn) if total_tp + total_fn else 1.0
    print(f"\nOVERALL precision={p:.2f} recall={r:.2f} "
          f"({total_tp} tp / {total_fp} fp / {total_fn} fn over {len(CASES)} cases)")


if __name__ == "__main__":
    main()
