"""
Standalone training script for the ShieldScan Random Forest Classifier.

Usage:
  python ml_model/train.py                  # train on built-in data only
  python ml_model/train.py --kaggle         # built-in + Kaggle augmentation
  python ml_model/train.py --kaggle --clear-cache  # fresh Kaggle download
  python ml_model/train.py --max-rows 4000

Architecture: Random Forest
  Model : RandomForestClassifier (500 trees, balanced class weights)
  CV    : 5-fold StratifiedKFold for accuracy, F1, precision, recall, AUC-ROC

  Note: Benchmarked against stacking ensemble (RF+ET+GB+XGBoost).
  Random Forest achieved 0.939 accuracy vs 0.872 for the ensemble
  on the built-in dataset — chosen for superior performance.

Output:
  ml_model/saved_model.pkl   (model weights)
  ml_model/model_meta.json   (training metadata + full metrics)
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import json

# Force UTF-8 output so Unicode box-drawing chars work on Windows (CP1252 consoles)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Make sure parent dir is on path when run as a script
_TOOLS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _TOOLS_DIR not in sys.path:
    sys.path.insert(0, _TOOLS_DIR)

logging.basicConfig(
    level=logging.INFO,
    format="  %(levelname)-8s  %(message)s",
)
log = logging.getLogger("train")


def _check_deps() -> bool:
    missing = []
    for pkg in ("numpy", "sklearn"):
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if "sklearn" in missing:
        missing[missing.index("sklearn")] = "scikit-learn"
    if missing:
        log.error("Missing required packages: %s", ", ".join(missing))
        log.error("Install with: pip install scikit-learn numpy")
        return False
    return True


def _bar(value: float, width: int = 30, char: str = "█") -> str:
    filled = round(value * width)
    return char * filled + "░" * (width - filled)


def main():
    parser = argparse.ArgumentParser(
        description="Train the ShieldScan stacking ensemble classifier",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--kaggle",      action="store_true",
                        help="Augment training data with Kaggle datasets")
    parser.add_argument("--clear-cache", action="store_true",
                        help="Clear cached Kaggle downloads before fetching")
    parser.add_argument("--max-rows",   type=int, default=4000,
                        help="Max rows per Kaggle dataset (default: 4000)")
    args = parser.parse_args()

    if not _check_deps():
        sys.exit(1)

    print()
    print("  ╔══════════════════════════════════════════════════╗")
    print("  ║   ShieldScan  —  Random Forest Trainer          ║")
    print("  ╚══════════════════════════════════════════════════╝")
    print()

    # ── Collect training data ──────────────────────────────────────────
    from ml_model.model_data import SAMPLES
    log.info("Built-in samples: %d", len(SAMPLES))
    all_samples = list(SAMPLES)

    if args.kaggle:
        from ml_model.kaggle_fetcher import fetch_and_convert, clear_cache
        if args.clear_cache:
            clear_cache()
            log.info("Kaggle cache cleared.")
        log.info("Fetching Kaggle datasets (requires kaggle.json API key)...")
        kaggle_samples = fetch_and_convert(max_rows_per_dataset=args.max_rows)
        if kaggle_samples:
            all_samples.extend(kaggle_samples)
            log.info("Total after augmentation: %d samples", len(all_samples))
        else:
            log.warning("No Kaggle samples added (check API key setup).")
    else:
        log.info("Tip: --kaggle augments with real-world malware data from Kaggle.")

    # ── Class distribution ─────────────────────────────────────────────
    from collections import Counter
    dist = Counter(s[5] for s in all_samples)
    print("  Class distribution:")
    for cls, cnt in sorted(dist.items(), key=lambda x: -x[1]):
        bar = "█" * min(cnt, 35)
        print(f"    {cls:<30}  {cnt:>4}  {bar}")
    print()

    log.info("Model: RandomForest (500 trees, balanced)  |  CV folds: 5")

    # ── Train ──────────────────────────────────────────────────────────
    from ml_model.threat_model import ThreatClassifier
    clf = ThreatClassifier()

    log.info("Training Random Forest (this takes ~30 seconds)…")
    metrics = clf.train(all_samples)

    # ── Results ───────────────────────────────────────────────────────
    print()
    print("  ┌─────────────────────────────────────────────────────┐")
    print("  │  Training Results                                   │")
    print("  ├─────────────────────────────────────────────────────┤")
    print(f"  │  Samples        : {metrics['samples']:<34}│")
    print(f"  │  Classes        : {metrics['classes']:<34}│")
    print(f"  │  Model          : {'RandomForest (500 trees)':<34}│")
    print("  ├─────────────────────────────────────────────────────┤")
    acc = metrics['cv_accuracy']
    f1  = metrics.get('f1_macro', 0)
    pre = metrics.get('precision_macro', 0)
    rec = metrics.get('recall_macro', 0)
    print(f"  │  CV Accuracy    : {acc:.3f} ± {metrics['cv_std']:.3f}"
          f"  {_bar(acc, 20):<26}│")
    print(f"  │  F1  (macro)    : {f1:.3f}        {_bar(f1, 20):<26}│")
    print(f"  │  Precision      : {pre:.3f}        {_bar(pre, 20):<26}│")
    print(f"  │  Recall         : {rec:.3f}        {_bar(rec, 20):<26}│")
    if "auc_roc" in metrics:
        auc = metrics["auc_roc"]
        print(f"  │  AUC-ROC        : {auc:.3f}        {_bar(auc, 20):<26}│")
    print("  └─────────────────────────────────────────────────────┘")

    # Per-class breakdown
    if metrics.get("per_class"):
        print()
        print("  Per-class F1 scores:")
        pc = metrics["per_class"]
        for cls in metrics.get("class_names", []):
            row = pc.get(cls, {})
            cf1 = row.get("f1-score", 0)
            n   = row.get("support", 0)
            bar = _bar(cf1, 16)
            print(f"    {cls:<30}  f1={cf1:.2f}  {bar}  (n={n})")

    # ── Save ───────────────────────────────────────────────────────────
    print()
    clf.save(metrics)
    log.info("Model saved to ml_model/saved_model.pkl")
    log.info("Metadata saved to ml_model/model_meta.json")

    # ── Self-test ──────────────────────────────────────────────────────
    print()
    print("  Self-test predictions:")
    test_cases = [
        ({"reason": "PID 1188 persistently visible in WMIC but absent from psutil",
          "severity": "HIGH", "port": 0, "name": "<unknown>"}, "Process"),
        ({"reason": "TCP port 4444 LISTEN visible in psutil but absent from netstat",
          "severity": "HIGH", "port": 4444, "name": "<unknown>"}, "Network"),
        ({"reason": "SSDT hook detected: NtOpenProcess redirected to unknown module",
          "severity": "HIGH", "port": 0, "name": "<kernel>"}, "Memory"),
        ({"reason": "Autorun in HKCU Run: 'malware' -> C:\\Temp\\malware.exe",
          "severity": "HIGH", "port": 0, "name": "malware"}, "Registry"),
        ({"reason": "OneDrive using IPv6 socket on port 42050 — normal cloud sync",
          "severity": "MEDIUM", "port": 42050, "name": "onedrive.exe"}, "Network"),
    ]
    for finding, scan_type in test_cases:
        result = clf.predict(finding, scan_type)
        flag = "  ✓ benign" if result["is_benign"] else ""
        print(f"    [{scan_type:<8}]  {result['category']:<28} "
              f"conf={result['confidence']:.2f}  "
              f"{_bar(result['confidence'], 16)}{flag}")

    print()
    print("  Done. ShieldScan Random Forest model saved — ready to scan.")
    print()


if __name__ == "__main__":
    main()
