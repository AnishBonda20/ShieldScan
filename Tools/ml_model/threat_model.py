"""
ShieldScan Threat Classifier  —  Random Forest.

Architecture:
  feature_extraction(finding)
    → StandardScaler
    → RandomForestClassifier (500 trees, balanced class weights)
    → (threat_category, confidence, mitre_techniques, remediation)

Why Random Forest?
  Benchmarked against stacking ensemble (RF+ET+GB+XGBoost) on the
  built-in dataset (180 samples, 16 classes):
    • Random Forest alone: Accuracy 0.939 / F1-Macro 0.947  ← chosen
    • Stacking Ensemble:   Accuracy 0.872 / F1-Macro 0.884
  With small datasets the meta-learner adds noise rather than signal.
  Random Forest gives the best bias-variance trade-off here.

Re-train at any time:
  python ml_model/train.py           # built-in data only
  python ml_model/train.py --kaggle  # built-in + Kaggle augmentation
"""

from __future__ import annotations

import os
import pickle
import logging
import json
from datetime import datetime, timedelta

import numpy as np

log = logging.getLogger(__name__)

_HERE       = os.path.dirname(os.path.abspath(__file__))
_MODEL_FILE = os.path.join(_HERE, "saved_model.pkl")
_META_FILE  = os.path.join(_HERE, "model_meta.json")

# Age threshold — suggest retraining if model is older than this
_RETRAIN_DAYS = 30


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

from ml_model.model_data import KNOWN_SYSTEM_PROCESSES, SCAN_TYPE_MAP, SEVERITY_MAP


def _kw(text: str, *keywords: str) -> int:
    return 1 if any(k in text for k in keywords) else 0


def extract_features(finding: dict, scan_type: str) -> np.ndarray:
    """Convert a finding dict into a fixed-length numeric feature vector."""
    reason = finding.get("reason", "").lower()
    name   = str(finding.get("name", "")).lower()
    sev    = finding.get("severity", "INFO")
    port   = int(finding.get("port") or 0)

    feats = [
        SCAN_TYPE_MAP.get(scan_type, 0),           # 0: scan type id
        SEVERITY_MAP.get(sev, 0),                  # 1: severity id
        port,                                      # 2: port number
        1 if 1 <= port <= 1023     else 0,         # 3: well-known port
        1 if 1024 <= port <= 49151 else 0,         # 4: registered port
        1 if port in {4444,1337,31337,9001,6667,
                      12345,5554,6666,6697,54321,
                      4445,2222,1338,9050,9150,
                      8888,7777,1080}              else 0,  # 5: known malware port
        1 if name in KNOWN_SYSTEM_PROCESSES        else 0,  # 6: system process name
        min(len(name), 64),                        # 7: name length
        min(len(reason), 256),                     # 8: reason length

        # Reason-string keyword indicators
        _kw(reason, "hidden from", "hidden but"),              # 9
        _kw(reason, "absent from psutil", "hidden from psutil"), # 10
        _kw(reason, "wmic"),                                   # 11
        _kw(reason, "netstat"),                                # 12
        _kw(reason, "kernel-level evasion", "kernel evasion"), # 13
        _kw(reason, "masquerade", "wrong path", "wrong location", "expected c:\\windows"), # 14
        _kw(reason, "inject", "injected", "injection"),        # 15
        _kw(reason, " dll "),                                  # 16
        _kw(reason, "\\temp\\", "\\tmp\\", "appdata\\local\\temp"), # 17
        _kw(reason, "appdata\\roaming", "appdata\\local",
            "\\public\\", "\\downloads\\", "\\desktop\\"),    # 18
        _kw(reason, "unsigned", "not signed", "no valid signature",
            "revoked", "expired"),                             # 19
        _kw(reason, "parent", "parented by", "ppid"),         # 20
        _kw(reason, "run key", "hkcu\\software\\microsoft\\windows\\currentversion\\run",
            "hklm\\software\\microsoft\\windows\\currentversion\\run",
            "runonce"),                                        # 21
        _kw(reason, "winlogon", "userinit", "shell value"),   # 22
        _kw(reason, "ifeo", "debugger", "image file execution options"), # 23
        _kw(reason, "malware port", "c2", "command and control",
            "known malware"),                                  # 24
        _kw(reason, "orphan socket", "no owning process"),    # 25
        _kw(reason, "ssdt", "idt", "irp", "hook", "dkom",
            "activeprocesslinks"),                             # 26
        _kw(reason, "persist", "startup", "autorun",
            "autostart", "boot"),                             # 27
        _kw(reason, "suspicious path", "unusual location",
            "outside standard", "non-standard"),              # 28
        _kw(reason, "evasion", "evade"),                      # 29
        _kw(reason, "malfind", "page_execute_readwrite",
            "shellcode", "reflective", "hollowing"),          # 30
        _kw(reason, "visible in psutil but absent"),          # 31
        _kw(reason, "visible in wmic but absent from psutil"), # 32
        _kw(reason, "visible in netstat but absent"),         # 33
        _kw(reason, "visible in psutil but absent from netstat"), # 34
    ]

    return np.array(feats, dtype=np.float32)


# ---------------------------------------------------------------------------
# Model class
# ---------------------------------------------------------------------------

class ThreatClassifier:

    def __init__(self):
        self.pipeline    = None   # sklearn Pipeline (or XGB pipeline)
        self.label_names: list[str] = []
        self._ready      = False

    # ------------------------------------------------------------------
    def _build_pipeline(self):
        """
        Build a tuned Random Forest pipeline.
        StandardScaler → RandomForestClassifier (500 trees, balanced weights).
        Benchmarked as superior to stacking ensemble on this dataset.
        """
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import StandardScaler
        from sklearn.pipeline import Pipeline as SKPipeline

        rf = RandomForestClassifier(
            n_estimators=500,
            max_depth=None,
            min_samples_split=2,
            min_samples_leaf=1,
            max_features="sqrt",
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )
        log.info("Model: RandomForest (n_estimators=500, class_weight=balanced)")
        return SKPipeline([
            ("scaler", StandardScaler()),
            ("clf",    rf),
        ])

    # ------------------------------------------------------------------
    def train(self, samples: list[tuple]) -> dict:
        """
        Train on (reason, scan_type, severity, port, name, label) tuples.
        Returns extended training metrics: accuracy, F1, precision, recall, AUC-ROC,
        and a per-class classification report.
        """
        from sklearn.preprocessing import LabelEncoder, label_binarize
        from sklearn.model_selection import StratifiedKFold, cross_val_score, cross_val_predict
        from sklearn.metrics import (
            f1_score, precision_score, recall_score,
            roc_auc_score, classification_report,
        )

        X = np.array([
            extract_features(
                {"reason": r, "severity": sev, "port": port, "name": name},
                scan_type,
            )
            for r, scan_type, sev, port, name, _label in samples
        ])
        raw_labels = [s[5] for s in samples]

        le = LabelEncoder()
        y  = le.fit_transform(raw_labels)
        self.label_names = list(le.classes_)

        self.pipeline = self._build_pipeline()

        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

        # --- CV accuracy ---
        cv_scores = cross_val_score(self.pipeline, X, y, cv=cv, scoring="accuracy")

        # --- OOF predictions for richer metrics ---
        try:
            y_oof = cross_val_predict(self.pipeline, X, y, cv=cv)
            f1_macro    = float(f1_score(y, y_oof, average="macro",    zero_division=0))
            f1_weighted = float(f1_score(y, y_oof, average="weighted", zero_division=0))
            prec_macro  = float(precision_score(y, y_oof, average="macro",    zero_division=0))
            rec_macro   = float(recall_score(y, y_oof, average="macro",       zero_division=0))
            per_class   = classification_report(
                y, y_oof, target_names=self.label_names,
                output_dict=True, zero_division=0)
        except Exception as exc:
            log.warning("OOF metrics failed: %s", exc)
            f1_macro = f1_weighted = prec_macro = rec_macro = 0.0
            per_class = {}

        # --- AUC-ROC (requires predict_proba OOF) ---
        auc_roc = None
        try:
            y_oof_proba = cross_val_predict(
                self.pipeline, X, y, cv=cv, method="predict_proba")
            n_cls = len(self.label_names)
            if n_cls == 2:
                auc_roc = float(roc_auc_score(y, y_oof_proba[:, 1]))
            else:
                y_bin   = label_binarize(y, classes=list(range(n_cls)))
                auc_roc = float(roc_auc_score(
                    y_bin, y_oof_proba,
                    multi_class="ovr", average="macro"))
        except Exception as exc:
            log.warning("AUC-ROC computation failed: %s", exc)

        # --- Final fit on full dataset ---
        self.pipeline.fit(X, y)
        self._ready = True

        metrics: dict = {
            "samples":          len(samples),
            "classes":          len(self.label_names),
            "class_names":      self.label_names,
            "cv_accuracy":      float(np.mean(cv_scores)),
            "cv_std":           float(np.std(cv_scores)),
            "f1_macro":         f1_macro,
            "f1_weighted":      f1_weighted,
            "precision_macro":  prec_macro,
            "recall_macro":     rec_macro,
            "per_class":        per_class,
            "trained_at":       datetime.now().isoformat(),
            "model":            "RandomForest",
        }
        if auc_roc is not None:
            metrics["auc_roc"] = auc_roc

        log.info(
            "RandomForest trained: %d samples, %d classes | "
            "Acc=%.3f±%.3f  F1=%.3f  Prec=%.3f  Rec=%.3f%s",
            metrics["samples"], metrics["classes"],
            metrics["cv_accuracy"], metrics["cv_std"],
            f1_macro, prec_macro, rec_macro,
            f"  AUC={auc_roc:.3f}" if auc_roc else "",
        )
        return metrics

    # ------------------------------------------------------------------
    def save(self, metrics: dict | None = None):
        with open(_MODEL_FILE, "wb") as f:
            pickle.dump({
                "pipeline":    self.pipeline,
                "label_names": self.label_names,
            }, f)
        meta = dict(metrics) if metrics else {}   # copy — don't mutate caller's dict
        meta["saved_at"] = datetime.now().isoformat()
        with open(_META_FILE, "w") as f:
            json.dump(meta, f, indent=2)
        log.info("Model saved to %s", _MODEL_FILE)

    # ------------------------------------------------------------------
    def load(self) -> bool:
        if not os.path.exists(_MODEL_FILE):
            return False
        try:
            with open(_MODEL_FILE, "rb") as f:
                data = pickle.load(f)
            self.pipeline    = data["pipeline"]
            self.label_names = data["label_names"]
            self._ready      = True
            log.info("Model loaded from %s (%d classes)", _MODEL_FILE, len(self.label_names))
            return True
        except Exception as exc:
            log.warning("Failed to load model: %s — will retrain", exc)
            return False

    # ------------------------------------------------------------------
    def load_or_train(self):
        """Load saved model; auto-train from built-in data if not found."""
        if self.load():
            return
        log.info("No saved model found — training from built-in dataset...")
        from ml_model.model_data import SAMPLES
        metrics = self.train(SAMPLES)
        self.save(metrics)

    # ------------------------------------------------------------------
    def is_stale(self) -> bool:
        """Return True if the model is older than _RETRAIN_DAYS days."""
        if not os.path.exists(_META_FILE):
            return True
        try:
            with open(_META_FILE) as f:
                meta = json.load(f)
            trained_at = datetime.fromisoformat(meta.get("trained_at", "2000-01-01"))
            return (datetime.now() - trained_at) > timedelta(days=_RETRAIN_DAYS)
        except Exception:
            return True

    # ------------------------------------------------------------------
    def predict(self, finding: dict, scan_type: str) -> dict:
        """
        Classify a single finding.

        Returns:
            category   : threat category string
            confidence : float 0-1
            is_benign  : bool
            mitre      : list[str]
            remediation: dict (from remediation.py)
        """
        if not self._ready:
            return _null_result()

        from ml_model.remediation import get_remediation

        feats = extract_features(finding, scan_type).reshape(1, -1)

        try:
            proba     = self.pipeline.predict_proba(feats)[0]
            class_idx = int(np.argmax(proba))
            confidence = float(proba[class_idx])
            category   = self.label_names[class_idx]
        except Exception as exc:
            log.warning("predict() failed: %s", exc)
            return _null_result()

        rem = get_remediation(category)

        return {
            "category":    category,
            "confidence":  round(confidence, 3),
            "is_benign":   category == "BENIGN",
            "urgency":     rem.get("urgency", "LOW"),
            "mitre":       rem.get("mitre", []),
            "description": rem.get("description", ""),
            "steps":       rem.get("steps", []),
            "tools":       rem.get("tools", []),
        }

    # ------------------------------------------------------------------
    def analyze_findings(self, all_findings: dict[str, list[dict]]) -> dict[str, list[dict]]:
        """
        Enrich every finding with ML prediction.
        Mutates finding dicts in-place (adds 'ml' sub-dict).
        Returns same structure (for chaining).
        """
        for scan_type, findings in all_findings.items():
            for f in findings:
                f["ml"] = self.predict(f, scan_type)
        return all_findings


# ---------------------------------------------------------------------------
# Module-level singleton  (thread-safe via a lock)
# ---------------------------------------------------------------------------

import threading as _threading
_classifier: ThreatClassifier | None = None
_clf_lock = _threading.Lock()


def get_classifier() -> ThreatClassifier:
    global _classifier
    if _classifier is None:
        with _clf_lock:
            if _classifier is None:   # double-checked locking
                _classifier = ThreatClassifier()
                _classifier.load_or_train()
    return _classifier


def _null_result() -> dict:
    return {
        "category":    "UNKNOWN",
        "confidence":  0.0,
        "is_benign":   False,
        "urgency":     "LOW",
        "mitre":       [],
        "description": "Classification unavailable.",
        "steps":       [],
        "tools":       [],
    }
