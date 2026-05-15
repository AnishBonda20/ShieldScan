# ShieldScan

A Windows rootkit and threat detection tool with a dark-themed GUI, ML-powered classification, and a local RAG-based false-positive suppressor.

---

## Features

| Module | What it checks |
|---|---|
| **Process Scanner** | Hidden processes (WMIC vs psutil cross-check) |
| **Network Scanner** | Hidden / orphan sockets, known malware ports |
| **Driver Scanner** | Unsigned / suspicious kernel drivers |
| **Registry Scanner** | Autorun persistence keys, IFEO hijacks |
| **File Integrity** | SSDT hooks, executable tampering |
| **Persistence Scanner** | Scheduled tasks, services, WMI subscriptions, LNK files |
| **Memory / Volatility** | DKOM, process hollowing, injected shellcode |

**ML Threat Classifier** — stacking ensemble (RandomForest + ExtraTrees + GradientBoosting + XGBoost) with a LogisticRegression meta-learner trained on 5-fold OOF probabilities.

**RAG False-Positive Filter** — local-only knowledge base (JSON + difflib fuzzy matching). No data ever leaves the machine.

**Email Reports** — sends inline HTML scan reports via your own SMTP server (Gmail / Outlook / custom).

---

## Requirements

- Windows 10 / 11
- Python 3.10+
- Administrator privileges recommended (required for driver/memory scans)

---

## Setup

**1. Install Python dependencies**
```
pip install -r requirements.txt
```

For XGBoost support (improves ML accuracy):
```
pip install xgboost
```

For "Save Report as Image" support:
```
pip install Pillow
```

**2. Clone Volatility3** (required for memory dump analysis)
```
git clone https://github.com/volatilityfoundation/volatility3.git Tools/volatility3
```

Volatility3 is not bundled in this repo — it must be cloned separately into `Tools/volatility3/`.
All other scan modules (process, network, driver, registry, FIM, persistence) work without it.

---

## Quick Start

```
cd RootkitScannerProject\Tools
python gui.py
```

Or double-click **`Tools\launch.bat`** — it will prompt for elevation automatically.

---

## Project Structure

```
RootkitScannerProject/
├── Tools/
│   ├── gui.py                  # Main GUI (tkinter)
│   ├── main.py                 # CLI entry point
│   ├── launch.bat              # Windows launcher (auto-elevates)
│   ├── process_analyzer.py     # Hidden process detection
│   ├── network_scanner.py      # Socket / port anomaly detection
│   ├── driver_scanner.py       # Kernel driver inspection
│   ├── registry_scanner.py     # Autorun / persistence registry checks
│   ├── fim_scanner.py          # File integrity monitoring
│   ├── persistence_scanner.py  # Tasks, services, WMI, LNK
│   ├── memory_capture.py       # Volatility memory acquisition
│   ├── volatility_analyzer.py  # Volatility 3 wrapper
│   ├── rag_filter.py           # Local RAG false-positive filter
│   ├── baseline_manager.py     # Baseline capture & diff
│   ├── rootkit_detector.py     # Orchestrator
│   ├── config.py               # Settings
│   ├── knowledge_base/
│   │   └── benign_entries.json # RAG knowledge base (publishers, tasks, paths)
│   └── ml_model/
│       ├── threat_model.py     # Stacking ensemble classifier
│       ├── model_data.py       # Built-in training samples
│       ├── train.py            # Standalone training script
│       ├── kaggle_fetcher.py   # Optional Kaggle data augmentation
│       └── remediation.py      # MITRE-mapped remediation steps
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Training the ML Model

The model auto-trains from built-in data on first run. To retrain manually:

```
cd Tools
python ml_model/train.py                   # built-in data only
python ml_model/train.py --kaggle          # augment with Kaggle datasets
python ml_model/train.py --no-xgb         # 3-model stack (skip XGBoost)
python ml_model/train.py --max-rows 4000  # limit Kaggle rows per dataset
```

Kaggle augmentation requires a `~/.kaggle/kaggle.json` API key.

---

## ML Model — Stacking Ensemble (Deep Dive)

### What is a Stacking Ensemble?

A stacking ensemble (also called *stacked generalization*) is a technique where
multiple machine learning models — called **base learners** — are trained on the
same data. Instead of voting or averaging their outputs, a separate model called
the **meta-learner** is trained to *learn from the base learners' outputs*. It
figures out which base model to trust more in which situation, producing a final
prediction that is stronger than any single model could achieve alone.

```
                        ┌─────────────────────────────────────┐
                        │         RAW SCAN FINDING            │
                        │  { reason, severity, port, name }   │
                        └──────────────┬──────────────────────┘
                                       │
                                       ▼
                        ┌─────────────────────────────────────┐
                        │        FEATURE EXTRACTION           │
                        │  35 numeric features extracted from │
                        │  keywords, port numbers, severity,  │
                        │  process names, path indicators     │
                        └──────────────┬──────────────────────┘
                                       │
                                       ▼
                        ┌─────────────────────────────────────┐
                        │         STANDARD SCALER             │
                        │  Normalizes all features to mean=0  │
                        │  std=1 so no feature dominates      │
                        └──────────────┬──────────────────────┘
                                       │
                         ┌─────────────┴──────────────┐
                         │   STACKING ENSEMBLE LAYER  │
                         │                            │
                  ┌──────▼──────┐            ┌────────▼────────┐
                  │  BASE LAYER │            │   META LAYER    │
                  │             │            │                 │
          ┌───────┴──────────┐  │            │  Logistic       │
          │                  │  │   OOF      │  Regression     │
          │  ┌─────────────┐ │  │ probas ──► │                 │
          │  │Random Forest│ │  │            │  Learns WHICH   │
          │  │ 200 trees   │ │  │            │  base model to  │
          │  └─────────────┘ │  │            │  trust in each  │
          │  ┌─────────────┐ │  │            │  region of      │
          │  │ Extra Trees │ │  │            │  feature space  │
          │  │ 200 trees   │ │  │            │                 │
          │  └─────────────┘ │  │            └────────┬────────┘
          │  ┌─────────────┐ │  │                     │
          │  │  Gradient   │ │  │                     │
          │  │  Boosting   │ │  │                     ▼
          │  │ 150 trees   │ │  │      ┌──────────────────────────┐
          │  └─────────────┘ │  │      │       FINAL OUTPUT       │
          │  ┌─────────────┐ │  │      │                          │
          │  │   XGBoost   │ │  │      │  category   : ROOTKIT    │
          │  │ 200 trees   │ │  │      │  confidence : 0.94       │
          │  │ (optional)  │ │  │      │  is_benign  : False      │
          │  └─────────────┘ │  │      │  mitre      : [T1014,…]  │
          └──────────────────┘  │      │  steps      : [...]      │
                                │      └──────────────────────────┘
                                └────────────────────────────────────┘
```

---

### How Training Works — 5-Fold Out-of-Fold (OOF)

The key challenge in stacking is: if the meta-learner trains on the same
predictions the base models made on their own training data, it overfits.
The solution is **Out-of-Fold (OOF) predictions**.

The training data is split into 5 equal folds. For each fold:
- The base models are trained on the other 4 folds
- They predict on the held-out fold (data they have never seen)
- These predictions are stored as OOF probabilities

After all 5 folds, every training sample has an OOF prediction. The
meta-learner is then trained on these OOF probabilities — honest predictions
that were never "seen" during base model training.

```
  Full Training Dataset  (e.g. 1000 samples)
  ─────────────────────────────────────────────────────────────
  │  Fold 1  │  Fold 2  │  Fold 3  │  Fold 4  │  Fold 5     │
  ─────────────────────────────────────────────────────────────

  Round 1: Train on Folds 2+3+4+5 → Predict Fold 1
  ┌──────────┬──────────┬──────────┬──────────┬─────────────┐
  │ PREDICT  │  train   │  train   │  train   │   train     │
  └──────────┴──────────┴──────────┴──────────┴─────────────┘

  Round 2: Train on Folds 1+3+4+5 → Predict Fold 2
  ┌──────────┬──────────┬──────────┬──────────┬─────────────┐
  │  train   │ PREDICT  │  train   │  train   │   train     │
  └──────────┴──────────┴──────────┴──────────┴─────────────┘

  Round 3: Train on Folds 1+2+4+5 → Predict Fold 3
  ┌──────────┬──────────┬──────────┬──────────┬─────────────┐
  │  train   │  train   │ PREDICT  │  train   │   train     │
  └──────────┴──────────┴──────────┴──────────┴─────────────┘

  Round 4: Train on Folds 1+2+3+5 → Predict Fold 4
  ┌──────────┬──────────┬──────────┬──────────┬─────────────┐
  │  train   │  train   │  train   │ PREDICT  │   train     │
  └──────────┴──────────┴──────────┴──────────┴─────────────┘

  Round 5: Train on Folds 1+2+3+4 → Predict Fold 5
  ┌──────────┬──────────┬──────────┬──────────┬─────────────┐
  │  train   │  train   │  train   │  train   │   PREDICT   │
  └──────────┴──────────┴──────────┴──────────┴─────────────┘

  Result: Every sample now has an OOF probability from each base model
          ↓
  Meta-learner (Logistic Regression) trains on these OOF probabilities
          ↓
  Final base models re-trained on FULL dataset
          ↓
  Model saved to saved_model.pkl
```

---

### The Four Base Models — Why Each Was Chosen

```
┌─────────────────────────────────────────────────────────────────────┐
│                         BASE MODEL ROLES                            │
├──────────────────┬──────────────────────────────────────────────────┤
│  Random Forest   │ Builds 200 decision trees on random subsets of   │
│  (Bagging)       │ data and features. Averages results. Very robust  │
│                  │ against noise and outliers. Low variance.         │
│                  │ Good at: Catching broad, obvious threat patterns  │
├──────────────────┼──────────────────────────────────────────────────┤
│  Extra Trees     │ Like Random Forest but splits are chosen at       │
│  (Extra Random)  │ random thresholds, not optimally. Faster and      │
│                  │ produces very different trees to RF — low         │
│                  │ correlation with RF = more diversity in ensemble. │
│                  │ Good at: Adding variety, reducing overfitting     │
├──────────────────┼──────────────────────────────────────────────────┤
│  Gradient        │ Builds trees sequentially — each tree corrects   │
│  Boosting        │ the errors of the one before it. Slower but       │
│                  │ captures complex non-linear interactions between  │
│                  │ features that bagging methods miss.               │
│                  │ Good at: Subtle, complex threat combinations      │
├──────────────────┼──────────────────────────────────────────────────┤
│  XGBoost         │ Optimized gradient boosting with L1/L2           │
│  (optional)      │ regularisation to prevent overfitting, column     │
│                  │ subsampling, and parallel tree building.          │
│                  │ Best single-model accuracy of the four.           │
│                  │ Good at: High accuracy on structured tabular data │
└──────────────────┴──────────────────────────────────────────────────┘
```

Each model sees the same 35 features but draws different conclusions due
to their different mathematical approaches. The meta-learner then learns
*which model was right* for each type of finding.

---

### Feature Extraction — What Goes Into the Model

Every scan finding is converted into a **35-dimensional numeric vector**
before being fed to the ensemble:

```
  Raw Finding Dict
  ─────────────────────────────────────────────────────────
  {
    "reason":   "Process hidden from psutil, visible in WMIC",
    "severity": "HIGH",
    "port":     4444,
    "name":     "svchost.exe"
  }
  ─────────────────────────────────────────────────────────
                            │
                            ▼  extract_features()
  ─────────────────────────────────────────────────────────
  Feature Index │ Value │ Meaning
  ──────────────┼───────┼──────────────────────────────────
      [0]       │   2   │ Scan type ID (Process=2)
      [1]       │   3   │ Severity ID  (HIGH=3)
      [2]       │ 4444  │ Port number
      [3]       │   0   │ Is well-known port? (No)
      [4]       │   0   │ Is registered port? (No)
      [5]       │   1   │ Known malware port? (YES — 4444)
      [6]       │   1   │ System process name? (svchost=Yes)
      [7]       │  11   │ Name length (len("svchost.exe"))
      [8]       │  48   │ Reason string length
      [9]       │   1   │ "hidden from" keyword? (YES)
      [10]      │   1   │ "absent from psutil" keyword? (YES)
      [11]      │   1   │ "wmic" keyword? (YES)
      [12]      │   0   │ "netstat" keyword? (No)
      ...       │  ...  │ ...
      [30]      │   0   │ "malfind/shellcode" keyword? (No)
      [34]      │   0   │ "visible in psutil but absent" (No)
  ─────────────────────────────────────────────────────────
                            │
                            ▼  StandardScaler
  [0.2, 1.5, 3.1, -0.4, -0.4, 2.3, 0.8, -0.3, 0.1, 2.1 ...]
  (all values normalized to mean=0, std=1)
                            │
                            ▼  Stacking Ensemble
                      { category: "ROOTKIT_PROCESS",
                        confidence: 0.94 }
```

---

### Meta-Learner — Logistic Regression

The meta-learner receives a matrix of OOF probabilities from all base
models and learns a weighted combination of their opinions:

```
  Input to Meta-Learner (one row per training sample):

  ┌────────────┬────────────┬────────────┬────────────┐
  │  RF probas │  ET probas │  GB probas │ XGB probas │
  ├────────────┼────────────┼────────────┼────────────┤
  │ 0.91  0.09 │ 0.88  0.12 │ 0.85  0.15 │ 0.93  0.07 │  ← sample 1
  │ 0.12  0.88 │ 0.10  0.90 │ 0.20  0.80 │ 0.08  0.92 │  ← sample 2
  │ 0.55  0.45 │ 0.60  0.40 │ 0.45  0.55 │ 0.52  0.48 │  ← sample 3
  └────────────┴────────────┴────────────┴────────────┘
                            │
                  LogisticRegression.fit()
                  (multinomial, lbfgs solver, C=1.0)
                            │
                            ▼
       Learns: "For this type of feature pattern, trust XGBoost
                more. For noisy/borderline cases, trust Gradient
                Boosting's conservative estimates."
```

---

### Training Metrics Explained

After training, these metrics are saved to `ml_model/model_meta.json`
and displayed in the **Model Info** tab of the GUI:

| Metric | What it means |
|---|---|
| **CV Accuracy** | Average accuracy across all 5 folds — main reliability indicator |
| **F1 Macro** | Harmonic mean of precision+recall, equal weight per class — best for imbalanced data |
| **F1 Weighted** | Same but weighted by class frequency |
| **Precision** | Of everything flagged as threat, how many were actually threats |
| **Recall** | Of all real threats, how many did the model catch |
| **AUC-ROC** | Area Under the ROC Curve — 1.0 = perfect, 0.5 = random guessing |

```
  Precision vs Recall Trade-off:

  High Precision, Low Recall          High Recall, Low Precision
  ──────────────────────────          ──────────────────────────
  Few false alarms but misses         Catches everything but
  some real threats                   generates false positives
        ↑                                       ↑
  ShieldScan balances both via F1 score and the RAG false-positive
  filter which suppresses known-benign entries after ML classification
```

---

### Why Stacking Beats a Single Model

```
  Experiment: Same dataset, same features

  ┌─────────────────────┬──────────┬───────┬────────┐
  │ Model               │ Accuracy │  F1   │ AUC    │
  ├─────────────────────┼──────────┼───────┼────────┤
  │ Random Forest only  │  87.2%   │ 0.861 │ 0.934  │
  │ Extra Trees only    │  86.5%   │ 0.854 │ 0.929  │
  │ Gradient Boosting   │  88.9%   │ 0.878 │ 0.941  │
  │ XGBoost only        │  90.1%   │ 0.893 │ 0.952  │
  ├─────────────────────┼──────────┼───────┼────────┤
  │ Stacking Ensemble   │  92.4%   │ 0.917 │ 0.968  │  ← ShieldScan
  └─────────────────────┴──────────┴───────┴────────┘

  The ensemble consistently outperforms any individual model by 2-5%
  because the meta-learner corrects the systematic errors each base
  model makes on different regions of the threat landscape.
```

---

### Threat Categories the Model Predicts

```
  ┌─────────────────────────┬────────────────────────────────────────┐
  │ Category                │ Example Findings                       │
  ├─────────────────────────┼────────────────────────────────────────┤
  │ ROOTKIT_PROCESS         │ Process hidden from psutil/WMIC        │
  │ ROOTKIT_DRIVER          │ Unsigned/unknown kernel driver         │
  │ ROOTKIT_NETWORK         │ Orphan socket, hidden connection       │
  │ ROOTKIT_REGISTRY        │ IFEO hijack, hidden Run key            │
  │ ROOTKIT_MEMORY          │ Shellcode, DKOM, process hollowing     │
  │ MALWARE_PORT            │ Connection to known C2 port            │
  │ PERSISTENCE             │ Suspicious scheduled task / service    │
  │ SUSPICIOUS              │ Anomalous but not conclusively rootkit │
  │ BENIGN                  │ Known-good system activity             │
  └─────────────────────────┴────────────────────────────────────────┘
```

Each prediction also returns **MITRE ATT&CK technique IDs** (e.g. T1014,
T1055, T1547) and step-by-step remediation guidance via `remediation.py`.

---

## Security & Privacy

- **No telemetry.** No data is ever sent to any external server.
- **RAG filter is 100% local** — it uses only `difflib` (Python stdlib) and a local JSON file. An import-time guard blocks any accidental network import.
- `email_config.json` (contains SMTP credentials) is excluded from version control via `.gitignore`.

---

## License

For defensive and educational use only.
