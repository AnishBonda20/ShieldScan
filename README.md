# ShieldScan v2.0

> Windows rootkit & advanced threat detector — cross-view process snapshots, kernel driver analysis, registry persistence scanning, file integrity monitoring, and Random Forest ML classification. 100% offline.

---

## How It Works

Rootkits survive by intercepting the very OS calls that security tools rely on to list processes, sockets, and drivers. ShieldScan's core technique is the **cross-view snapshot**: at the start of every scan, it queries multiple completely independent OS APIs simultaneously. A rootkit can tamper with one source, but it cannot intercept all of them at the same moment.

```
  Same moment in time — three independent views of running processes:

  psutil                  WMIC                    tasklist
  (NtQuerySysInfo)        (WMI subsystem)         (Win32 API)
  ──────────────          ──────────────          ──────────────
  PID 1044                PID 1044                PID 1044
  PID 2304                PID 1188  ←             PID 1188  ←
  PID 4412                PID 2304                PID 2304
                          PID 4412                PID 4412

  PID 1188 is visible to WMIC and tasklist but hidden from psutil
  → Flagged as a hidden process (kernel rootkit indicator)
```

The same cross-view approach is applied to network sockets (psutil vs netstat) and kernel drivers (driverquery vs registry).

---

## Features

| Module | What it checks |
|---|---|
| **Process Scanner** | Hidden PIDs — cross-view: psutil vs WMIC vs tasklist. Masquerade detection (wrong exe path), temp-dir launches, bad parent relationships |
| **Network Scanner** | Hidden sockets — psutil vs netstat -ano. Known malware/C2 ports (4444, 1337, 9050 …) with per-process whitelist |
| **Driver Scanner** | Hidden drivers — driverquery vs registry. Unsigned, suspicious-path, or no-description kernel drivers |
| **Registry Scanner** | Autorun keys (HKCU/HKLM Run, RunOnce), Winlogon hijack, IFEO debugger hijack, BootExecute |
| **Persistence Scanner** | Scheduled tasks, WMI subscriptions, startup folders, services in temp dirs, AppInit_DLLs, LSA packages |
| **File Integrity Monitor** | SHA-256 hashes of critical Windows binaries (ntoskrnl, ntdll, kernel32, lsass …) compared against baseline |
| **Memory / Volatility** | DKOM, process hollowing, injected shellcode (requires Volatility 3 — optional) |

**Random Forest ML Classifier** — 500-tree forest with balanced class weights, trained on a 35-feature vector extracted from every finding. Benchmarked as the best-performing model for this dataset (see ML section below).

**RAG False-Positive Filter** — local-only knowledge base (JSON + difflib fuzzy matching). Suppresses known-benign software before results reach the user. No data ever leaves the machine.

**Email Reports** — inline HTML scan reports via your own SMTP server (Gmail / Outlook / custom).

---

## Requirements

- Windows 10 / 11
- Python 3.10+
- Administrator privileges recommended (required for driver / kernel scans)

---

## Setup

**1. Install dependencies**
```bash
pip install -r requirements.txt
```

**2. Clone Volatility 3** *(optional — only needed for memory dump analysis)*
```bash
git clone https://github.com/volatilityfoundation/volatility3.git Tools/volatility3
```
All other scan modules work without it.

---

## Quick Start

Double-click **`Tools\launch.bat`** — it auto-elevates to Administrator.

Or from a terminal:
```bash
cd RootkitScannerProject\Tools
python gui_restored.py
```

**Dev / hot-reload mode** (auto-restarts the GUI on every save):
```bash
pip install watchdog   # one-time
python dev.py          # watches gui_restored.py; Ctrl+C to stop
python dev.py --all    # watch all .py files in Tools/
```

---

## GUI Overview

| Tab | Contents |
|---|---|
| **Scan Output** | Live scan results with severity colour-coding and ML verdict |
| **History** | All previous scans with score, verdict, and diff comparison |
| **Model Info** | Architecture, feature engineering, performance metrics, benchmark |
| **Dashboard** | Threat trend chart, quick actions, ML snapshot, recent scans |
| **About** | Full explanation of how ShieldScan works — start here |

**Login features** — local account system (SHA-256 hashed passwords), account registration, and **Forgot Password** reset dialog.

---

## Project Structure

```
RootkitScannerProject/
├── Tools/
│   ├── gui_restored.py         # Main GUI (tkinter) — all features
│   ├── dev.py                  # Hot-reload dev runner (watchdog / polling)
│   ├── main.py                 # CLI entry point
│   ├── launch.bat              # Windows launcher (auto-elevates)
│   ├── process_analyzer.py     # Hidden process detection (cross-view)
│   ├── rootkit_detector.py     # Process heuristics (masquerade, temp-path …)
│   ├── network_scanner.py      # Socket / port anomaly detection
│   ├── driver_scanner.py       # Kernel driver inspection
│   ├── registry_scanner.py     # Autorun / persistence registry checks
│   ├── fim_scanner.py          # File integrity monitoring (SHA-256)
│   ├── persistence_scanner.py  # Tasks, services, WMI, LSA, AppInit
│   ├── memory_capture.py       # Volatility memory acquisition
│   ├── volatility_analyzer.py  # Volatility 3 wrapper
│   ├── rag_filter.py           # Local RAG false-positive filter
│   ├── baseline_manager.py     # Baseline capture & diff
│   ├── config.py               # Settings
│   ├── knowledge_base/
│   │   └── benign_entries.json # RAG knowledge base
│   └── ml_model/
│       ├── threat_model.py     # Random Forest classifier
│       ├── model_data.py       # Built-in training samples (180 samples, 16 classes)
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

```bash
cd Tools
python ml_model/train.py                   # built-in data only (default)
python ml_model/train.py --kaggle          # augment with Kaggle datasets
python ml_model/train.py --max-rows 4000  # limit rows per Kaggle dataset
```

Kaggle augmentation requires `~/.kaggle/kaggle.json` (Kaggle API key).

---

## ML Model — Random Forest (Deep Dive)

### Why Random Forest?

ShieldScan's classifier was benchmarked against a full stacking ensemble (Random Forest + Extra Trees + Gradient Boosting + XGBoost with a Logistic Regression meta-learner). Results on the built-in dataset:

```
  ┌─────────────────────┬──────────┬──────────┐
  │ Model               │ Accuracy │ F1 Macro │
  ├─────────────────────┼──────────┼──────────┤
  │ Random Forest       │  93.89%  │  0.9466  │  ← ShieldScan
  │ Extra Trees         │  92.22%  │  0.9306  │
  │ XGBoost             │  88.89%  │  0.8992  │
  │ Gradient Boosting   │  88.89%  │  0.8922  │
  │ Stacking Ensemble   │  87.22%  │  0.8841  │  ← worse than any single model
  └─────────────────────┴──────────┴──────────┘

  Dataset: 180 samples · 16 threat categories · 5-fold stratified CV
```

With only 180 samples across 16 classes (≈11 samples per class), the stacking meta-learner adds noise rather than signal — it overfits to the OOF probability patterns instead of the underlying threat features. Random Forest alone gives the best bias-variance trade-off.

---

### Architecture

```
  Raw Scan Finding
  { reason, severity, port, name, scan_type }
           │
           ▼
  Feature Extraction  →  35-dimensional numeric vector
           │
           ▼
  StandardScaler  →  Z-score normalisation (mean=0, std=1)
           │
           ▼
  RandomForestClassifier
  ┌──────────────────────────────────────────┐
  │  500 decision trees                      │
  │  Each tree trained on a random subset    │
  │  of samples (bootstrap) and features     │
  │  (sqrt of 35 = ~6 features per split)    │
  │  class_weight = "balanced"               │
  │  (rare threat classes get more weight)   │
  └──────────────────┬───────────────────────┘
                     │  majority vote across all 500 trees
                     ▼
  Output:  category="ROOTKIT_PROCESS"  confidence=0.94
           mitre=["T1014"]  steps=[...]
```

---

### Feature Extraction — 35 Features

Every scan finding is converted into a fixed-length numeric vector:

```
  Feature   Value   Meaning
  ───────────────────────────────────────────────────────────
  [0]         2     Scan type ID  (Process=2, Network=3 …)
  [1]         3     Severity      (HIGH=3, MED=2, LOW=1)
  [2]      4444     Raw port number
  [3]         0     Is well-known port?  (1–1023)
  [4]         0     Is registered port?  (1024–49151)
  [5]         1     Known malware port?  (4444=YES)
  [6]         1     Is system process name?  (svchost=YES)
  [7]        11     Process name length  (capped at 64)
  [8]        48     Reason string length  (capped at 256)
  [9]         1     Keyword: "hidden from"
  [10]        1     Keyword: "absent from psutil"
  [11]        1     Keyword: "wmic"
  [12]        0     Keyword: "netstat"
  [13]        0     Keyword: "kernel-level evasion"
  [14]        0     Keyword: "masquerade / wrong path"
  [15]        0     Keyword: "inject / injected"
  [16]        0     Keyword: " dll "
  [17]        0     Keyword: temp directory path
  [18]        0     Keyword: AppData / Downloads / Desktop path
  [19]        0     Keyword: "unsigned / not signed"
  [20]        0     Keyword: "parent / ppid"
  [21]        0     Keyword: Run key / RunOnce
  [22]        0     Keyword: "winlogon / userinit / shell"
  [23]        0     Keyword: IFEO / debugger
  [24]        0     Keyword: "malware port / C2"
  [25]        0     Keyword: "hook / hooked"
  [26]        0     Keyword: "shellcode / malfind"
  [27]        0     Keyword: "hollow / dkom"
  [28]        0     Keyword: "autostart / persistence"
  [29]        0     Keyword: "scheduled task / schtasks"
  [30]        0     Keyword: "WMI subscription"
  [31]        0     Keyword: "service / imagepa"
  [32]        0     Keyword: "appinit / lsa package"
  [33]        0     Keyword: "visible in psutil but absent"
  [34]        0     Keyword: "startup folder"
```

---

### Training Metrics

Saved to `ml_model/model_meta.json` and displayed in the **Model Info** tab:

| Metric | What it means |
|---|---|
| **CV Accuracy** | Mean accuracy across 5 stratified folds |
| **F1 Macro** | Harmonic mean of precision + recall, equal weight per class — best indicator for imbalanced multi-class |
| **F1 Weighted** | Same but weighted by class frequency |
| **Precision Macro** | Of everything flagged as a threat, how many were actually threats |
| **Recall Macro** | Of all real threats, how many did the model catch |
| **AUC-ROC** | Area under the ROC curve — 1.0 = perfect, 0.5 = random |

---

### Threat Categories

```
  ┌──────────────────────────┬──────────────────────────────────────────┐
  │ Category                 │ Example Findings                         │
  ├──────────────────────────┼──────────────────────────────────────────┤
  │ ROOTKIT_PROCESS          │ PID hidden from psutil, visible in WMIC  │
  │ ROOTKIT_DRIVER           │ Unsigned / unknown kernel driver         │
  │ ROOTKIT_NETWORK          │ Orphan socket, hidden TCP connection      │
  │ ROOTKIT_REGISTRY         │ IFEO hijack, hidden Run key              │
  │ ROOTKIT_MEMORY           │ Shellcode, DKOM, process hollowing       │
  │ PROCESS_INJECTION        │ Injected DLL, hollow process             │
  │ MALWARE_PORT             │ Connection on known C2 port              │
  │ PERSISTENCE              │ Suspicious scheduled task / service      │
  │ KERNEL_HOOK              │ SSDT / IAT hook detected                 │
  │ FIM_VIOLATION            │ Critical system file modified            │
  │ MASQUERADE               │ System binary running from wrong path    │
  │ SUSPICIOUS               │ Anomalous but not conclusive             │
  │ BENIGN                   │ Known-good system activity               │
  └──────────────────────────┴──────────────────────────────────────────┘
```

Each prediction also returns **MITRE ATT&CK technique IDs** (T1014, T1055, T1547 …) and step-by-step remediation guidance.

---

## Security & Privacy

- **100% offline.** ShieldScan never opens a network socket of its own.
- **No telemetry.** No scan data, process names, or file paths ever leave the machine.
- **RAG filter is local-only** — uses only `difflib` (Python stdlib) and a local JSON file. An import-time guard blocks any accidental network import.
- **Local accounts** — passwords stored as SHA-256 hashes in `users.json` (excluded from version control by `.gitignore`).
- `email_config.json` (SMTP credentials) is also excluded from version control.

---

## License

For defensive and educational use only.
