"""
Kaggle dataset fetcher for model augmentation.

Targets publicly accessible datasets (no license-acceptance required):

  1. themrinmoy/network-intrusion-detection-system-dataset
     Network connections labeled as Normal/Anomalous — maps to our
     NETWORK_HIDING / MALWARE_PORT / BENIGN categories.

  2. pranavbansal0110/malware-classification-dataset
     Malware PE feature classification — maps to process/driver threat
     categories.

  3. hetulmehta/network-intrusion-detection-connection-records
     Alternate network intrusion dataset (fallback).

  NOTE on 403 errors:
  Some popular datasets (microsoft/malware-prediction, cicdataset/cicids2017)
  require you to manually accept their license on kaggle.com BEFORE the API
  will allow download. If you want to use those, visit their pages and click
  "I Understand and Accept", then re-run: python main.py --update-ml --kaggle

Setup (one-time):
  pip install kaggle
  Place your API token at %USERPROFILE%\.kaggle\access_token
  (Download from https://www.kaggle.com/settings -> API -> Create Token)

Usage:
  from ml_model.kaggle_fetcher import fetch_and_convert
  extra_samples = fetch_and_convert()   # returns list of training tuples
"""

from __future__ import annotations

import os
import json
import logging
import tempfile
import csv

log = logging.getLogger(__name__)

_HERE      = os.path.dirname(os.path.abspath(__file__))
_CACHE_DIR = os.path.join(_HERE, "kaggle_cache")

# ---------------------------------------------------------------------------
# Kaggle API helpers
# ---------------------------------------------------------------------------

def _check_kaggle_available() -> bool:
    try:
        import kaggle  # noqa: F401
        return True
    except ImportError:
        log.warning(
            "kaggle package not installed. Run: pip install kaggle\n"
            "Then place your API token at %%USERPROFILE%%\\.kaggle\\access_token"
        )
        return False


def _kaggle_api():
    # kaggle >= 2.0 uses 'from kaggle import api' (singleton, already authenticated)
    try:
        from kaggle import api as _api
        _api.authenticate()
        return _api
    except ImportError:
        pass
    # Fallback for kaggle < 2.0
    from kaggle.api.kaggle_api_extended import KaggleApiExtended
    _api = KaggleApiExtended()
    _api.authenticate()
    return _api


# ---------------------------------------------------------------------------
# Dataset 1: Network Intrusion Detection — sampadab17/network-intrusion-detection
#   KDD Cup-style dataset: 41 features + 'class' label
# ---------------------------------------------------------------------------

_NIDS_DATASET  = "sampadab17/network-intrusion-detection"
_NIDS_LABEL_MAP = {
    "normal":    "BENIGN",
    "neptune":   "MALWARE_PORT",
    "satan":     "NETWORK_HIDING",
    "ipsweep":   "NETWORK_HIDING",
    "portsweep": "NETWORK_HIDING",
    "smurf":     "MALWARE_PORT",
    "nmap":      "NETWORK_HIDING",
    "back":      "MALWARE_PORT",
    "teardrop":  "MALWARE_PORT",
    "warezclient": "MALWARE_PORT",
    "warezmaster": "MALWARE_PORT",
    "spy":       "PROCESS_HIDING",
    "rootkit":   "KERNEL_HOOK",
    "buffer_overflow": "MEMORY_INJECTION",
    "loadmodule": "DRIVER_SUSPICIOUS",
    "perl":      "TEMP_EXECUTION",
    "multihop":  "MALWARE_PORT",
    "phf":       "MALWARE_PORT",
    "ftp_write": "REGISTRY_PERSISTENCE",
    "imap":      "MALWARE_PORT",
    "land":      "NETWORK_HIDING",
    "pod":       "MALWARE_PORT",
}


def _fetch_nids_dataset(api, max_rows: int = 5000) -> list[tuple]:
    """Download and convert the KDD/NSL-KDD inspired NIDS dataset."""
    cache_file = os.path.join(_CACHE_DIR, "nids_converted.json")
    if os.path.exists(cache_file):
        log.info("Using cached NIDS dataset")
        with open(cache_file) as f:
            return [tuple(s) for s in json.load(f)]

    os.makedirs(_CACHE_DIR, exist_ok=True)
    out_dir = os.path.join(_CACHE_DIR, "nids")
    os.makedirs(out_dir, exist_ok=True)

    log.info("Downloading Network Intrusion Detection dataset...")
    try:
        api.dataset_download_files(_NIDS_DATASET, path=out_dir, unzip=True)
    except Exception as exc:
        _log_403_hint(exc, _NIDS_DATASET)
        return []

    import glob
    csv_files = glob.glob(os.path.join(out_dir, "**", "*.csv"), recursive=True)
    if not csv_files:
        log.warning("No CSV files found in NIDS download")
        return []

    samples: list[tuple] = []
    per_file = max(1, max_rows // max(len(csv_files), 1))

    for csv_path in csv_files:
        try:
            with open(csv_path, encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for i, row in enumerate(reader):
                    if i >= per_file:
                        break
                    s = _nids_row_to_sample(row)
                    if s:
                        samples.append(s)
        except Exception as exc:
            log.warning("Error reading %s: %s", csv_path, exc)

    with open(cache_file, "w") as f:
        json.dump(samples, f)
    log.info("Converted %d samples from NIDS dataset", len(samples))
    return samples


def _nids_row_to_sample(row: dict) -> tuple | None:
    # KDD Cup columns: 'class' is the label (normal / attack_type)
    label_raw = (
        row.get("class") or row.get("label") or row.get("Label") or "normal"
    ).strip().lower()

    label = "BENIGN"
    for key, mapped in _NIDS_LABEL_MAP.items():
        if key in label_raw:
            label = mapped
            break

    try:
        duration  = int(float(row.get("duration", 0) or 0))
        src_bytes = int(float(row.get("src_bytes", 0) or 0))
        dst_bytes = int(float(row.get("dst_bytes", 0) or 0))
        root_shell= int(float(row.get("root_shell", 0) or 0))
        num_root  = int(float(row.get("num_root", 0) or 0))
        service   = row.get("service", "")
        protocol  = row.get("protocol_type", "")
    except (ValueError, TypeError):
        return None

    # Map service name to a representative port
    _svc_port = {"http": 80, "ftp": 21, "smtp": 25, "ssh": 22, "telnet": 23,
                 "ftp_data": 20, "imap4": 143, "pop_3": 110, "domain": 53}
    port = _svc_port.get(service, 0)

    if label == "BENIGN":
        reason = (f"Normal {protocol} connection: service={service} duration={duration}s "
                  f"src_bytes={src_bytes} dst_bytes={dst_bytes}")
    else:
        extra = ""
        if root_shell:
            extra += " root shell obtained"
        if num_root > 0:
            extra += f" num_root={num_root}"
        reason = (f"Malicious {protocol} activity ({label_raw}): service={service} "
                  f"duration={duration}s src_bytes={src_bytes} dst_bytes={dst_bytes}"
                  f"{extra} possible kernel-level evasion or malware port usage")

    severity = "MEDIUM" if label == "BENIGN" else "HIGH"
    return (reason, "Network", severity, port, "<network>", label)


# ---------------------------------------------------------------------------
# Dataset 2: Windows Malware PE features — joebeachcapital/windows-malwares
#   Columns: SHA256, Type (0=benign,1=malware), + binary API/DLL features
# ---------------------------------------------------------------------------

_WIN_MAL_DATASET = "joebeachcapital/windows-malwares"

# API calls that strongly indicate specific threat categories
_API_TO_CATEGORY = {
    "createremotethread":          "MEMORY_INJECTION",
    "virtualallocex":              "MEMORY_INJECTION",
    "writeprocessmemory":          "MEMORY_INJECTION",
    "ntcreatethreadex":            "MEMORY_INJECTION",
    "loadlibrary":                 "DLL_INJECTION",
    "loadlibrarya":                "DLL_INJECTION",
    "loadlibraryexw":              "DLL_INJECTION",
    "regsetvalueex":               "REGISTRY_PERSISTENCE",
    "regsetvalueexa":              "REGISTRY_PERSISTENCE",
    "regcreatekeyex":              "REGISTRY_PERSISTENCE",
    "createservice":               "DRIVER_SUSPICIOUS",
    "openscmanager":               "DRIVER_SUSPICIOUS",
    "ntloadsdriver":               "DRIVER_SUSPICIOUS",
    "setwindowshookex":            "DLL_INJECTION",
    "createprocesswithtokenw":     "PROCESS_MASQUERADE",
    "openprocess":                 "PROCESS_HIDING",
    "adjusttokenprivileges":       "PROCESS_HIDING",
    "ntopenprocess":               "PROCESS_HIDING",
}


def _fetch_windows_malware_dataset(api, max_rows: int = 4000) -> list[tuple]:
    """Download and convert the Windows Malware PE features dataset."""
    cache_file = os.path.join(_CACHE_DIR, "winmal_converted.json")
    if os.path.exists(cache_file):
        log.info("Using cached Windows malware dataset")
        with open(cache_file) as f:
            return [tuple(s) for s in json.load(f)]

    os.makedirs(_CACHE_DIR, exist_ok=True)
    out_dir = os.path.join(_CACHE_DIR, "winmal")
    os.makedirs(out_dir, exist_ok=True)

    log.info("Downloading Windows Malware PE dataset (joebeachcapital/windows-malwares)...")
    try:
        api.dataset_download_files(_WIN_MAL_DATASET, path=out_dir, unzip=True)
    except Exception as exc:
        _log_403_hint(exc, _WIN_MAL_DATASET)
        return []

    import glob
    csv_files = glob.glob(os.path.join(out_dir, "**", "*.csv"), recursive=True)
    if not csv_files:
        log.warning("No CSV files found in Windows malware dataset")
        return []

    samples: list[tuple] = []
    per_file = max(1, max_rows // max(len(csv_files), 1))

    for csv_path in csv_files:
        try:
            with open(csv_path, encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for i, row in enumerate(reader):
                    if i >= per_file:
                        break
                    s = _winmal_row_to_sample(row)
                    if s:
                        samples.append(s)
        except Exception as exc:
            log.warning("Error reading %s: %s", csv_path, exc)

    with open(cache_file, "w") as f:
        json.dump(samples, f)
    log.info("Converted %d samples from Windows malware dataset", len(samples))
    return samples


def _winmal_row_to_sample(row: dict) -> tuple | None:
    try:
        malware_type = int(row.get("Type", 0))
    except (ValueError, TypeError):
        return None

    sha = row.get("SHA256", "unknown")[:16]

    if malware_type == 0:
        return (f"Clean Windows PE file {sha}: no malicious API calls or DLL imports",
                "Process", "INFO", 0, sha, "BENIGN")

    # Malware — determine most likely category from active API features
    active_apis = [col for col, val in row.items()
                   if col.lower() != "type" and col.lower() != "sha256"
                   and str(val).strip() == "1"]

    label = "TEMP_EXECUTION"  # default for generic malware
    for api_name in active_apis:
        mapped = _API_TO_CATEGORY.get(api_name.lower())
        if mapped:
            label = mapped
            break

    api_summary = ", ".join(active_apis[:5]) if active_apis else "no notable APIs"
    reason = (f"Malicious PE {sha}: active APIs [{api_summary}] "
              f"inject dll hidden process suspicious path temp execution registry persist")

    return (reason, "Process", "HIGH", 0, sha, label)


# ---------------------------------------------------------------------------
# Shared helper
# ---------------------------------------------------------------------------

def _log_403_hint(exc: Exception, dataset_id: str):
    msg = str(exc)
    if "403" in msg or "Forbidden" in msg:
        log.warning(
            "Dataset '%s' returned 403 Forbidden.\n"
            "  This usually means you need to accept the dataset license on Kaggle first.\n"
            "  Visit: https://www.kaggle.com/datasets/%s\n"
            "  Click 'I Understand and Accept', then re-run: python main.py --update-ml --kaggle",
            dataset_id, dataset_id,
        )
    else:
        log.warning("Dataset '%s' download failed: %s", dataset_id, exc)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def fetch_and_convert(max_rows_per_dataset: int = 4000) -> list[tuple]:
    """
    Download Kaggle datasets and return converted training samples.
    Returns an empty list if kaggle is not set up.
    """
    if not _check_kaggle_available():
        return []

    try:
        api = _kaggle_api()
    except Exception as exc:
        log.warning("Kaggle authentication failed: %s\n"
                    "Place your API token at %%USERPROFILE%%\\.kaggle\\access_token", exc)
        return []

    samples: list[tuple] = []

    nids_samples = _fetch_nids_dataset(api, max_rows=max_rows_per_dataset)
    samples.extend(nids_samples)
    log.info("Added %d samples from Network Intrusion Detection (KDD) dataset", len(nids_samples))

    winmal_samples = _fetch_windows_malware_dataset(api, max_rows=max_rows_per_dataset)
    samples.extend(winmal_samples)
    log.info("Added %d samples from Windows Malware PE dataset", len(winmal_samples))

    log.info("Total Kaggle samples: %d", len(samples))
    return samples


def clear_cache():
    """Delete all cached Kaggle data so fresh downloads happen on next run."""
    import shutil
    if os.path.exists(_CACHE_DIR):
        shutil.rmtree(_CACHE_DIR)
        log.info("Kaggle cache cleared: %s", _CACHE_DIR)
