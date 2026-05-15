import json
import os

_BASE        = os.path.dirname(os.path.abspath(__file__))
_CONFIG_PATH = os.path.join(_BASE, "config.json")

_DEFAULTS = {
    "dumpit_path":    "",
    "volatility_path": "",
    "output_dir":     "logs",
    "scan_timeout":   300,
    "scans": {
        "process":  True,
        "driver":   True,
        "network":  True,
        "registry": True,
        "memory":   False,
    },
    "ignore": {
        "process_names":  [],
        "ports":          [],
        "driver_names":   [],
        "pids":           [],
        "reason_contains": [],
    },
}


def _auto_detect_dumpit() -> str:
    for c in [os.path.join(_BASE, "x64", "DumpIt.exe"), os.path.join(_BASE, "DumpIt.exe")]:
        if os.path.exists(c):
            return c
    return ""


def _auto_detect_volatility() -> str:
    c = os.path.join(_BASE, "volatility3", "vol.py")
    return c if os.path.exists(c) else ""


def load() -> dict:
    cfg = json.loads(json.dumps(_DEFAULTS))   # deep copy
    if os.path.exists(_CONFIG_PATH):
        try:
            with open(_CONFIG_PATH, encoding="utf-8") as f:
                on_disk = json.load(f)
            # merge top-level keys
            for k, v in on_disk.items():
                if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                    cfg[k].update(v)
                else:
                    cfg[k] = v
        except (json.JSONDecodeError, OSError):
            pass

    if not cfg["dumpit_path"]:
        cfg["dumpit_path"] = _auto_detect_dumpit()
    if not cfg["volatility_path"]:
        cfg["volatility_path"] = _auto_detect_volatility()

    if not os.path.isabs(cfg["output_dir"]):
        cfg["output_dir"] = os.path.join(_BASE, cfg["output_dir"])
    os.makedirs(cfg["output_dir"], exist_ok=True)

    return cfg


def save(cfg: dict) -> None:
    """Persist the current config back to config.json (exclude auto-detected paths)."""
    to_save = {k: v for k, v in cfg.items()
               if k not in ("dumpit_path", "volatility_path") or v}
    # Use the raw disk values for paths that were auto-detected (keep them blank)
    if os.path.exists(_CONFIG_PATH):
        try:
            with open(_CONFIG_PATH, encoding="utf-8") as f:
                existing = json.load(f)
        except Exception:
            existing = {}
    else:
        existing = {}

    for path_key in ("dumpit_path", "volatility_path"):
        to_save[path_key] = existing.get(path_key, "")

    with open(_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(to_save, f, indent=2)


def apply_ignore(findings: dict[str, list[dict]], ignore: dict) -> tuple[dict, list[dict]]:
    """
    Filter findings using the ignore rules.
    Returns (filtered_findings, suppressed_list).
    """
    proc_names  = {n.lower() for n in ignore.get("process_names", [])}
    ports       = set(ignore.get("ports", []))
    drv_names   = {n.lower() for n in ignore.get("driver_names", [])}
    pids        = set(ignore.get("pids", []))
    reason_kws  = [kw.lower() for kw in ignore.get("reason_contains", [])]

    filtered    = {}
    suppressed  = []

    for section, items in findings.items():
        kept = []
        for f in items:
            reason = f.get("reason", "").lower()
            name   = str(f.get("name", "")).lower()
            proc   = str(f.get("process", "")).lower()
            port   = f.get("port")
            pid    = f.get("pid")
            drv    = str(f.get("name", "")).lower()

            if name in proc_names or proc in proc_names:
                suppressed.append(f); continue
            if port is not None and port in ports:
                suppressed.append(f); continue
            if section == "Driver" and drv in drv_names:
                suppressed.append(f); continue
            if pid is not None and pid in pids:
                suppressed.append(f); continue
            if any(kw in reason for kw in reason_kws):
                suppressed.append(f); continue
            kept.append(f)
        filtered[section] = kept

    return filtered, suppressed
