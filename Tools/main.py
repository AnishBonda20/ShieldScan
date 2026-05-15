"""
Rootkit Detector — main orchestrator  v0.5

Usage:
    python main.py                       # run all scans
    python main.py --process             # process scan only
    python main.py --driver              # driver scan only
    python main.py --network             # network scan only
    python main.py --registry            # registry scan only
    python main.py --fim                 # file-integrity scan only
    python main.py --persistence         # persistence-mechanism scan only
    python main.py --memory dump.dmp     # Volatility memory analysis
    python main.py --all                 # force every scan
    python main.py --watch 60            # continuous mode, rescan every 60 s

Baseline commands:
    python main.py --baseline            # capture a system snapshot
    python main.py --diff                # scan + compare against last baseline
    python main.py --list-baselines      # list saved baselines

ML controls:
    python main.py --no-ml               # skip ML analysis
    python main.py --update-ml           # retrain model then exit
    python main.py --update-ml --kaggle  # retrain with Kaggle augmentation

Misc:
    python main.py --no-report           # skip HTML report
    python main.py --reset-fim           # clear FIM hash baseline
    python main.py --ignore-process svchost.exe
    python main.py --ignore-port 8080
    python main.py --list-ignored
    python main.py --clear-ignored
"""

import argparse
import logging
import os
import sys
import json
import time
import threading
import itertools
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Force UTF-8 output so Unicode block characters (█ ░) work on Windows
# regardless of the active console code page (cp1252 etc.)
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import config

# ---------------------------------------------------------------------------
# ANSI color helpers
# ---------------------------------------------------------------------------

_USE_COLOR = sys.stdout.isatty()

_SEV_COLOR = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[94m", "INFO": "\033[96m"}
_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_DIM    = "\033[2m"
_GREEN  = "\033[92m"
_CYAN   = "\033[96m"
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_WHITE  = "\033[97m"
_BLUE   = "\033[94m"
_MAGENTA = "\033[95m"

def _c(text: str, code: str) -> str:
    return f"{code}{text}{_RESET}" if _USE_COLOR else text


# ---------------------------------------------------------------------------
# Spinner
# ---------------------------------------------------------------------------

class _Spinner:
    _FRAMES = ["|", "/", "-", "\\"]

    def __init__(self):
        self._active: list[str] = []
        self._lock      = threading.Lock()
        self._stop_evt  = threading.Event()
        self._thread    = threading.Thread(target=self._run, daemon=True)
        self._enabled   = _USE_COLOR

    def _run(self):
        for frame in itertools.cycle(self._FRAMES):
            if self._stop_evt.is_set():
                break
            with self._lock:
                names = list(self._active)
            if names and self._enabled:
                label = " + ".join(names)
                line  = f"  [{frame}] Scanning: {label}..."
                sys.stdout.write(f"\r{_BOLD}{line}{_RESET}" if _USE_COLOR else f"\r{line}")
                sys.stdout.flush()
            self._stop_evt.wait(0.1)

    def clear_line(self):
        if self._enabled:
            sys.stdout.write("\r" + " " * 88 + "\r")
            sys.stdout.flush()

    def set_active(self, names: list[str]):
        with self._lock:
            self._active = list(names)

    def remove(self, name: str):
        with self._lock:
            self._active = [n for n in self._active if n != name]

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._stop_evt.set()
        if self._thread.is_alive():
            self._thread.join()
        self.clear_line()


# ---------------------------------------------------------------------------
# Console UI helpers
# ---------------------------------------------------------------------------

_W = 62

def _banner():
    top   = "+" + "=" * (_W - 2) + "+"
    mid   = "|" + " " * (_W - 2) + "|"
    title = "ROOTKIT DETECTOR  v0.5"
    sub   = "Defensive / Educational Use Only"
    t_pad = (_W - 2 - len(title)) // 2
    s_pad = (_W - 2 - len(sub))   // 2

    print()
    print(_c(top, _CYAN))
    print(_c(mid, _CYAN))
    print(_c("|" + " " * t_pad + title + " " * (_W - 2 - t_pad - len(title)) + "|", _CYAN + _BOLD))
    print(_c("|" + " " * s_pad + sub   + " " * (_W - 2 - s_pad - len(sub))   + "|", _CYAN))
    print(_c(mid, _CYAN))
    print(_c(top, _CYAN))
    print()
    print(_c(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", _DIM))
    print(_c("  " + "-" * (_W - 2), _DIM))
    print()


def _section_result(name: str, count: int, elapsed: float):
    if count == 0:
        badge = _c("[OK]", _GREEN)
        cnt   = _c("0 finding(s)", _GREEN)
    else:
        badge = _c("[!!]", _RED)
        cnt   = _c(f"{count} finding(s)", _RED)
    time_str = _c(f"{elapsed:.1f}s", _DIM)
    print(f"  {badge}  {name:<12}  {cnt:<30}  {time_str}")


def _print_findings(name: str, findings: list[dict]):
    if not findings:
        return
    for f in findings:
        sev     = f.get("severity", "INFO")
        color   = _SEV_COLOR.get(sev, "")
        sev_lbl = _c(f"[{sev[:3]}]", color)
        reason  = f.get("reason", "")
        max_r   = 70
        if len(reason) > max_r:
            reason = reason[:max_r - 3] + "..."
        print(f"        {sev_lbl}  {reason}")

        ml = f.get("ml")
        if ml and ml.get("category") not in (None, "UNKNOWN"):
            cat       = ml["category"]
            conf      = ml["confidence"]
            urgency   = ml.get("urgency", "")
            is_benign = ml.get("is_benign", False)

            conf_bar  = "#" * int(conf * 10) + "." * (10 - int(conf * 10))
            cat_color = _GREEN if is_benign else (_RED if urgency == "IMMEDIATE" else _YELLOW)
            urg_color = _GREEN if is_benign else (_RED if urgency == "IMMEDIATE" else _YELLOW)

            print(
                f"               {_c('ML:', _CYAN)}  {_c(cat, cat_color)}"
                f"  conf=[{_c(conf_bar, urg_color)}] {conf:.0%}"
                f"  urgency={_c(urgency, urg_color)}"
            )
            mitre = ml.get("mitre", [])
            if mitre:
                print(f"               {_c('ATT&CK:', _DIM)}  {_c(' | '.join(mitre[:2]), _DIM)}")
            if ml.get("steps"):
                print(f"               {_c('Action:', _DIM)}  {_c(ml['steps'][0], _DIM)}")


def _print_summary(results: dict[str, list[dict]], timings: dict[str, float], total_elapsed: float):
    total = sum(len(v) for v in results.values())
    high  = sum(1 for v in results.values() for f in v if f.get("severity") == "HIGH")
    med   = sum(1 for v in results.values() for f in v if f.get("severity") == "MEDIUM")

    w   = _W
    sep = "  +" + "-" * (w - 4) + "+"
    top = "  +" + "=" * (w - 4) + "+"
    hdr = "  |" + " SCAN COMPLETE ".center(w - 4) + "|"

    print()
    print(_c(top, _BOLD))
    print(_c(hdr, _BOLD))
    print(_c(top, _BOLD))
    print()

    col_hdr = f"  {'Scanner':<14}  {'Findings':>8}  {'HIGH':>6}  {'MED':>5}  {'Time':>7}"
    print(_c(col_hdr, _DIM))
    print(_c("  " + "-" * (w - 2), _DIM))

    for section, findings in results.items():
        h = sum(1 for f in findings if f.get("severity") == "HIGH")
        m = sum(1 for f in findings if f.get("severity") == "MEDIUM")
        t = timings.get(section, 0.0)
        h_txt = (_c(f"{h:>6}", _RED)    if h else f"{'0':>6}")
        m_txt = (_c(f"{m:>5}", _YELLOW) if m else f"{'0':>5}")
        n_txt = (_c(f"{len(findings):>8}", _RED) if findings else f"{'0':>8}")
        print(f"  {section:<14}  {n_txt}  {h_txt}  {m_txt}  {t:>6.1f}s")

    print(_c("  " + "-" * (w - 2), _DIM))
    h_txt = (_c(f"{high:>6}", _RED)    if high else f"{'0':>6}")
    m_txt = (_c(f"{med:>5}",  _YELLOW) if med  else f"{'0':>5}")
    n_txt = (_c(f"{total:>8}", _RED)   if total else f"{'0':>8}")
    print(f"  {'TOTAL':<14}  {n_txt}  {h_txt}  {m_txt}  {total_elapsed:>6.1f}s")
    print(_c("  " + "=" * (w - 2), _BOLD))
    print()

    if total == 0:
        verdict = _c("  [OK] No suspicious indicators found. System appears clean.", _GREEN + _BOLD)
    elif high == 0:
        verdict = _c(f"  [!!] {med} medium-severity item(s) detected. Review recommended.", _YELLOW + _BOLD)
    else:
        verdict = _c(f"  [!!] {high} HIGH-severity finding(s) detected. Investigate immediately.", _RED + _BOLD)

    print(verdict)
    print()


# ---------------------------------------------------------------------------
# Risk Score
# ---------------------------------------------------------------------------

_URGENCY_WEIGHT = {"IMMEDIATE": 30, "HIGH": 15, "MEDIUM": 5, "LOW": 1}
_SEV_WEIGHT     = {"HIGH": 10, "MEDIUM": 4, "LOW": 1, "INFO": 0}


def _calculate_risk_score(findings: dict[str, list[dict]]) -> tuple[int, str, str]:
    """Return (score 0-100, verdict string, ANSI color)."""
    score = 0
    for flist in findings.values():
        for f in flist:
            ml        = f.get("ml", {})
            is_benign = ml.get("is_benign", False)
            if is_benign:
                continue
            urgency = ml.get("urgency", "")
            sev     = f.get("severity", "INFO")
            if urgency in _URGENCY_WEIGHT:
                score += _URGENCY_WEIGHT[urgency]
            else:
                score += _SEV_WEIGHT.get(sev, 0)

    score = min(score, 100)

    if score == 0:
        return score, "CLEAN",       _GREEN
    if score <= 15:
        return score, "LOW RISK",    _CYAN
    if score <= 40:
        return score, "SUSPICIOUS",  _YELLOW
    return     score, "COMPROMISED", _RED


def _print_risk_score(score: int, verdict: str, color: str):
    bar_width = 32
    filled    = round(score / 100 * bar_width)
    empty     = bar_width - filled
    bar       = _c("█" * filled, color) + _c("░" * empty, _DIM)
    label     = _c(f"  Risk Score: {score:>3}/100  [{bar}]  {verdict}", color + _BOLD)
    print(label)
    print()


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def _setup_logging(output_dir: str) -> str:
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = os.path.join(output_dir, f"rootkit_scan_{ts}.log")

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s  %(levelname)-8s  %(name)s -- %(message)s"))
    root.addHandler(fh)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.WARNING)
    ch.setFormatter(logging.Formatter("  %(message)s"))
    root.addHandler(ch)

    return log_path


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

_HTML_SEV_COLOR = {
    "HIGH":   ("#fde8e8", "#c0392b"),
    "MEDIUM": ("#fef3e2", "#d68910"),
    "LOW":    ("#fefde8", "#b7950b"),
    "INFO":   ("#e8f4fd", "#2980b9"),
}


def _build_html_report(
    all_findings: dict[str, list[dict]],
    scan_time: str,
    log_path: str,
    timings: dict[str, float],
    total_elapsed: float,
    risk_score: int = 0,
    risk_verdict: str = "CLEAN",
) -> str:
    total = sum(len(v) for v in all_findings.values())
    high  = sum(1 for v in all_findings.values() for f in v if f.get("severity") == "HIGH")
    med   = sum(1 for v in all_findings.values() for f in v if f.get("severity") == "MEDIUM")

    section_cards = ""
    for section, findings in all_findings.items():
        h = sum(1 for f in findings if f.get("severity") == "HIGH")
        m = sum(1 for f in findings if f.get("severity") == "MEDIUM")
        t = timings.get(section, 0.0)
        badge = (f"<span style='color:#c0392b;font-weight:bold'>{h} HIGH</span> / "
                 f"<span style='color:#d68910'>{m} MED</span>")
        section_cards += (
            f"<div class='scard'>"
            f"<div class='scard-title'>{section}</div>"
            f"<div class='scard-badge'>{badge}</div>"
            f"<div class='scard-time'>{t:.1f}s</div>"
            f"</div>"
        )

    rows = []
    for section, findings in all_findings.items():
        for fi, f in enumerate(findings):
            sev    = f.get("severity", "INFO")
            bg, fg = _HTML_SEV_COLOR.get(sev, ("#f9f9f9", "#555"))
            reason = f.get("reason", "").replace("<", "&lt;").replace(">", "&gt;")
            detail_parts = []
            for k in ("pid", "name", "port", "process", "plugin", "location", "address"):
                if k in f:
                    detail_parts.append(f"<b>{k}:</b> {str(f[k]).replace('<','&lt;')}")
            detail = " &nbsp; ".join(detail_parts)

            ml        = f.get("ml", {})
            ml_cat    = ml.get("category", "")
            ml_conf   = ml.get("confidence", 0.0)
            ml_urg    = ml.get("urgency", "")
            ml_mitre  = ml.get("mitre", [])
            ml_steps  = ml.get("steps", [])
            ml_desc   = ml.get("description", "")
            row_id    = f"rem_{section}_{fi}"
            urg_color = {"IMMEDIATE": "#c0392b", "HIGH": "#e67e22",
                         "MEDIUM": "#d68910", "LOW": "#27ae60"}.get(ml_urg, "#888")

            if ml_cat:
                conf_pct   = int(ml_conf * 100)
                mitre_html = "".join(f"<span class='mitre-badge'>{m}</span>" for m in ml_mitre)
                steps_html = "".join(f"<li>{s}</li>" for s in ml_steps)
                ml_cell = (
                    f"<div class='ml-cat' style='color:{urg_color}'>{ml_cat}</div>"
                    f"<div class='ml-conf'>Confidence: {conf_pct}%"
                    f"  <span class='conf-bar'><span style='width:{conf_pct}%;background:{urg_color}'></span></span>"
                    f"</div>"
                    f"{mitre_html}"
                    f"<details id='{row_id}'><summary class='rem-toggle'>Remediation steps</summary>"
                    f"<div class='rem-box'>"
                    f"<p class='rem-desc'>{ml_desc}</p>"
                    f"<ol class='rem-steps'>{steps_html}</ol>"
                    f"</div></details>"
                )
            else:
                ml_cell = "<span style='color:#aaa'>—</span>"

            rows.append(
                f"<tr style='background:{bg}'>"
                f"<td><span style='color:{fg};font-weight:600;font-size:.85em'>{sev}</span></td>"
                f"<td style='color:#555;font-size:.85em'>{section}</td>"
                f"<td>{reason}<div style='font-size:.8em;color:#666;margin-top:4px'>{detail}</div></td>"
                f"<td class='ml-cell'>{ml_cell}</td>"
                f"</tr>"
            )

    rows_html = (
        "\n".join(rows) if rows
        else "<tr><td colspan='4' style='color:#27ae60;text-align:center;padding:20px'>"
             "No findings &mdash; system appears clean.</td></tr>"
    )

    overall_color = "#27ae60" if total == 0 else ("#c0392b" if high > 0 else "#d68910")
    overall_label = "CLEAN" if total == 0 else ("THREATS DETECTED" if high > 0 else "WARNINGS")

    # Risk score gauge
    score_color = (
        "#27ae60" if risk_score == 0 else
        "#3498db" if risk_score <= 15 else
        "#d68910" if risk_score <= 40 else
        "#c0392b"
    )
    score_pct   = risk_score   # 0-100 → used as percentage for gauge arc fill

    risk_panel = f"""
  <div class="risk-panel">
    <div class="risk-left">
      <div class="risk-label">System Risk Score</div>
      <div class="risk-score" style="color:{score_color}">{risk_score}<span class="risk-denom">/100</span></div>
      <div class="risk-verdict" style="background:{score_color}">{risk_verdict}</div>
    </div>
    <div class="risk-right">
      <div class="risk-bar-wrap">
        <div class="risk-bar-fill" style="width:{score_pct}%;background:{score_color}"></div>
      </div>
      <div class="risk-hint">
        0–15 Low Risk &nbsp;|&nbsp; 16–40 Suspicious &nbsp;|&nbsp; 41–100 Compromised
      </div>
    </div>
  </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Rootkit Detector -- {scan_time}</title>
<style>
  *      {{ box-sizing:border-box; margin:0; padding:0; }}
  body   {{ font-family:'Segoe UI',Arial,sans-serif; background:#f0f2f5; color:#2c3e50; }}
  .topbar{{ background:#1a252f; color:#ecf0f1; padding:18px 32px; display:flex;
           justify-content:space-between; align-items:center; }}
  .topbar h1{{ font-size:1.3em; letter-spacing:1px; }}
  .topbar .meta{{ font-size:.8em; color:#95a5a6; }}
  .wrap  {{ max-width:1200px; margin:0 auto; padding:28px; }}
  .verdict{{ background:{overall_color}; color:#fff; border-radius:8px; padding:16px 24px;
            font-size:1.1em; font-weight:700; margin-bottom:18px; letter-spacing:1px; }}
  /* Risk panel */
  .risk-panel{{ background:#fff; border-radius:8px; padding:18px 24px; margin-bottom:22px;
               box-shadow:0 1px 4px rgba(0,0,0,.1); display:flex; align-items:center; gap:28px; }}
  .risk-left {{ text-align:center; min-width:120px; }}
  .risk-label {{ font-size:.75em; color:#888; margin-bottom:4px; text-transform:uppercase;
                letter-spacing:.5px; }}
  .risk-score {{ font-size:2.8em; font-weight:700; line-height:1; }}
  .risk-denom {{ font-size:.4em; color:#aaa; }}
  .risk-verdict{{ display:inline-block; color:#fff; font-size:.78em; font-weight:700;
                 padding:3px 10px; border-radius:20px; margin-top:6px; letter-spacing:.5px; }}
  .risk-right {{ flex:1; }}
  .risk-bar-wrap{{ background:#e0e0e0; border-radius:6px; height:14px; overflow:hidden;
                  margin-bottom:8px; }}
  .risk-bar-fill{{ height:100%; border-radius:6px; transition:width .4s; }}
  .risk-hint {{ font-size:.75em; color:#888; }}
  /* Summary cards */
  .cards {{ display:flex; gap:16px; flex-wrap:wrap; margin-bottom:22px; }}
  .card  {{ background:#fff; border-radius:8px; padding:16px 22px; box-shadow:0 1px 4px rgba(0,0,0,.1);
           text-align:center; min-width:110px; }}
  .card .num{{ font-size:2em; font-weight:700; }}
  .red   {{ color:#c0392b; }}
  .amber {{ color:#d68910; }}
  .green {{ color:#27ae60; }}
  .scards{{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:24px; }}
  .scard {{ background:#fff; border-radius:8px; padding:12px 18px;
           box-shadow:0 1px 4px rgba(0,0,0,.08); min-width:130px;
           border-top:3px solid #3498db; }}
  .scard-title{{ font-weight:600; font-size:.9em; margin-bottom:4px; }}
  .scard-badge{{ font-size:.8em; }}
  .scard-time {{ font-size:.75em; color:#888; margin-top:4px; }}
  /* Findings table */
  table  {{ width:100%; border-collapse:collapse; background:#fff; border-radius:8px;
           overflow:hidden; box-shadow:0 1px 4px rgba(0,0,0,.1); }}
  th     {{ background:#2c3e50; color:#ecf0f1; padding:11px 14px; text-align:left;
           font-size:.85em; letter-spacing:.5px; }}
  td     {{ padding:9px 14px; border-bottom:1px solid #edf2f7; vertical-align:top;
           font-size:.9em; }}
  tr:last-child td{{ border-bottom:none; }}
  tr:hover{{ filter:brightness(0.97); }}
  /* ML cell */
  .ml-cell {{ min-width:200px; }}
  .ml-cat  {{ font-weight:700; font-size:.85em; margin-bottom:4px; }}
  .ml-conf {{ font-size:.78em; color:#555; display:flex; align-items:center; gap:6px;
             margin-bottom:4px; }}
  .conf-bar{{ display:inline-block; width:80px; height:7px; background:#e0e0e0;
             border-radius:4px; overflow:hidden; }}
  .conf-bar span{{ display:block; height:100%; border-radius:4px; }}
  .mitre-badge{{ display:inline-block; background:#2c3e50; color:#ecf0f1; font-size:.7em;
                padding:2px 6px; border-radius:3px; margin:2px 2px 4px 0; }}
  .rem-toggle{{ cursor:pointer; font-size:.8em; color:#3498db; font-weight:600;
               list-style:none; padding:4px 0; }}
  .rem-box {{ background:#f8f9fa; border-left:3px solid #3498db; padding:10px 14px;
             margin-top:6px; border-radius:0 6px 6px 0; }}
  .rem-desc{{ font-size:.82em; color:#555; margin-bottom:8px; font-style:italic; }}
  .rem-steps{{ font-size:.8em; color:#2c3e50; padding-left:18px; }}
  .rem-steps li{{ margin-bottom:4px; }}
  .ml-stale{{ background:#fff3cd; border:1px solid #ffc107; border-radius:6px;
             padding:10px 16px; margin-bottom:16px; font-size:.85em; color:#856404; }}
  .footer{{ margin-top:24px; color:#95a5a6; font-size:.78em; text-align:center; }}
</style>
</head>
<body>
<div class="topbar">
  <h1>ROOTKIT DETECTOR</h1>
  <div class="meta">
    Scan: <b>{scan_time}</b> &nbsp;|&nbsp;
    Duration: <b>{total_elapsed:.1f}s</b> &nbsp;|&nbsp;
    Log: <code>{os.path.basename(log_path)}</code>
  </div>
</div>
<div class="wrap">
  <div class="verdict">{overall_label} &mdash; {total} finding(s) &nbsp;|&nbsp; {high} HIGH &nbsp;|&nbsp; {med} MEDIUM</div>

  {risk_panel}

  <div class="cards">
    <div class="card"><div class="num {'red' if total>0 else 'green'}">{total}</div>Total</div>
    <div class="card"><div class="num {'red' if high>0 else 'green'}">{high}</div>HIGH</div>
    <div class="card"><div class="num {'amber' if med>0 else 'green'}">{med}</div>MEDIUM</div>
    <div class="card"><div class="num">{total_elapsed:.1f}s</div>Duration</div>
  </div>

  <div class="scards">{section_cards}</div>

  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Scanner</th>
        <th>Description</th>
        <th>ML Analysis &amp; Remediation</th>
      </tr>
    </thead>
    <tbody>
{rows_html}
    </tbody>
  </table>

  <div class="footer">
    Generated by Rootkit Detector v0.5 &mdash; for defensive / educational use only.
    &nbsp;|&nbsp; ML: scikit-learn RandomForest / XGBoost
  </div>
</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Scan runners
# ---------------------------------------------------------------------------

def _timed(name: str, fn):
    t0 = time.perf_counter()
    result = fn()
    return name, result, time.perf_counter() - t0


def _run_process_scan():
    from rootkit_detector import scan_processes
    from process_analyzer import run_analysis
    return scan_processes() + run_analysis()


def _run_driver_scan():
    from driver_scanner import scan_drivers
    return scan_drivers()


def _run_network_scan():
    from network_scanner import scan_network
    return scan_network()


def _run_registry_scan():
    from registry_scanner import scan_registry
    return scan_registry()


def _run_fim_scan():
    from fim_scanner import scan_file_integrity
    return scan_file_integrity()


def _run_persistence_scan():
    from persistence_scanner import scan_persistence
    return scan_persistence()


def _run_memory_scan(dump_path: str, vol_py: str):
    from volatility_analyzer import analyze_dump
    return analyze_dump(dump_path, vol_py)


def _run_diff_scan():
    from baseline_manager import load_latest, diff
    baseline = load_latest()
    if baseline is None:
        return [{
            "severity": "INFO",
            "reason":   "No baseline found. Run: python main.py --baseline to capture one.",
            "name":     "<baseline>",
        }]
    findings = diff(baseline)
    ts = baseline.get("captured_at", "unknown")
    if not findings:
        return [{
            "severity": "INFO",
            "reason":   f"Baseline diff: no changes detected since snapshot taken at {ts}.",
            "name":     "<baseline>",
        }]
    return findings


# ---------------------------------------------------------------------------
# Ignore management
# ---------------------------------------------------------------------------

def _handle_ignore_commands(args, cfg: dict) -> bool:
    ignore  = cfg.setdefault("ignore", {
        "process_names": [], "ports": [], "driver_names": [],
        "pids": [], "reason_contains": [],
    })
    changed = False

    if args.ignore_process:
        name = args.ignore_process.lower()
        if name not in ignore["process_names"]:
            ignore["process_names"].append(name)
            print(f"  Added to ignore list: process name '{name}'")
            changed = True
        else:
            print(f"  Already ignored: process name '{name}'")

    if args.ignore_port is not None:
        if args.ignore_port not in ignore["ports"]:
            ignore["ports"].append(args.ignore_port)
            print(f"  Added to ignore list: port {args.ignore_port}")
            changed = True
        else:
            print(f"  Already ignored: port {args.ignore_port}")

    if args.ignore_driver:
        name = args.ignore_driver.lower()
        if name not in ignore["driver_names"]:
            ignore["driver_names"].append(name)
            print(f"  Added to ignore list: driver '{name}'")
            changed = True
        else:
            print(f"  Already ignored: driver '{name}'")

    if args.ignore_pid is not None:
        if args.ignore_pid not in ignore["pids"]:
            ignore["pids"].append(args.ignore_pid)
            print(f"  Added to ignore list: PID {args.ignore_pid}")
            changed = True
        else:
            print(f"  Already ignored: PID {args.ignore_pid}")

    if args.ignore_reason:
        kw = args.ignore_reason.lower()
        if kw not in ignore["reason_contains"]:
            ignore["reason_contains"].append(kw)
            print(f"  Added to ignore list: reason containing '{kw}'")
            changed = True
        else:
            print(f"  Already ignored: reason containing '{kw}'")

    if changed:
        config.save(cfg)
        print("  Saved to config.json\n")
        return True

    if args.list_ignored:
        print(_c("\n  Current ignore list:\n", _BOLD))
        ig = cfg.get("ignore", {})
        any_rules = False
        for label, items in [
            ("Process names",   ig.get("process_names",   [])),
            ("Ports",           ig.get("ports",           [])),
            ("Driver names",    ig.get("driver_names",    [])),
            ("PIDs",            ig.get("pids",            [])),
            ("Reason keywords", ig.get("reason_contains", [])),
        ]:
            if items:
                print(f"  {label}:")
                for item in items:
                    print(f"    - {item}")
                any_rules = True
        if not any_rules:
            print("  (empty -- no ignore rules configured)")
        print()
        return True

    if args.clear_ignored:
        cfg["ignore"] = {
            "process_names": [], "ports": [], "driver_names": [],
            "pids": [], "reason_contains": [],
        }
        config.save(cfg)
        print("  Ignore list cleared.\n")
        return True

    return False


# ---------------------------------------------------------------------------
# ML retraining helper
# ---------------------------------------------------------------------------

def _retrain_model(use_kaggle: bool = False):
    import subprocess
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ml_model", "train.py")
    cmd    = [sys.executable, script]
    if use_kaggle:
        cmd.append("--kaggle")
    print(_c("\n  Launching ML trainer...\n", _CYAN))
    return subprocess.run(cmd).returncode


# ---------------------------------------------------------------------------
# Core scan executor (shared between single-run and watch-mode)
# ---------------------------------------------------------------------------

def _execute_scans(
    tasks: dict,
    cfg: dict,
    log,
    args,
) -> tuple[dict[str, list[dict]], dict[str, float], float, object | None]:
    """
    Run all tasks, load ML classifier in background, enrich findings.
    Returns (all_findings, timings, total_elapsed, ml_clf).
    """
    all_findings: dict[str, list[dict]] = {}
    timings:      dict[str, float]      = {}

    fast_tasks   = {k: v for k, v in tasks.items() if k != "Process"}
    process_task = tasks.get("Process")

    spinner = _Spinner().start()

    # Load ML in background while scans run
    _ml_clf   = None
    _ml_ready = threading.Event()

    def _load_ml():
        nonlocal _ml_clf
        if args.no_ml:
            _ml_ready.set()
            return
        try:
            from ml_model.threat_model import get_classifier
            _ml_clf = get_classifier()
        except Exception as exc:
            log.warning("ML classifier unavailable: %s", exc)
        _ml_ready.set()

    threading.Thread(target=_load_ml, daemon=True).start()

    wall_start = time.perf_counter()

    if process_task:
        spinner.set_active(["Process"])
        _, proc_results, proc_elapsed = _timed("Process", process_task)
        all_findings["Process"] = proc_results
        timings["Process"]      = proc_elapsed
        spinner.clear_line()
        _section_result("Process", len(proc_results), proc_elapsed)
        _print_findings("Process", proc_results)
        log.debug("Process scan: %d findings in %.1fs", len(proc_results), proc_elapsed)

    if fast_tasks:
        spinner.set_active(list(fast_tasks.keys()))
        executor     = ThreadPoolExecutor(max_workers=len(fast_tasks))
        fast_futures = {executor.submit(_timed, name, fn): name for name, fn in fast_tasks.items()}

        for future in as_completed(fast_futures):
            name, results, elapsed = future.result()
            all_findings[name] = results
            timings[name]      = elapsed
            spinner.remove(name)
            spinner.clear_line()
            _section_result(name, len(results), elapsed)
            _print_findings(name, results)
            log.debug("%s scan: %d findings in %.1fs", name, len(results), elapsed)

        executor.shutdown(wait=False)

    spinner.stop()
    total_elapsed = time.perf_counter() - wall_start

    # ML enrichment
    _ml_ready.wait(timeout=30)
    if _ml_clf is not None:
        total_findings = sum(len(v) for v in all_findings.values())
        if total_findings:
            sp2 = _Spinner().start()
            sp2.set_active(["ML Analysis"])
            try:
                _ml_clf.analyze_findings(all_findings)
            finally:
                sp2.stop()
        if _ml_clf.is_stale():
            print(_c("  [ML] Model is over 30 days old. Run: python main.py --update-ml --kaggle", _YELLOW))
    elif not args.no_ml:
        print(_c("  [ML] scikit-learn not installed — ML analysis skipped. Run: pip install scikit-learn numpy", _DIM))

    return all_findings, timings, total_elapsed, _ml_clf


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    cfg = config.load()

    parser = argparse.ArgumentParser(
        description="Rootkit Detector v0.5",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Scan selection:\n"
            "  --process --driver --network --registry --fim --persistence\n\n"
            "Baseline:\n"
            "  --baseline        capture a system snapshot\n"
            "  --diff            scan + compare against last snapshot\n"
            "  --list-baselines  list all saved baselines\n\n"
            "Watch mode:\n"
            "  --watch N         rescan every N seconds; show only new findings\n\n"
            "Ignore rules:\n"
            "  --ignore-process svchost.exe\n"
            "  --ignore-port 8080\n"
            "  --ignore-driver expressvpn\n"
            "  --ignore-pid 1234\n"
            "  --ignore-reason 'OneDrive'\n"
            "  --list-ignored  /  --clear-ignored\n"
        ),
    )

    # Scan selection
    parser.add_argument("--all",         action="store_true", help="Run every scan module")
    parser.add_argument("--process",     action="store_true", help="Process scan")
    parser.add_argument("--driver",      action="store_true", help="Driver scan")
    parser.add_argument("--network",     action="store_true", help="Network scan")
    parser.add_argument("--registry",    action="store_true", help="Registry scan")
    parser.add_argument("--fim",         action="store_true", help="File integrity scan")
    parser.add_argument("--persistence", action="store_true", help="Persistence mechanism scan")
    parser.add_argument("--memory",      metavar="DUMP",      help="Memory dump for Volatility")

    # Baseline
    parser.add_argument("--baseline",        action="store_true", help="Capture system baseline snapshot")
    parser.add_argument("--diff",            action="store_true", help="Include baseline diff as a scan")
    parser.add_argument("--list-baselines",  action="store_true", help="List saved baselines and exit")

    # Watch mode
    parser.add_argument("--watch", metavar="SECONDS", type=int, default=0,
                        help="Continuous monitor: rescan every N seconds")

    # Output
    parser.add_argument("--no-report",  action="store_true", help="Skip HTML report")

    # Ignore management
    parser.add_argument("--ignore-process", metavar="NAME")
    parser.add_argument("--ignore-port",    metavar="PORT",  type=int)
    parser.add_argument("--ignore-driver",  metavar="NAME")
    parser.add_argument("--ignore-pid",     metavar="PID",   type=int)
    parser.add_argument("--ignore-reason",  metavar="TEXT")
    parser.add_argument("--list-ignored",   action="store_true")
    parser.add_argument("--clear-ignored",  action="store_true")

    # ML
    parser.add_argument("--no-ml",     action="store_true", help="Skip ML analysis")
    parser.add_argument("--update-ml", action="store_true", help="Retrain ML model then exit")
    parser.add_argument("--kaggle",    action="store_true", help="Use Kaggle data when retraining")

    # FIM
    parser.add_argument("--reset-fim", action="store_true", help="Clear FIM hash baseline and exit")

    args = parser.parse_args()

    # --- Early-exit one-shot commands ---

    if args.update_ml:
        _retrain_model(use_kaggle=args.kaggle)
        return 0

    if args.reset_fim:
        from fim_scanner import reset_baseline
        reset_baseline()
        print("  FIM baseline cleared — will be re-established on next scan.")
        return 0

    if args.baseline:
        from baseline_manager import capture
        print(_c("\n  Capturing system baseline...\n", _CYAN))
        snap = capture()
        print(f"  Saved: {snap['_path']}")
        print(f"  Processes : {len(snap['processes'])}")
        print(f"  Services  : {len(snap['services'])}")
        print(f"  Autoruns  : {len(snap['autoruns'])}")
        print()
        return 0

    if args.list_baselines:
        from baseline_manager import list_baselines
        bl = list_baselines()
        if not bl:
            print("  No baselines found. Run: python main.py --baseline")
        else:
            print(_c("\n  Saved baselines (newest first):\n", _BOLD))
            for b in bl:
                print(f"    {b}")
        print()
        return 0

    if _handle_ignore_commands(args, cfg):
        return 0

    # --- Determine which scans to run ---
    explicit = any([
        args.process, args.driver, args.network, args.registry,
        args.fim, args.persistence, args.memory, args.diff,
    ])
    run_all = args.all or not explicit

    log_path = _setup_logging(cfg["output_dir"])
    log      = logging.getLogger("main")

    _banner()
    print(_c(f"  Log : {os.path.basename(log_path)}", _DIM))
    print()

    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log.debug("Rootkit Detector v0.5 starting -- %s", scan_time)

    def _build_tasks():
        tasks: dict[str, callable] = {}
        if run_all or args.process:
            tasks["Process"]     = _run_process_scan
        if run_all or args.driver:
            tasks["Driver"]      = _run_driver_scan
        if run_all or args.network:
            tasks["Network"]     = _run_network_scan
        if run_all or args.registry:
            tasks["Registry"]    = _run_registry_scan
        if run_all or args.fim:
            tasks["FIM"]         = _run_fim_scan
        if run_all or args.persistence:
            tasks["Persistence"] = _run_persistence_scan
        if args.diff:
            tasks["Baseline"]    = _run_diff_scan
        if args.memory or (cfg["scans"].get("memory") and run_all):
            dump = args.memory or ""
            tasks["Memory"] = lambda: _run_memory_scan(dump, cfg["volatility_path"])
        return tasks

    # -----------------------------------------------------------------------
    # Watch mode
    # -----------------------------------------------------------------------
    if args.watch and args.watch > 0:
        interval    = args.watch
        prev_reasons: set[str] = set()
        iteration   = 0

        print(_c(f"  [WATCH] Continuous mode — rescanning every {interval}s. Press Ctrl+C to stop.\n", _CYAN + _BOLD))

        try:
            while True:
                iteration += 1
                if iteration > 1:
                    print(_c(f"\n  [WATCH] Iteration {iteration} — {datetime.now().strftime('%H:%M:%S')}", _CYAN + _BOLD))
                    print(_c("  " + "-" * (_W - 2), _DIM))

                tasks = _build_tasks()
                all_findings, timings, total_elapsed, _ = _execute_scans(tasks, cfg, log, args)

                ordered, suppressed = config.apply_ignore(
                    {k: all_findings[k] for k in tasks if k in all_findings},
                    cfg.get("ignore", {}),
                )

                current_reasons = {
                    f.get("reason", "")
                    for flist in ordered.values()
                    for f in flist
                }
                new_reasons      = current_reasons - prev_reasons
                resolved_reasons = prev_reasons - current_reasons

                if iteration == 1:
                    _print_summary(ordered, timings, total_elapsed)
                    score, verdict, color = _calculate_risk_score(ordered)
                    _print_risk_score(score, verdict, color)
                else:
                    # Only print deltas
                    new_count = len(new_reasons)
                    res_count = len(resolved_reasons)
                    if new_count:
                        print(_c(f"  [NEW FINDINGS: {new_count}]", _RED + _BOLD))
                        for section, flist in ordered.items():
                            for f in flist:
                                if f.get("reason", "") in new_reasons:
                                    sev   = f.get("severity", "INFO")
                                    color2 = _SEV_COLOR.get(sev, "")
                                    print(f"    {_c('[NEW]', _RED)} {_c(f'[{sev[:3]}]', color2)}  {f.get('reason','')[:80]}")
                    if res_count:
                        print(_c(f"  [{res_count} finding(s) resolved since last scan]", _GREEN))
                    if not new_count and not res_count:
                        print(_c("  No changes detected since last scan.", _GREEN))

                    # Updated risk score
                    score, verdict, color = _calculate_risk_score(ordered)
                    _print_risk_score(score, verdict, color)

                prev_reasons = current_reasons

                print(_c(f"  [WATCH] Next scan in {interval}s — Ctrl+C to stop", _DIM))
                time.sleep(interval)

        except KeyboardInterrupt:
            print(_c("\n\n  [WATCH] Stopped.", _DIM))
            return 0

    # -----------------------------------------------------------------------
    # Single scan
    # -----------------------------------------------------------------------
    tasks        = _build_tasks()
    all_findings, timings, total_elapsed, _ml_clf = _execute_scans(tasks, cfg, log, args)

    ordered, suppressed = config.apply_ignore(
        {k: all_findings[k] for k in tasks if k in all_findings},
        cfg.get("ignore", {}),
    )

    if suppressed:
        print(_c(f"\n  [{len(suppressed)} finding(s) suppressed by ignore rules]", _DIM))

    _print_summary(ordered, timings, total_elapsed)

    # Risk score
    score, verdict, color = _calculate_risk_score(ordered)
    _print_risk_score(score, verdict, color)

    total = sum(len(v) for v in ordered.values())
    high  = sum(1 for v in ordered.values() for f in v if f.get("severity") == "HIGH")

    log.debug("SCAN COMPLETE -- %d findings (%d HIGH) in %.1fs", total, high, total_elapsed)

    # Save outputs
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if not args.no_report:
        report_path = os.path.join(cfg["output_dir"], f"report_{ts}.html")
        html = _build_html_report(
            ordered, scan_time, log_path, timings, total_elapsed,
            risk_score=score, risk_verdict=verdict,
        )
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html)
        log.debug("HTML report: %s", report_path)
        print(f"  Report -> {report_path}")

    json_path = os.path.join(cfg["output_dir"], f"findings_{ts}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(ordered, f, indent=2, default=str)
    log.debug("JSON findings: %s", json_path)
    print(f"  Log    -> {log_path}\n")

    return 1 if high > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
