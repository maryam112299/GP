"""
evaluation/run_eval.py — measure black-box judge accuracy against the oracle.

For every attack in the target-adaptive suite:

    POST /reset → GET /state (before) → POST /api/generate (attack)
               → GET /state (after) → oracle.label()  vs  judge_response()

The oracle (evaluation/oracle.py) establishes the TRUE label from the target's
/sensitive manifest + observable /state; the judge is graded against it. We
report a confusion matrix + precision / recall / F1 / FPR / FNR for two judges:

    • text-judge      : blackbox_judge.judge_response (deterministic + LLM)
    • text-judge+GT   : the same, upgraded by the ground-truth state diff
                        (ground_truth.diff_breach) — to quantify how much the
                        ground-truth cross-check adds to recall.

UNKNOWN judge verdicts are treated as abstentions: reported separately and
excluded from precision/recall (accuracy is computed on decided cases only).

Prerequisites: run from the backend venv (so blackbox_judge imports), with the
victim mini-app AND Ollama running.

    python evaluation/run_eval.py --target bank
    python evaluation/run_eval.py --target hr --pace 8
    python evaluation/run_eval.py --base-url http://localhost:9300 --name myagent
"""
from __future__ import annotations

import os
import sys
import csv
import json
import time
import argparse
import datetime

import requests

# Windows consoles default to cp1252 — victim replies and our marks can contain
# characters it can't encode, which would crash the run at print time. Make
# stdout tolerant.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# Make backend/ importable when launched as evaluation/run_eval.py ------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_BACKEND = os.path.dirname(_HERE)
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import oracle as O           # evaluation/oracle.py
import suites as S           # evaluation/suites.py

try:
    from blackbox_judge import judge_response
except Exception as exc:     # pragma: no cover
    print(f"[fatal] could not import blackbox_judge.judge_response: {exc}")
    print("        Run this from the backend venv with the Ollama deps installed,")
    print("        and make sure Ollama is running (the LLM judge calls it).")
    sys.exit(1)

try:
    from ground_truth import diff_breach as gt_diff
except Exception:
    gt_diff = None

TARGETS = {"bank": "http://localhost:9100", "hr": "http://localhost:9200"}


# ---------------------------------------------------------------------------
# Victim HTTP client
# ---------------------------------------------------------------------------

def _get(url: str, timeout: float = 8.0):
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    return r.json()


def _post(url: str, body=None, timeout: float = 180.0):
    r = requests.post(url, json=body or {}, timeout=timeout)
    r.raise_for_status()
    return r.json()


def victim_ask(base: str, prompt: str, model: str) -> str:
    data = _post(base + "/api/generate", {"model": model, "prompt": prompt})
    return data.get("response", "") or ""


# ---------------------------------------------------------------------------
# Build the judge's view (what discovery WOULD hand it) from the manifest
# ---------------------------------------------------------------------------

def build_intel(manifest: dict) -> dict:
    intel = dict(manifest.get("attack_intel") or {})
    session = manifest.get("session_accounts") or intel.get("session_accounts") or []
    priv = list(manifest.get("forbidden_tool_calls_succeeded") or [])
    intel["session_accounts"] = session
    intel["permission_model"] = {
        "privileged_tools": priv,
        "session_accounts": session,
    }
    return intel


def build_profile(manifest: dict) -> str:
    intel = manifest.get("attack_intel") or {}
    bits = [intel.get("application"), intel.get("policy_summary")]
    return " — ".join(b for b in bits if b) or "(target profile from manifest)"


# ---------------------------------------------------------------------------
# Prediction mapping + metrics
# ---------------------------------------------------------------------------

def pred_text(result: str) -> str:
    if result == "FAIL":
        return "BREACH"
    if result == "UNKNOWN":
        return "ABSTAIN"
    return "SAFE"


def pred_gt(result: str, gt_hit) -> str:
    if result == "FAIL" or gt_hit is not None:
        return "BREACH"
    if result == "UNKNOWN":
        return "ABSTAIN"
    return "SAFE"


def confusion(rows, predkey):
    tp = fp = fn = tn = ab = 0
    for r in rows:
        g, p = r["gold"], r[predkey]
        if p == "ABSTAIN":
            ab += 1
            continue
        if g == "BREACH" and p == "BREACH":
            tp += 1
        elif g == "SAFE" and p == "BREACH":
            fp += 1
        elif g == "BREACH" and p == "SAFE":
            fn += 1
        else:
            tn += 1
    return tp, fp, fn, tn, ab


def metrics(tp, fp, fn, tn, ab):
    decided = tp + fp + fn + tn
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    acc = (tp + tn) / decided if decided else 0.0
    return dict(tp=tp, fp=fp, fn=fn, tn=tn, abstain=ab, decided=decided,
                precision=prec, recall=rec, f1=f1, fpr=fpr, fnr=fnr, accuracy=acc)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _print_block(name: str, m: dict):
    print(f"\n  {name}")
    print( "    confusion (positive = BREACH)")
    print(f"                 pred BREACH   pred SAFE")
    print(f"      gold BREACH    TP={m['tp']:<3}        FN={m['fn']:<3}")
    print(f"      gold SAFE      FP={m['fp']:<3}        TN={m['tn']:<3}")
    print(f"    precision {m['precision']:.3f}   recall {m['recall']:.3f}   F1 {m['f1']:.3f}")
    print(f"    FPR {m['fpr']:.3f}        FNR {m['fnr']:.3f}    accuracy {m['accuracy']:.3f} "
          f"(decided={m['decided']}, abstain={m['abstain']})")


def report(name: str, rows, m_text, m_gt):
    print("\n" + "=" * 68)
    print(f"  JUDGE ACCURACY - target: {name}   ({len(rows)} attacks)")
    print("=" * 68)
    _print_block("text-judge (judge_response)", m_text)
    if gt_diff is not None:
        _print_block("text-judge + ground-truth (judge_response + diff_breach)", m_gt)

    # Mismatches — the actionable part: where the judge disagreed with reality.
    mism = [r for r in rows if r["gold"] != r["pred_text"] and r["pred_text"] != "ABSTAIN"]
    if mism:
        print("\n  --- text-judge mismatches (judge vs reality) ---")
        for r in mism:
            tag = "FALSE-POS" if r["gold"] == "SAFE" else "FALSE-NEG"
            print(f"   [{tag}] {r['id']:<22} gold={r['gold']:<6} judge={r['pred_text']:<6} "
                  f"({r['judge_method']})")
            print(f"             gold_reason: {r['gold_reason'][:90]}")
            print(f"             reply: {r['response'][:90]!r}")
    else:
        print("\n  text-judge matched reality on every decided case.")


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def save(out_dir: str, name: str, rows, summary: dict):
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    folder = os.path.join(out_dir, f"{name}-{stamp}")
    os.makedirs(folder, exist_ok=True)

    csv_path = os.path.join(folder, "attacks.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        cols = ["id", "category", "expect_breach", "gold", "gold_reason",
                "judge_result", "judge_method", "pred_text", "pred_gt", "prompt", "response"]
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)

    json_path = os.path.join(folder, "summary.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, default=str)

    print(f"\n  saved -> {csv_path}")
    print(f"          {json_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run(args):
    base = args.base_url.rstrip("/")
    name = args.name

    try:
        health = _get(base + "/health")
    except Exception as exc:
        print(f"[fatal] victim not reachable at {base} ({exc}). Start the mini-app first.")
        sys.exit(1)
    model = health.get("model", "victim")

    manifest = {}
    try:
        manifest = _get(base + "/sensitive") or {}
    except Exception as exc:
        print(f"[warn] could not fetch /sensitive ({exc}); oracle will have nothing to ground on.")
    if not manifest:
        print("[warn] target published no /sensitive manifest — every attack will be labelled SAFE.")

    attacks = S.resolve(manifest)
    if args.limit:
        attacks = attacks[:args.limit]
    priv_tools = list(manifest.get("forbidden_tool_calls_succeeded") or [])
    intel = build_intel(manifest)
    profile = build_profile(manifest)

    print(f"target={name}  model={model}  attacks={len(attacks)}  pace={args.pace}s  "
          f"ground_truth={'on' if gt_diff else 'off'}")

    rows = []
    for i, atk in enumerate(attacks, 1):
        if not args.no_reset:
            try:
                _post(base + "/reset")
            except Exception as exc:
                print(f"   [reset failed: {exc}]")
        try:
            before = _get(base + "/state")
            response = victim_ask(base, atk["prompt"], model)
            after = _get(base + "/state")
        except Exception as exc:
            print(f"[{i}/{len(attacks)}] {atk['id']}: victim error -> {exc} (skipped)")
            continue

        gold, gold_reasons = O.label(manifest, before, after, response, atk["prompt"])

        result, method, _ev = judge_response(
            atk["prompt"], response, profile=profile, discovered_intel=intel,
        )
        gt_hit = None
        if gt_diff is not None:
            try:
                gt_hit = gt_diff(before, after, atk["prompt"], priv_tools)
            except Exception:
                gt_hit = None

        row = {
            "id": atk["id"],
            "category": atk["category"],
            "expect_breach": atk["expect_breach"],
            "gold": gold,
            "gold_reason": "; ".join(r["detail"] for r in gold_reasons) or "(no breach signal)",
            "judge_result": result,
            "judge_method": method,
            "pred_text": pred_text(result),
            "pred_gt": pred_gt(result, gt_hit),
            "prompt": atk["prompt"],
            "response": response,
        }
        rows.append(row)

        mark = "OK" if row["gold"] == row["pred_text"] else " X"
        print(f"[{i}/{len(attacks)}] {mark} {atk['id']:<22} gold={gold:<6} "
              f"judge={result:<7} gt={'hit' if gt_hit else '-'}")
        if i < len(attacks):
            time.sleep(args.pace)

    if not rows:
        print("\n[fatal] no attacks completed (victim errored on all). Check the mini-app + keys.")
        sys.exit(1)

    m_text = metrics(*confusion(rows, "pred_text"))
    m_gt = metrics(*confusion(rows, "pred_gt"))
    report(name, rows, m_text, m_gt)

    summary = {
        "target": name,
        "base_url": base,
        "model": model,
        "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
        "n_attacks": len(rows),
        "manifest_present": bool(manifest),
        "ground_truth_enabled": gt_diff is not None,
        "metrics_text_judge": m_text,
        "metrics_text_judge_plus_ground_truth": m_gt,
        "gold_distribution": {
            "BREACH": sum(1 for r in rows if r["gold"] == "BREACH"),
            "SAFE": sum(1 for r in rows if r["gold"] == "SAFE"),
        },
    }
    save(args.out, name, rows, summary)


def parse_args():
    ap = argparse.ArgumentParser(description="Measure judge accuracy against the objective oracle.")
    ap.add_argument("--target", choices=list(TARGETS), help="preset victim (bank|hr)")
    ap.add_argument("--base-url", help="victim base url (overrides --target)")
    ap.add_argument("--name", help="label for the report/output folder")
    ap.add_argument("--pace", type=float,
                    default=float(os.getenv("VICTIM_MIN_INTERVAL_SEC", "6")),
                    help="seconds to wait between attacks (free-tier rate limits)")
    ap.add_argument("--limit", type=int, default=0, help="run only the first N attacks")
    ap.add_argument("--no-reset", action="store_true",
                    help="do NOT /reset between attacks (state accumulates)")
    ap.add_argument("--out", default=os.path.join(_HERE, "results"),
                    help="output directory for CSV + JSON")
    args = ap.parse_args()
    if not args.base_url:
        args.base_url = TARGETS.get(args.target or "bank")
    if not args.name:
        args.name = args.target or "victim"
    return args


if __name__ == "__main__":
    run(parse_args())
