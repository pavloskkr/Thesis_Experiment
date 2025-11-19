#!/usr/bin/env python3
# comparator.py  —  CVE-centric diffs + daily summaries
#
# Parses raw reports JSON under reports/{trivy,clair}/<DD-MM-YYYY>/*.json,
# builds per-day CVE+severity sets, compares consecutive dates, prints/exports
# stats and writes various CSVs and plots.

import csv
import sys
import json
import pathlib
import datetime
from collections import defaultdict

import pandas as pd
import matplotlib.pyplot as plt

from aggregate import load_items  # <-- reuse your canonical parser

BASE_REPORTS = pathlib.Path("reports")
OUT_DIR = pathlib.Path("out")
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Severity ranking for comparisons (same order as elsewhere)
SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def sev_rank(sev: str) -> int:
    if not isinstance(sev, str):
        return 0
    return SEV_ORDER.get(sev.upper(), 0)


# ---------- Helpers: safe JSON load, date parsing/sorting ----------

def load_json(path: pathlib.Path):
    try:
        with path.open(encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def parse_date_folder(name: str):
    # DD-MM-YYYY
    try:
        return datetime.datetime.strptime(name, "%d-%m-%Y").date()
    except Exception:
        return None


def find_tool_dates():
    # scan reports/<tool>/<DD-MM-YYYY>/
    found = defaultdict(list)  # tool -> [date_str,...]
    if not BASE_REPORTS.exists():
        return found
    for tool_dir in BASE_REPORTS.iterdir():
        if not tool_dir.is_dir():
            continue
        tool = tool_dir.name  # 'trivy' or 'clair'
        for d in tool_dir.iterdir():
            if d.is_dir() and parse_date_folder(d.name):
                found[tool].append(d.name)
    for tool in list(found.keys()):
        found[tool] = sorted(found[tool], key=lambda s: parse_date_folder(s))
    return found


# ---------- Build per-day -> tool -> image -> {"cves": set, "sev": {cve:severity}} ----------

def image_from_filename(path: pathlib.Path):
    # reports/<tool>/<date>/<SAFE>.json  ; we use the stem as the image key
    return path.stem


def build_day_index(date_str: str):
    """
    returns dict: tool -> image -> {"cves": set(CVE), "sev": {CVE: SEV}}
    """
    day_index = defaultdict(lambda: defaultdict(lambda: {"cves": set(), "sev": {}}))

    for tool_hint in ("trivy", "clair"):
        day_dir = BASE_REPORTS / tool_hint / date_str
        if not day_dir.exists():
            continue

        for jpath in sorted(day_dir.glob("*.json")):
            tool_detected, items = load_items(jpath)
            if tool_detected is None:
                continue

            image_key = image_from_filename(jpath)
            entry = day_index[tool_detected][image_key]

            for it in items:
                vid = it.get("id")
                sev = it.get("severity", "UNKNOWN")
                if not vid:
                    continue
                vid = vid.upper()
                sev = (sev or "UNKNOWN")
                if isinstance(sev, str):
                    sev = sev.upper()
                else:
                    sev = "UNKNOWN"

                entry["cves"].add(vid)
                entry["sev"][vid] = sev

    return day_index


# ---------- Diffs & summaries ----------

def compare_day_pair(d1: str, d2: str, idx1, idx2):
    """
    idx1/idx2: tool->image->{"cves": set(CVE), "sev": {CVE:SEV}}
    Returns:
      - console lines (unused placeholder for future),
      - row list for cve_pairwise_diffs.csv,
      - row list for cve_severity_changes.csv,
      - pair summary dict.
    """
    tools = sorted(set(idx1.keys()) | set(idx2.keys()))
    lines = []
    pair_diffs_rows = []
    severity_change_rows = []

    tool_new_total = 0
    tool_removed_total = 0
    per_tool_totals = {t: {"new": 0, "removed": 0} for t in tools}
    per_tool_sev = {t: {"up": 0, "down": 0} for t in tools}

    for tool in tools:
        images = sorted(set(idx1.get(tool, {}).keys()) | set(idx2.get(tool, {}).keys()))
        t_new = 0
        t_removed = 0

        for img in images:
            old_entry = idx1.get(tool, {}).get(img, {"cves": set(), "sev": {}})
            new_entry = idx2.get(tool, {}).get(img, {"cves": set(), "sev": {}})

            old = old_entry["cves"]
            new = new_entry["cves"]

            add = new - old
            rem = old - new
            common = old & new

            # per-image add/remove counts
            if add or rem:
                pair_diffs_rows.append({
                    "from_date": d1,
                    "to_date": d2,
                    "tool": tool,
                    "image": img,
                    "new_count": len(add),
                    "removed_count": len(rem),
                    "sample_new": ",".join(sorted(list(add))[:5]),
                    "sample_removed": ",".join(sorted(list(rem))[:5]),
                })

            # severity changes on common CVEs
            for cve in common:
                s1 = old_entry["sev"].get(cve, "UNKNOWN")
                s2 = new_entry["sev"].get(cve, "UNKNOWN")
                r1 = sev_rank(s1)
                r2 = sev_rank(s2)
                if r1 == r2:
                    continue

                if r2 > r1:
                    direction = "up"
                    per_tool_sev[tool]["up"] += 1
                else:
                    direction = "down"
                    per_tool_sev[tool]["down"] += 1

                severity_change_rows.append({
                    "from_date": d1,
                    "to_date": d2,
                    "tool": tool,
                    "image": img,
                    "cve": cve,
                    "old_severity": s1,
                    "new_severity": s2,
                    "direction": direction,
                    "delta_rank": r2 - r1,
                })

            t_new += len(add)
            t_removed += len(rem)

        per_tool_totals[tool]["new"] += t_new
        per_tool_totals[tool]["removed"] += t_removed
        tool_new_total += t_new
        tool_removed_total += t_removed

    # Pair-level union/intersection on the target (newer) day:
    trivy_new = idx2.get("trivy", {})
    clair_new = idx2.get("clair", {})

    trivy_set = set()
    for entry in trivy_new.values():
        trivy_set |= entry["cves"]

    clair_set = set()
    for entry in clair_new.values():
        clair_set |= entry["cves"]

    union = trivy_set | clair_set
    inter = trivy_set & clair_set
    only_trivy = trivy_set - clair_set
    only_clair = clair_set - trivy_set

    return lines, pair_diffs_rows, severity_change_rows, {
        "from_date": d1,
        "to_date": d2,
        "union": len(union),
        "intersection": len(inter),
        "only_trivy": len(only_trivy),
        "only_clair": len(only_clair),
        "tool_totals": per_tool_totals,
        "tool_severity": per_tool_sev,
        "total_new": tool_new_total,
        "total_removed": tool_removed_total,
    }


def collect_daily_totals(date_str: str, idx):
    rows = []
    for tool, images in idx.items():
        s = set()
        for entry in images.values():
            s |= entry["cves"]
        rows.append({"date": date_str, "tool": tool, "total_cves": len(s)})
    return rows


# ---------- CSV writers ----------

def write_csv(path: pathlib.Path, rows, fieldnames):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fieldnames})


# ---------- main ----------

def main():
    pair_rows = []      # for cve_pairwise_diffs.csv
    sev_change_all = [] # for cve_severity_changes.csv
    uni_int_rows = []   # for cve_pairwise_union_intersection.csv
    daily_change_rows = []  # per-pair, per-tool totals
    grand_new = 0
    grand_removed = 0

    tool_dates = find_tool_dates()   # e.g. {'trivy':['01-10-2025',...], 'clair':[...]}

    # union of all dates that appear in any tool folder
    all_dates = set()
    for dl in tool_dates.values():
        all_dates.update(dl)
    dates = sorted(all_dates, key=lambda s: parse_date_folder(s) or datetime.date(1970, 1, 1))
    if len(dates) < 1:
        print("No report dates found under reports/*/<DD-MM-YYYY>/")
        sys.exit(0)

    # Build per-day index & gather daily totals
    day_indexes = {}
    daily_total_rows = []
    for d in dates:
        idx = build_day_index(d)
        day_indexes[d] = idx
        daily_total_rows += collect_daily_totals(d, idx)

    # Track first seen date per (tool, CVE)
    first_seen = {}  # (tool, cve) -> date
    for d in dates:
        idx = day_indexes[d]
        for tool, images in idx.items():
            for img, entry in images.items():
                for cve in entry["cves"]:
                    key = (tool, cve)
                    if key not in first_seen:
                        first_seen[key] = parse_date_folder(d)

    # Print header
    print("=" * 78)
    print("CVE DIFFS (parsed directly from reports/<tool>/<DD-MM-YYYY>/*.json)")
    print("-" * 78)
    print()

    # Compare consecutive pairs
    for i in range(len(dates) - 1):
        d1, d2 = dates[i], dates[i + 1]
        print(f"{d1}  →  {d2}")
        print("-" * 78)

        _, pair_diffs, sev_changes, pair_summary = compare_day_pair(
            d1, d2, day_indexes[d1], day_indexes[d2]
        )

        for tool in ("trivy", "clair"):
            tnew = pair_summary["tool_totals"].get(tool, {}).get("new", 0)
            trem = pair_summary["tool_totals"].get(tool, {}).get("removed", 0)
            print(f"[{tool}]  new: {tnew:4d}   removed: {trem:4d}")
            daily_change_rows.append({
                "from_date": d1,
                "to_date": d2,
                "tool": tool,
                "new_total": tnew,
                "removed_total": trem,
            })
        print(f"TOTAL   new: {pair_summary['total_new']:4d}   removed: {pair_summary['total_removed']:4d}")
        print()

        pair_rows += pair_diffs
        sev_change_all += sev_changes
        uni_int_rows.append({
            "from_date": d1,
            "to_date": d2,
            "union": pair_summary["union"],
            "intersection": pair_summary["intersection"],
            "only_trivy": pair_summary["only_trivy"],
            "only_clair": pair_summary["only_clair"],
        })
        grand_new += pair_summary["total_new"]
        grand_removed += pair_summary["total_removed"]

    # ----- First-seen analysis: which tool leads for shared CVEs? -----
    first_rows = []
    cve_to_first = defaultdict(dict)  # cve -> {tool: date}

    for (tool, cve), dt_first in first_seen.items():
        cve_to_first[cve][tool] = dt_first

    for cve, m in cve_to_first.items():
        if "trivy" not in m or "clair" not in m:
            continue  # appears in only one tool; skip
        dt_t = m["trivy"]
        dt_c = m["clair"]
        diff = (dt_t - dt_c).days
        if diff == 0:
            leading = "tie"
        elif diff < 0:
            leading = "trivy"  # Trivy saw it earlier
        else:
            leading = "clair"  # Clair saw it earlier

        first_rows.append({
            "cve": cve,
            "first_trivy": dt_t.strftime("%d-%m-%Y"),
            "first_clair": dt_c.strftime("%d-%m-%Y"),
            "leading_tool": leading,
            "day_diff": diff,
        })

    write_csv(
        OUT_DIR / "cve_first_seen.csv",
        first_rows,
        fieldnames=["cve", "first_trivy", "first_clair", "leading_tool", "day_diff"],
    )

    # SUMMARY
    print("=" * 78)
    print("SUMMARY across all consecutive dates")
    print("-" * 78)
    print(f"Total new CVEs     : {grand_new}")
    print(f"Total removed CVEs : {grand_removed}\n")
    if dates:
        last_idx = day_indexes[dates[-1]]
        tool_totals_last = {
            t: (len(set().union(*(e["cves"] for e in imgs.values()))) if imgs else 0)
            for t, imgs in last_idx.items()
        }
        print("Totals in latest day:")
        for t in ("trivy", "clair"):
            if t in tool_totals_last:
                print(f"  • {t}: {tool_totals_last[t]} unique CVEs")
        print("=" * 78)

    # ----- Write CSVs -----
    write_csv(
        OUT_DIR / "cve_daily_totals.csv",
        daily_total_rows,
        fieldnames=["date", "tool", "total_cves"],
    )

    write_csv(
        OUT_DIR / "cve_pairwise_diffs.csv",
        pair_rows,
        fieldnames=[
            "from_date", "to_date", "tool", "image",
            "new_count", "removed_count", "sample_new", "sample_removed",
        ],
    )

    write_csv(
        OUT_DIR / "cve_pairwise_union_intersection.csv",
        uni_int_rows,
        fieldnames=["from_date", "to_date", "union", "intersection", "only_trivy", "only_clair"],
    )

    write_csv(
        OUT_DIR / "cve_daily_changes.csv",
        daily_change_rows,
        fieldnames=["from_date", "to_date", "tool", "new_total", "removed_total"],
    )

    write_csv(
        OUT_DIR / "cve_severity_changes.csv",
        sev_change_all,
        fieldnames=[
            "from_date", "to_date", "tool", "image",
            "cve", "old_severity", "new_severity", "direction", "delta_rank",
        ],
    )

    # ----- Plot: total CVEs per day per tool -----
    try:
        df = pd.read_csv(OUT_DIR / "cve_daily_totals.csv")
        df["total_cves"] = pd.to_numeric(df["total_cves"], errors="coerce").fillna(0)
        pivot = df.pivot(index="date", columns="tool", values="total_cves")
        pivot = pivot.reindex(dates)

        ax = pivot.plot(marker="o", figsize=(8, 5))
        ax.set_title("Total unique CVEs per day by tool")
        ax.set_xlabel("Date")
        ax.set_ylabel("Unique CVEs")

        plt.tight_layout()
        png = OUT_DIR / "fig_cve_daily_totals.png"
        svg = OUT_DIR / "fig_cve_daily_totals.svg"
        plt.savefig(png, dpi=200, bbox_inches="tight")
        plt.savefig(svg, bbox_inches="tight")
        plt.close()

        print("Wrote daily CVE totals plot:")
        print(" -", png)
        print(" -", svg)
    except Exception as e:
        print("⚠️ Could not generate daily CVE totals plot:", e)

    # ----- Plot: which tool sees CVEs first? -----
    try:
        df_first = pd.read_csv(OUT_DIR / "cve_first_seen.csv")
        df_first["day_diff"] = pd.to_numeric(df_first["day_diff"], errors="coerce").fillna(0)

        # --- Chart 1: full-scale (including ties) ---
        counts_full = df_first["leading_tool"].value_counts()

        fig, ax = plt.subplots(figsize=(6, 4))
        ax.bar(counts_full.index, counts_full.values)
        ax.set_title("Leading tool for shared CVEs (full scale)")
        ax.set_xlabel("Leading tool")
        ax.set_ylabel("Count")
        plt.tight_layout()

        png1 = OUT_DIR / "fig_cve_first_seen_leading_tool_full.png"
        plt.savefig(png1, dpi=200, bbox_inches="tight")
        plt.close()

        # --- Chart 2: zoom only non-ties ---
        df_non_tie = df_first[df_first["leading_tool"] != "tie"]
        counts_zoom = df_non_tie["leading_tool"].value_counts()

        fig, ax = plt.subplots(figsize=(6, 4))
        ax.bar(counts_zoom.index, counts_zoom.values, color=["#4C72B0", "#55A868"])
        ax.set_title("Leading tool for shared CVEs (non-tied only)")
        ax.set_xlabel("Leading tool")
        ax.set_ylabel("Count")
        plt.tight_layout()

        png2 = OUT_DIR / "fig_cve_first_seen_leading_tool_zoom.png"
        plt.savefig(png2, dpi=200, bbox_inches="tight")
        plt.close()

        print("Wrote first-seen plots:")
        print(" -", png1)
        print(" -", png2)

    except Exception as e:
        print("⚠️ Could not generate first-seen plots:", e)

if __name__ == "__main__":
    main()
