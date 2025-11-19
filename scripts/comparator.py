#!/usr/bin/env python3
# comparator.py  —  CVE-centric diffs + daily summaries
#
# Parses raw reports JSON under reports/{trivy,clair}/<DD-MM-YYYY>/*.json,
# builds per-day CVE sets, compares consecutive dates, prints/exports stats
# and writes a line chart of total CVEs per day per tool.

import re
import csv
import sys
import json
import pathlib
import datetime
from collections import defaultdict

import pandas as pd
import matplotlib.pyplot as plt

BASE_REPORTS = pathlib.Path("reports")
OUT_DIR = pathlib.Path("out")
OUT_DIR.mkdir(parents=True, exist_ok=True)

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

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

# ---------- CVE extraction from report JSON ----------

def extract_cves_trivy(js):
    """
    Trivy JSON (image mode):
      {
        "Results": [
            {
              "Vulnerabilities": [
                 {"VulnerabilityID": "CVE-2023-XXXX", ...}, ...
              ],
            }, ...
        ],
      }
    """
    out = set()
    if not isinstance(js, dict):
        return out
    results = js.get("Results") or js.get("results") or []
    for r in results:
        vulns = (r or {}).get("Vulnerabilities") or (r or {}).get("vulnerabilities") or []
        for v in vulns:
            if isinstance(v, dict):
                vid = v.get("VulnerabilityID") or (v.get("vulnerability") or {}).get("id")
                if isinstance(vid, str) and CVE_RE.fullmatch(vid.upper()):
                    out.add(vid.upper())
            elif isinstance(v, str):
                for m in CVE_RE.findall(v):
                    out.add(m.upper())
    return out

def extract_cves_clair(js):
    """
    Clair 'clairctl report --out json' varies by version.
    We try common shapes, then fall back to a deep scan.
    """
    out = set()
    if not isinstance(js, dict):
        return out

    # Common top-level array/dict
    vulns = js.get("vulnerabilities") or js.get("Vulnerabilities") or []
    for v in vulns:
        if isinstance(v, dict):
            vid = v.get("id") or v.get("ID")
            if isinstance(vid, str) and CVE_RE.fullmatch(vid.upper()):
                out.add(vid.upper())
        elif isinstance(v, str):
            for m in CVE_RE.findall(v):
                out.add(m.upper())

    # Some Clair outputs nest findings under "packages"/"components"/"features"
    # Deep scan dictionaries/lists and scrape any CVE-like strings safely.
    stack = [js]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            for val in cur.values():
                if isinstance(val, (dict, list)):
                    stack.append(val)
                elif isinstance(val, str):
                    for m in CVE_RE.findall(val):
                        out.add(m.upper())
        elif isinstance(cur, list):
            for item in cur:
                if isinstance(item, (dict, list)):
                    stack.append(item)
                elif isinstance(item, str):
                    for m in CVE_RE.findall(item):
                        out.add(m.upper())

    return out

def extract_cves_generic(js):
    try:
        s = json.dumps(js, ensure_ascii=False)
    except Exception:
        s = str(js)
    return set(m.upper() for m in CVE_RE.findall(s))

def extract_cves(tool: str, js):
    tool_l = tool.lower()
    if tool_l == "trivy":
        s = extract_cves_trivy(js)
        return s or extract_cves_generic(js)
    if tool_l == "clair":
        s = extract_cves_clair(js)
        return s or extract_cves_generic(js)
    return extract_cves_generic(js)

# ---------- Build per-day -> tool -> image -> set(CVEs) ----------

def image_from_filename(path: pathlib.Path):
    # reports/<tool>/<date>/<SAFE>.json  ; we use the stem as the image key
    return path.stem

def build_day_index(date_str: str):
    """
    returns dict: tool -> image -> set(CVE)
    """
    day_index = defaultdict(lambda: defaultdict(set))
    for tool in ("trivy", "clair"):
        day_dir = BASE_REPORTS / tool / date_str
        if not day_dir.exists():
            continue
        for jpath in sorted(day_dir.glob("*.json")):
            js = load_json(jpath)
            if js is None:
                continue
            cves = extract_cves(tool, js)
            image_key = image_from_filename(jpath)
            day_index[tool][image_key] |= cves
    return day_index

# ---------- Diffs & summaries ----------

def compare_day_pair(d1: str, d2: str, idx1, idx2):
    """
    idx1/idx2: tool->image->set(CVE)
    Returns:
      - console lines (unused placeholder for future),
      - row list for cve_pairwise_diffs.csv,
      - pair summary dict.
    """
    tools = sorted(set(idx1.keys()) | set(idx2.keys()))
    lines = []
    pair_diffs_rows = []
    tool_new_total = 0
    tool_removed_total = 0
    per_tool_totals = {t: {"new":0, "removed":0} for t in tools}

    for tool in tools:
        images = sorted(set(idx1.get(tool, {}).keys()) | set(idx2.get(tool, {}).keys()))
        t_new = 0
        t_removed = 0
        for img in images:
            old = idx1.get(tool, {}).get(img, set())
            new = idx2.get(tool, {}).get(img, set())
            add = new - old
            rem = old - new
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
            t_new += len(add)
            t_removed += len(rem)
        per_tool_totals[tool]["new"] += t_new
        per_tool_totals[tool]["removed"] += t_removed
        tool_new_total += t_new
        tool_removed_total += t_removed

    # Pair-level union/intersection on the target (newer) day:
    trivy_new = idx2.get("trivy", {})
    clair_new = idx2.get("clair", {})
    trivy_set = set().union(*trivy_new.values()) if trivy_new else set()
    clair_set = set().union(*clair_new.values()) if clair_new else set()
    union = trivy_set | clair_set
    inter = trivy_set & clair_set
    only_trivy = trivy_set - clair_set
    only_clair = clair_set - trivy_set

    return lines, pair_diffs_rows, {
        "from_date": d1,
        "to_date": d2,
        "union": len(union),
        "intersection": len(inter),
        "only_trivy": len(only_trivy),
        "only_clair": len(only_clair),
        "tool_totals": per_tool_totals,
        "total_new": tool_new_total,
        "total_removed": tool_removed_total,
    }

def collect_daily_totals(date_str: str, idx):
    rows = []
    for tool, images in idx.items():
        s = set()
        for cves in images.values():
            s |= cves
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
    pair_rows = []   # for cve_pairwise_diffs.csv
    uni_int_rows = []# for cve_pairwise_union_intersection.csv
    daily_change_rows = []  # <-- NEW: per-pair, per-tool totals
    grand_new = 0
    grand_removed = 0

    tool_dates = find_tool_dates()   # e.g. {'trivy':['01-10-2025',...], 'clair':[...]}

    # union of all dates that appear in any tool folder
    all_dates = set()
    for dl in tool_dates.values():
        all_dates.update(dl)
    dates = sorted(all_dates, key=lambda s: parse_date_folder(s) or datetime.date(1970,1,1))
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
            for img, cves in images.items():
                # cves is a set in your current code
                for cve in cves:
                    key = (tool, cve)
                    if key not in first_seen:
                        first_seen[key] = parse_date_folder(d)

    # Print header
    print("="*78)
    print("CVE DIFFS (parsed directly from reports/<tool>/<DD-MM-YYYY>/*.json)")
    print("-"*78)
    print()

    # Compare consecutive pairs
    pair_rows = []   # for cve_pairwise_diffs.csv
    uni_int_rows = []# for cve_pairwise_union_intersection.csv
    grand_new = 0
    grand_removed = 0

    for i in range(len(dates)-1):
        d1, d2 = dates[i], dates[i+1]
        print(f"{d1}  →  {d2}")
        print("-"*78)

        _, pair_diffs, pair_summary = compare_day_pair(d1, d2, day_indexes[d1], day_indexes[d2])
        for tool in ("trivy","clair"):
            tnew = pair_summary["tool_totals"].get(tool,{}).get("new",0)
            trem = pair_summary["tool_totals"].get(tool,{}).get("removed",0)
            print(f"[{tool}]  new: {tnew:4d}   removed: {trem:4d}")
            # NEW: record per-pair totals for CSV
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

    write_csv(OUT_DIR/"cve_first_seen.csv",
              first_rows,
              fieldnames=["cve","first_trivy","first_clair","leading_tool","day_diff"])

    # SUMMARY
    print("="*78)
    print("SUMMARY across all consecutive dates")
    print("-"*78)
    print(f"Total new CVEs     : {grand_new}")
    print(f"Total removed CVEs : {grand_removed}\n")
    if dates:
        last_idx = day_indexes[dates[-1]]
        tool_totals_last = {t: len(set().union(*imgs.values())) if imgs else 0 for t, imgs in last_idx.items()}
        print("Totals in latest day:")
        for t in ("trivy","clair"):
            if t in tool_totals_last:
                print(f"  • {t}: {tool_totals_last[t]} unique CVEs")
        print("="*78)

    # ----- Write CSVs -----
    write_csv(OUT_DIR/"cve_daily_totals.csv",
              daily_total_rows,
              fieldnames=["date","tool","total_cves"])

    write_csv(OUT_DIR/"cve_pairwise_diffs.csv",
              pair_rows,
              fieldnames=[
                  "from_date","to_date","tool","image",
                  "new_count","removed_count","sample_new","sample_removed"
              ])

    write_csv(OUT_DIR/"cve_pairwise_union_intersection.csv",
              uni_int_rows,
              fieldnames=["from_date","to_date","union","intersection","only_trivy","only_clair"])

    write_csv(OUT_DIR/"cve_daily_changes.csv",
              daily_change_rows,
              fieldnames=["from_date","to_date","tool","new_total","removed_total"])

    # ----- Plot: total CVEs per day per tool -----
    try:
        df = pd.read_csv(OUT_DIR / "cve_daily_totals.csv")
        # ensure numeric
        df["total_cves"] = pd.to_numeric(df["total_cves"], errors="coerce").fillna(0)

        # pivot to date x tool
        pivot = df.pivot(index="date", columns="tool", values="total_cves")

        # reindex by sorted dates to ensure order on x-axis
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

    # ----- Plot: daily new/removed CVEs per tool -----
    try:
        df_changes = pd.read_csv(OUT_DIR / "cve_daily_changes.csv")
        # Convert to a single label "window" for x-axis (e.g., "10-10→11-10")
        df_changes["window"] = df_changes["from_date"] + "→" + df_changes["to_date"]

        # Sort windows by from_date
        df_changes["from_dt"] = pd.to_datetime(df_changes["from_date"], format="%d-%m-%Y")
        df_changes = df_changes.sort_values(["from_dt", "tool"])

        fig, ax = plt.subplots(figsize=(9, 5))

        for tool in ("trivy", "clair"):
            dft = df_changes[df_changes["tool"] == tool]
            if dft.empty:
                continue
            ax.plot(
                dft["window"],
                dft["new_total"],
                marker="o",
                label=f"{tool} new"
            )
            ax.plot(
                dft["window"],
                dft["removed_total"],
                marker="x",
                linestyle="--",
                label=f"{tool} removed"
            )

        ax.set_title("Daily CVE additions and removals per tool")
        ax.set_xlabel("Date window")
        ax.set_ylabel("Count of CVEs")
        plt.xticks(rotation=45, ha="right")
        ax.legend()
        plt.tight_layout()

        png2 = OUT_DIR / "fig_cve_daily_changes.png"
        svg2 = OUT_DIR / "fig_cve_daily_changes.svg"
        plt.savefig(png2, dpi=200, bbox_inches="tight")
        plt.savefig(svg2, bbox_inches="tight")
        plt.close()

        print("Wrote daily CVE changes plot:")
        print(" -", png2)
        print(" -", svg2)
    except Exception as e:
        print("⚠️ Could not generate daily CVE changes plot:", e)

    # ----- Plot: which tool sees CVEs first? -----
    try:
        df_first = pd.read_csv(OUT_DIR / "cve_first_seen.csv")

        # Ensure day_diff is numeric
        df_first["day_diff"] = pd.to_numeric(df_first["day_diff"], errors="coerce").fillna(0)

        # 1) Bar chart: count of CVEs by leading_tool
        counts = df_first["leading_tool"].value_counts()

        fig, ax = plt.subplots(figsize=(5, 4))
        ax.bar(counts.index, counts.values)
        ax.set_title("Leading tool for shared CVEs")
        ax.set_xlabel("Leading tool")
        ax.set_ylabel("Number of CVEs")
        plt.tight_layout()

        png_lead = OUT_DIR / "fig_cve_first_seen_leading_tool.png"
        svg_lead = OUT_DIR / "fig_cve_first_seen_leading_tool.svg"
        plt.savefig(png_lead, dpi=200, bbox_inches="tight")
        plt.savefig(svg_lead, bbox_inches="tight")
        plt.close()

        print("Wrote first-seen leading-tool plot:")
        print(" -", png_lead)
        print(" -", svg_lead)

        # 2) Histogram: distribution of day_diff (exclude ties if you want)
        df_non_tie = df_first[df_first["leading_tool"] != "tie"]

        if not df_non_tie.empty:
            fig, ax = plt.subplots(figsize=(6, 4))
            ax.hist(df_non_tie["day_diff"], bins=11, edgecolor="black")
            ax.set_title("Distribution of first-seen lag between tools")
            ax.set_xlabel("Trivy date − Clair date (days)")
            ax.set_ylabel("Number of CVEs")
            plt.tight_layout()

            png_diff = OUT_DIR / "fig_cve_first_seen_daydiff.png"
            svg_diff = OUT_DIR / "fig_cve_first_seen_daydiff.svg"
            plt.savefig(png_diff, dpi=200, bbox_inches="tight")
            plt.savefig(svg_diff, bbox_inches="tight")
            plt.close()

            print("Wrote first-seen day-diff plot:")
            print(" -", png_diff)
            print(" -", svg_diff)
        else:
            print("No non-tie CVEs to plot day_diff histogram.")

    except Exception as e:
        print("⚠️ Could not generate first-seen plots:", e)

if __name__ == "__main__":
    main()
