#!/usr/bin/env python3
# comparator.py  —  CVE-centric diffs + daily summaries
#
# Drop-in: put this file in ./scripts/comparator.py and run:
#   python3 ./scripts/comparator.py
#
# Parses raw reports JSON under reports/{trivy,clair}/<DD-MM-YYYY>/*.json,
# builds per-day CVE sets, compares consecutive dates, prints/exports stats.

import re
import csv
import sys
import json
import pathlib
import datetime
from collections import defaultdict

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

    # Common top-level array
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


if __name__ == "__main__":
    main()
