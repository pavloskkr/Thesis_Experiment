#!/usr/bin/env python3
import sys, csv, pathlib, datetime

def read_csv(path):
    rows = {}
    if not path.exists():
        return rows
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            key = row["image"] + "::" + row.get("tool", "")
            rows[key] = row
    return rows

def read_agreement(path):
    rows = {}
    if not path.exists():
        return rows
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            key = row["image"]
            rows[key] = row
    return rows

def compare_dicts(old, new, label):
    diffs = []
    all_keys = sorted(set(old) | set(new))
    for k in all_keys:
        if k not in old:
            diffs.append(f"{label} {k} added in new run")
        elif k not in new:
            diffs.append(f"{label} {k} missing in new run")
        else:
            for fld in old[k]:
                if fld not in ["image","tool"]:
                    if str(old[k][fld]) != str(new[k][fld]):
                        diffs.append(f"{label} {k} field {fld}: {old[k][fld]} → {new[k][fld]}")
    return diffs

def main(base_dir="out"):
    today = datetime.datetime.now().strftime("%d-%m-%Y")
    yesterday = (datetime.datetime.now() - datetime.timedelta(days=1)).strftime("%d-%m-%Y")

    today_dir = pathlib.Path(base_dir) / today
    yest_dir  = pathlib.Path(base_dir) / yesterday

    today_metrics = read_csv(today_dir/"metrics.csv")
    yest_metrics  = read_csv(yest_dir/"metrics.csv")

    today_agree = read_agreement(today_dir/"agreement.csv")
    yest_agree  = read_agreement(yest_dir/"agreement.csv")

    print(f"Comparing {yesterday} → {today}\n")

    diffs = []
    diffs += compare_dicts(yest_metrics, today_metrics, "METRIC")
    diffs += compare_dicts(yest_agree, today_agree, "AGREE")

    if not diffs:
        print("No differences found — runs are consistent.")
    else:
        for d in diffs:
            print(d)

if __name__ == "__main__":
    main()
