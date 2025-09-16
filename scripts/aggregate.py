# scripts/aggregate.py
import json, sys, pathlib, csv

def severity_counts(findings):
    sev = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"UNKNOWN":0}
    for f in findings:
        sev[f.get("Severity","UNKNOWN").upper()] = sev.get(f.get("Severity","UNKNOWN").upper(),0)+1
    return sev

def risk_score(sc): return 5*sc["CRITICAL"] + 3*sc["HIGH"] + 1*sc["MEDIUM"] + 0.5*sc["LOW"]

def trivy_items(obj):
    for r in obj.get("Results", []):
        for v in r.get("Vulnerabilities",[]) or []:
            yield {"VulnerabilityID":v.get("VulnerabilityID"), "Severity":v.get("Severity")}

def clair_items(obj):
    # Handle both top-level and nested "Report" shapes
    def _collect(vuln_map, out):
        if isinstance(vuln_map, dict):
            for vid, v in vuln_map.items():
                out.append({
                    "VulnerabilityID": v.get("Name") or v.get("name") or vid,
                    "Severity": (v.get("Severity") or v.get("severity") or v.get("NormalizedSeverity") or "UNKNOWN")
                })
    items=[]
    if isinstance(obj, dict):
        _collect(obj.get("vulnerabilities"), items)
        rep = obj.get("Report")
        if isinstance(rep, dict):
            _collect(rep.get("vulnerabilities"), items)
    return items

def load_json(path: pathlib.Path):
    s = path.read_text(encoding="utf-8", errors="ignore").strip()
    if not s:
        raise ValueError("empty file")
    try:
        return json.loads(s)
    except json.JSONDecodeError as e:
        raise ValueError(f"invalid JSON: {e}") from e

def detect_tool(obj):
    return "trivy" if isinstance(obj, dict) and "Results" in obj else "clair"

def load(path):
    obj = load_json(path)
    tool = detect_tool(obj)
    items = list(trivy_items(obj)) if tool == "trivy" else list(clair_items(obj))
    return tool, items

def main(in_dir, out_csv):
    rows=[]
    by_image_tool = {}
    skipped = []

    for p in sorted(pathlib.Path(in_dir).rglob("*.json")):
        try:
            tool, items = load(p)
        except Exception as e:
            skipped.append((str(p), str(e)))
            continue
        img = p.stem
        sc = severity_counts(items)
        rs = risk_score(sc)
        rows.append({"image":img,"tool":tool,**sc,"risk":rs,"total":sum(sc.values())})
        by_image_tool.setdefault(img,{})[tool] = {i["VulnerabilityID"] for i in items}

    # Jaccard agreement
    for img, m in by_image_tool.items():
        a, b = m.get("trivy", set()), m.get("clair", set())
        j = (len(a & b)/len(a | b)) if (a or b) else 1.0
        rows.append({"image":img,"tool":"agreement","CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"UNKNOWN":0,"risk":0,"total":len(a|b),"jaccard":round(j,3)})

    pathlib.Path(out_csv).parent.mkdir(parents=True, exist_ok=True)
    with open(out_csv,"w",newline="",encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["image","tool","CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN","total","risk","jaccard"])
        w.writeheader(); w.writerows(rows)

    if skipped:
        sys.stderr.write("Skipped files (not fatal):\n")
        for path, reason in skipped:
            sys.stderr.write(f"  - {path}: {reason}\n")

if __name__=="__main__":
    in_dir = sys.argv[1]; out_csv = sys.argv[2]
    main(in_dir, out_csv)
