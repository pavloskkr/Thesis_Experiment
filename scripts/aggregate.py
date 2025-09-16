# scripts/aggregate.py
import json, sys, pathlib, csv
from statistics import mean

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
    # Clair v4 JSON shape: report.Vulnerabilities keyed by package; flatten minimally
    vulns = obj.get("vulnerabilities") or obj.get("Report") or {}
    # be defensive across versions; adapt if your actual JSON differs
    for k,v in (vulns.items() if isinstance(vulns, dict) else []):
        yield {"VulnerabilityID": v.get("Name") or k, "Severity": (v.get("Severity") or "UNKNOWN").upper()}

def load(path):
    data = json.loads(path.read_text())
    if "Results" in data:            # Trivy
        items = list(trivy_items(data))
        tool = "trivy"
    else:                            # Clair (best-effort)
        items = list(clair_items(data))
        tool = "clair"
    return tool, items

def main(in_dir, out_csv):
    rows=[]
    by_image_tool = {}
    for p in pathlib.Path(in_dir).rglob("*.json"):
        tool, items = load(p)
        img = p.stem
        sc = severity_counts(items)
        rs = risk_score(sc)
        rows.append({"image":img,"tool":tool,**sc,"risk":rs,"total":sum(sc.values())})
        by_image_tool.setdefault(img,{})[tool] = {i["VulnerabilityID"] for i in items}
    # compute Jaccard
    for img, m in by_image_tool.items():
        a, b = m.get("trivy", set()), m.get("clair", set())
        j = (len(a & b)/len(a | b)) if (a or b) else 1.0
        rows.append({"image":img,"tool":"agreement","CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"UNKNOWN":0,"risk":0,"total":len(a|b),"jaccard":round(j,3)})
    with open(out_csv,"w",newline="") as f:
        w = csv.DictWriter(f, fieldnames=["image","tool","CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN","total","risk","jaccard"])
        w.writeheader(); w.writerows(rows)

if __name__=="__main__":
    in_dir = sys.argv[1]; out_csv = sys.argv[2]
    pathlib.Path(out_csv).parent.mkdir(parents=True, exist_ok=True)
    main(in_dir, out_csv)
