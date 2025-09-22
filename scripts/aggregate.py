# scripts/aggregate.py
import json, sys, pathlib, csv, re

SEV_BUCKETS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
RISK_W = {"CRITICAL":5, "HIGH":3, "MEDIUM":1, "LOW":0.5, "UNKNOWN":0}

CVE_RX = re.compile(r"(CVE-\d{4}-\d+)", re.IGNORECASE)

def read_json(path: pathlib.Path):
    try:
        text = path.read_text(encoding="utf-8").strip()
        if not text or not text.startswith(("{","[")):
            return None
        return json.loads(text)
    except Exception:
        return None

def sev_norm_trivy(v):
    # Trivy uses CRITICAL/HIGH/MEDIUM/LOW; keep UNKNOWN if absent
    s = (v.get("Severity") or "UNKNOWN").upper()
    return s if s in SEV_BUCKETS else "UNKNOWN"

def extract_cve(text: str):
    if not text:
        return None
    m = CVE_RX.search(text)
    return m.group(1).upper() if m else None

def clair_iter_items(obj):
    """
    Yield dicts: {"id": <CVE or best id>, "severity": <normalized>} from Clair.
    Skip Negligible entirely.
    Handles both shapes seen from `clairctl report --out json`.
    """
    # Common shape: top-level key "vulnerabilities" is a dict
    vulns = None
    if isinstance(obj, dict) and "vulnerabilities" in obj and isinstance(obj["vulnerabilities"], dict):
        vulns = obj["vulnerabilities"]
    elif isinstance(obj, dict):
        # Sometimes the whole object is the map (numeric keys) — heuristic:
        # if values look like vuln objects with fields like "name" or "normalized_severity"
        sample = next(iter(obj.values())) if obj else None
        if isinstance(sample, dict) and ("name" in sample or "normalized_severity" in sample or "severity" in sample):
            vulns = obj

    if not isinstance(vulns, dict):
        return  # nothing usable

    for key, v in vulns.items():
        norm = (v.get("normalized_severity") or v.get("severity") or "UNKNOWN").strip().title()
        # Skip Negligible entirely, as requested
        if norm.lower() == "negligible":
            continue
        sev = norm.upper()
        if sev not in SEV_BUCKETS:
            sev = "UNKNOWN"

        # Prefer a clean CVE id for agreement:
        vid = extract_cve(v.get("name")) or extract_cve(v.get("links")) or v.get("name") or key
        yield {"id": (vid or key).upper(), "severity": sev}

def trivy_iter_items(obj):
    """
    Yield dicts: {"id": <CVE>, "severity": <normalized>} from Trivy result.
    """
    results = obj.get("Results", []) if isinstance(obj, dict) else []
    for r in results:
        vulns = r.get("Vulnerabilities") or []
        for v in vulns:
            vid = (v.get("VulnerabilityID") or "").upper()
            if not vid:
                continue
            sev = sev_norm_trivy(v)
            yield {"id": vid, "severity": sev}

def severity_counts(items):
    c = {k:0 for k in SEV_BUCKETS}
    for it in items:
        c[it["severity"]] += 1
    return c

def risk_score(c):
    return (c["CRITICAL"]*RISK_W["CRITICAL"] +
            c["HIGH"]*RISK_W["HIGH"] +
            c["MEDIUM"]*RISK_W["MEDIUM"] +
            c["LOW"]*RISK_W["LOW"] +
            c["UNKNOWN"]*RISK_W["UNKNOWN"])

def detect_tool_from_path(p: pathlib.Path):
    parts = [s.lower() for s in p.parts]
    if "trivy" in parts:
        return "trivy"
    if "clair" in parts:
        return "clair"
    # fallback: inspect JSON
    obj = read_json(p)
    if isinstance(obj, dict) and "Results" in obj:
        return "trivy"
    return "clair"

def load_items(p: pathlib.Path):
    obj = read_json(p)
    if obj is None:
        return None, []

    tool = detect_tool_from_path(p)
    if tool == "trivy":
        items = list(trivy_iter_items(obj))
    else:
        items = list(clair_iter_items(obj))
    return tool, items

def main(in_dir: str, out_dir: str):
    in_path = pathlib.Path(in_dir)
    out_path = pathlib.Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    metrics_rows = []
    agree_map = {}   # image -> {"trivy": set(ids), "clair": set(ids)}

    bad = []

    for p in sorted(in_path.rglob("*.json")):
        tool, items = load_items(p)
        if tool is None:
            bad.append(str(p))
            continue

        image = p.stem  # already normalized by your scripts
        # severity summary
        sc = severity_counts(items)
        rs = risk_score(sc)

        metrics_rows.append({
            "image": image,
            "tool": tool,
            **sc,
            "total": sum(sc.values()),
            "risk": rs,
        })

        # build agreement sets (skip Negligible already applied for Clair)
        agree = agree_map.setdefault(image, {"trivy": set(), "clair": set()})
        ids = {it["id"] for it in items if it.get("id")}
        agree[tool].update(ids)

    # Write metrics.csv
    metrics_csv = out_path / "metrics.csv"
    with metrics_csv.open("w", newline="", encoding="utf-8") as f:
        fieldnames = ["image","tool","CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN","total","risk"]
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in metrics_rows:
            w.writerow(row)

    # Compute + write agreement.csv
    agree_csv = out_path / "agreement.csv"
    with agree_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=[
            "image","trivy_count","clair_count","both","only_trivy","only_clair",
            "union","jaccard"
        ])
        w.writeheader()
        for image, m in sorted(agree_map.items()):
            A = m.get("trivy", set())
            B = m.get("clair", set())
            inter = A & B
            union = A | B
            row = {
                "image": image,
                "trivy_count": len(A),
                "clair_count": len(B),
                "both": len(inter),
                "only_trivy": len(A - B),
                "only_clair": len(B - A),
                "union": len(union),
                "jaccard": round((len(inter) / len(union)) if union else 1.0, 3),
            }
            w.writerow(row)

    # Optional: show any files we had to skip
    if bad:
        print("Skipped invalid/empty JSON files:")
        for b in bad:
            print("  -", b)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 scripts/aggregate.py <reports_dir> <out_dir>")
        sys.exit(2)
    main(sys.argv[1], sys.argv[2])
