#!/usr/bin/env python3
import csv
import datetime as dt
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

# Reuse the parsing logic from aggregate.py
from aggregate import load_items, SEV_BUCKETS, RISK_W

# -------------------------------------------------------------------
# Config
# -------------------------------------------------------------------
REPORTS_DIR = Path("reports")
OUT_ROOT = Path("out")
OUT_DIR = OUT_ROOT / "summary_unique"
OUT_DIR.mkdir(parents=True, exist_ok=True)

TOOLS = ["trivy", "clair"]

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------

def parse_date_folder(name: str):
    """Parse 'DD-MM-YYYY' into a date object, or None."""
    try:
        return dt.datetime.strptime(name, "%d-%m-%Y").date()
    except ValueError:
        return None


def find_dates():
    """Return sorted unique list of date strings ('DD-MM-YYYY') present under reports/<tool>/."""
    all_dates = set()
    if not REPORTS_DIR.exists():
        return []

    for tool in TOOLS:
        tdir = REPORTS_DIR / tool
        if not tdir.exists():
            continue
        for d in tdir.iterdir():
            if not d.is_dir():
                continue
            if parse_date_folder(d.name):
                all_dates.add(d.name)

    return sorted(all_dates, key=lambda s: parse_date_folder(s) or dt.date(1970, 1, 1))


def sev_rank(sev: str) -> int:
    """Order severities from most to least severe for conflict resolution."""
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
    return order.get(sev, 0)


# -------------------------------------------------------------------
# 1. Walk reports and build indexes
# -------------------------------------------------------------------

def main():
    dates = find_dates()
    if not dates:
        raise SystemExit("❌ No report dates found under reports/<tool>/<DD-MM-YYYY>/")

    # (a) overall unique CVEs per tool+image across all days
    #     (tool, image) -> {cve_id: severity}
    overall_image_cves = defaultdict(dict)

    # (b) daily union CVEs per date+tool
    #     (date_str, tool) -> {cve_id: severity}
    daily_tool_cves = defaultdict(dict)

    skipped = []

    for d_str in dates:
        for tool in TOOLS:
            day_dir = REPORTS_DIR / tool / d_str
            if not day_dir.exists():
                continue

            for jp in sorted(day_dir.glob("*.json")):
                tool_detected, items = load_items(jp)
                if tool_detected is None:
                    skipped.append(str(jp))
                    continue

                image = jp.stem

                # items are [{"id": ..., "severity": ...}, ...]
                for it in items:
                    vid = it.get("id")
                    sev = it.get("severity", "UNKNOWN")
                    if not vid:
                        continue

                    # (a) overall per tool+image
                    key_img = (tool_detected, image)
                    prev_sev = overall_image_cves[key_img].get(vid)
                    if prev_sev is None or sev_rank(sev) > sev_rank(prev_sev):
                        overall_image_cves[key_img][vid] = sev

                    # (b) daily union per date+tool
                    key_daytool = (d_str, tool_detected)
                    prev_sev2 = daily_tool_cves[key_daytool].get(vid)
                    if prev_sev2 is None or sev_rank(sev) > sev_rank(prev_sev2):
                        daily_tool_cves[key_daytool][vid] = sev

    # ----------------------------------------------------------------
    # 2. summary_unique_per_image.csv
    # ----------------------------------------------------------------
    rows_per_image = []
    for (tool, image), cve_map in sorted(overall_image_cves.items()):
        counts = {s: 0 for s in SEV_BUCKETS}
        for sev in cve_map.values():
            bucket = sev if sev in SEV_BUCKETS else "UNKNOWN"
            counts[bucket] += 1
        total_cves = sum(counts.values())
        risk = (
            counts["CRITICAL"] * RISK_W["CRITICAL"]
            + counts["HIGH"] * RISK_W["HIGH"]
            + counts["MEDIUM"] * RISK_W["MEDIUM"]
            + counts["LOW"] * RISK_W["LOW"]
            + counts["UNKNOWN"] * RISK_W["UNKNOWN"]
        )
        row = {
            "tool": tool,
            "image": image,
            **counts,
            "total_cves": total_cves,
            "risk": risk,
        }
        rows_per_image.append(row)

    per_image_csv = OUT_DIR / "summary_unique_per_image.csv"
    with per_image_csv.open("w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "tool",
            "image",
            *SEV_BUCKETS,
            "total_cves",
            "risk",
        ]
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows_per_image:
            w.writerow(r)

    print(f"✅ Wrote {per_image_csv}")

    df_img = pd.DataFrame(rows_per_image)

    # ----------------------------------------------------------------
    # 3. tool_unique_totals.csv + stacked bar plot
    # ----------------------------------------------------------------
    tool_totals = (
        df_img.groupby("tool")[SEV_BUCKETS + ["total_cves", "risk"]]
        .sum()
        .sort_values("risk", ascending=False)
    )
    tool_totals_csv = OUT_DIR / "tool_unique_totals.csv"
    tool_totals.to_csv(tool_totals_csv)
    print(f"✅ Wrote {tool_totals_csv}")

    ax = tool_totals[SEV_BUCKETS].plot(
        kind="bar",
        stacked=True,
        figsize=(8, 5),
    )
    ax.set_title("Unique CVEs by severity and tool — full experiment")
    ax.set_xlabel("Tool")
    ax.set_ylabel("Unique CVEs (count)")
    ax.legend(title="Severity", bbox_to_anchor=(1.02, 1), loc="upper left")
    plt.tight_layout()
    png = OUT_DIR / "fig_tool_unique_severity_totals.png"
    svg = OUT_DIR / "fig_tool_unique_severity_totals.svg"
    plt.savefig(png, dpi=200, bbox_inches="tight")
    plt.savefig(svg, bbox_inches="tight")
    plt.close()
    print(f"✅ Wrote {png}")
    print(f"✅ Wrote {svg}")

    # ----------------------------------------------------------------
    # 4. daily_severity_totals.csv + delta trend plot (both tools)
    # ----------------------------------------------------------------
    rows_daily = []
    for (d_str, tool), cve_map in sorted(daily_tool_cves.items()):
        counts = {s: 0 for s in SEV_BUCKETS}
        for sev in cve_map.values():
            bucket = sev if sev in SEV_BUCKETS else "UNKNOWN"
            counts[bucket] += 1
        total = sum(counts.values())
        row = {
            "date": d_str,
            "tool": tool,
            "total_cves": total,
        }
        row.update(counts)
        rows_daily.append(row)

    df_daily = pd.DataFrame(rows_daily)
    if not df_daily.empty:
        df_daily.sort_values(["date", "tool"], inplace=True)
        daily_csv = OUT_DIR / "daily_severity_totals.csv"
        df_daily.to_csv(daily_csv, index=False)
        print(f"✅ Wrote {daily_csv}")

        # Convert date strings -> datetime for nicer plots
        df_daily["date_dt"] = pd.to_datetime(df_daily["date"], format="%d-%m-%Y")

        # Optional: compute a daily risk score as well
        df_daily["risk"] = (
            df_daily["CRITICAL"] * RISK_W["CRITICAL"]
            + df_daily["HIGH"] * RISK_W["HIGH"]
            + df_daily["MEDIUM"] * RISK_W["MEDIUM"]
            + df_daily["LOW"] * RISK_W["LOW"]
            + df_daily["UNKNOWN"] * RISK_W["UNKNOWN"]
        )

        # Compute day-to-day deltas per tool (for total CVE counts)
        df_daily = df_daily.sort_values(["tool", "date_dt"])
        df_daily["delta_total_cves"] = (
            df_daily.groupby("tool")["total_cves"].diff().fillna(0)
        )
        df_daily["delta_risk"] = (
            df_daily.groupby("tool")["risk"].diff().fillna(0)
        )

        # Save with deltas for reference
        daily_deltas_csv = OUT_DIR / "daily_severity_deltas.csv"
        df_daily.to_csv(daily_deltas_csv, index=False)
        print(f"✅ Wrote {daily_deltas_csv}")

        # Single trend figure: Trivy vs Clair, day-to-day delta in total CVEs
        fig, ax = plt.subplots(figsize=(9, 5))

        for tool in TOOLS:
            dft = df_daily[df_daily["tool"] == tool]
            if dft.empty:
                continue
            ax.plot(
                dft["date_dt"],
                dft["delta_total_cves"],
                marker="o",
                label=tool.capitalize(),
            )

        ax.axhline(0, linestyle="--")
        ax.set_title("Day-to-day change in unique CVEs per tool")
        ax.set_xlabel("Date")
        ax.set_ylabel("Δ total unique CVEs (today vs previous day)")
        plt.xticks(rotation=45, ha="right")
        ax.legend(title="Tool")
        plt.tight_layout()

        png_t = OUT_DIR / "fig_daily_deltas_both_tools.png"
        svg_t = OUT_DIR / "fig_daily_deltas_both_tools.svg"
        plt.savefig(png_t, dpi=200, bbox_inches="tight")
        plt.savefig(svg_t, bbox_inches="tight")
        plt.close()

        print(f"✅ Wrote {png_t}")
        print(f"✅ Wrote {svg_t}")

    # ----------------------------------------------------------------
    # 5. Optional: report skipped files
    # ----------------------------------------------------------------
    if skipped:
        print("⚠️  Skipped invalid/empty JSON files:")
        for s in skipped:
            print("   -", s)


if __name__ == "__main__":
    main()
