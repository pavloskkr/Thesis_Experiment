#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path
from datetime import datetime

OUT_ROOT = Path("out")
SUMMARY_DIR = OUT_ROOT / "risk_trends"
SUMMARY_DIR.mkdir(parents=True, exist_ok=True)

# ---- 1. Collect all metrics.csv (per day) ----
all_rows = []

for day_dir in OUT_ROOT.iterdir():
    if not day_dir.is_dir():
        continue
    metrics_path = day_dir / "metrics.csv"
    if not metrics_path.exists():
        continue

    try:
        df_day = pd.read_csv(metrics_path)
    except Exception:
        continue

    # date folder is DD-MM-YYYY
    try:
        date_dt = datetime.strptime(day_dir.name, "%d-%m-%Y")
    except ValueError:
        # skip non-date folders like "summary_unique"
        continue

    df_day["date_str"] = day_dir.name
    df_day["date"] = date_dt
    all_rows.append(df_day)

if not all_rows:
    raise SystemExit("❌ No metrics.csv files with date folders found under out/<DD-MM-YYYY>/")

df = pd.concat(all_rows, ignore_index=True)

# ---- 2. Ensure risk is numeric ----
df["risk"] = pd.to_numeric(df["risk"], errors="coerce").fillna(0.0)

# ---- 3. Aggregate per day + tool: total_risk, mean_risk ----
agg = (
    df.groupby(["date", "date_str", "tool"])
      .agg(
          total_risk=("risk", "sum"),
          mean_risk=("risk", "mean")
      )
      .reset_index()
)

# sort properly
agg = agg.sort_values(["tool", "date"])

# ---- 4. Compute Δ mean_risk per tool (relative to first day) ----
agg["delta_mean_risk"] = 0.0

for tool, g in agg.groupby("tool"):
    first = g["mean_risk"].iloc[0]
    agg.loc[g.index, "delta_mean_risk"] = g["mean_risk"] - first


# ---- 5. Save risk_daily_totals.csv for transparency ----
risk_csv = SUMMARY_DIR / "risk_daily_totals.csv"
agg_out = agg[["date_str", "tool", "total_risk", "mean_risk", "delta_mean_risk"]].copy()
agg_out.rename(columns={"date_str": "date"}, inplace=True)
agg_out.to_csv(risk_csv, index=False)
print("✅ Wrote:", risk_csv)

# ---- 6. Pivot for plotting Δ mean_risk ----
pivot = agg.pivot(index="date", columns="tool", values="delta_mean_risk").sort_index()

# ---- 7. Plot Δ mean risk per image over time ----
ax = pivot.plot(kind="line", marker="o", figsize=(8, 5))
ax.set_title("Change in mean risk score per image over time")
ax.set_xlabel("Date")
ax.set_ylabel("Δ mean risk (relative to first day)")
ax.axhline(0, linestyle="--", linewidth=0.8)

plt.tight_layout()
png = SUMMARY_DIR / "fig_risk_delta_mean_both_tools.png"
svg = SUMMARY_DIR / "fig_risk_delta_mean_both_tools.svg"
plt.savefig(png, dpi=200, bbox_inches="tight")
plt.savefig(svg, bbox_inches="tight")
plt.close()

print("✅ Wrote plots:")
print(" -", png)
print(" -", svg)
