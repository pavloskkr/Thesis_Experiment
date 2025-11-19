import pandas as pd, pathlib, sys, math, re
import matplotlib.pyplot as plt

# image label prettifier
def pretty_image_label(s: str, maxlen: int = 36) -> str:
    # 1) drop digest tail
    s = re.sub(r'_sha256_[0-9a-f]{16,64}$', '', s)
    # 2) strip local registry host prefix
    s = re.sub(r'^localhost_5001_', '', s)
    # 3) reconstruct "path:tag" (last underscore is tag sep)
    if '_' in s:
        name_part, tag = s.rsplit('_', 1)
        # turn underscores back to slashes in the repo path
        name_part = name_part.replace('_', '/')
        s = f"{name_part}:{tag}"
    # 4) shorten long labels with center ellipsis
    if len(s) > maxlen:
        keep = maxlen - 1
        head = keep // 2
        tail = keep - head
        s = s[:head] + '…' + s[-tail:]
    return s

# ----------- inputs / paths -----------
date = sys.argv[1] if len(sys.argv) > 1 else None
if not date:
    import datetime; date = datetime.datetime.now().strftime("%d-%m-%Y")
base = pathlib.Path("out") / date
base.mkdir(parents=True, exist_ok=True)

m = pd.read_csv(base / "metrics.csv")
a = pd.read_csv(base / "agreement.csv")

# ----------- helper -----------
def savefig(path_png: pathlib.Path):
    path_svg = path_png.with_suffix(".svg")
    plt.tight_layout()
    plt.savefig(path_png, dpi=200, bbox_inches="tight")
    plt.savefig(path_svg, bbox_inches="tight")
    plt.close()

# ----------- 1) Per-tool totals (stacked severities) -----------
sev_cols = ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"]
tool_totals = m.groupby("tool")[sev_cols + ["total","risk"]].sum()
tool_totals = tool_totals.sort_values("risk", ascending=False)
tool_totals.to_csv(base / "table_tool_totals.csv")

ax = tool_totals[sev_cols].plot(kind="bar", stacked=True, figsize=(8,5))
ax.set_title(f"Severity totals by tool — {date}")
ax.set_xlabel("Tool")
ax.set_ylabel("Findings (count)")
ax.legend(title="Severity", bbox_to_anchor=(1.02, 1), loc="upper left")
savefig(base / "fig_tool_totals.png")

# ----------- 2) Per-image risk (grouped bars) -----------
# pivot to columns per tool; fill missing with 0; sort by combined risk
risk_wide = m.pivot(index="image", columns="tool", values="risk").fillna(0.0)
risk_wide["__sum__"] = risk_wide.sum(axis=1)
risk_wide = risk_wide.sort_values("__sum__", ascending=False).drop(columns="__sum__")
risk_wide.to_csv(base / "table_risk_per_image.csv")

# Limit x tick clutter if many images
max_labels = 40
show = risk_wide.head(max_labels) if len(risk_wide) > max_labels else risk_wide

ax = show.plot(kind="bar", figsize=(max(10, len(show)*0.35), 6))
ax.set_title(f"Per-image risk by tool (top {len(show)}/{len(risk_wide)}) — {date}")
ax.set_xlabel("Image")
ax.set_ylabel("Risk score")
ax.set_xticklabels([pretty_image_label(x) for x in show.index], rotation=80, ha="right")
ax.legend(title="Tool")
savefig(base / "fig_risk_per_image.png")

# Top 10 risky images (csv only, like your original)
m["risk_sum_image"] = m.groupby("image")["risk"].transform("sum")
top10 = (m.sort_values("risk_sum_image", ascending=False)
           .drop_duplicates("image").head(10)[["image","risk_sum_image"]])
top10.to_csv(base / "table_top10_images.csv", index=False)

# ----------- 3) Agreement per image (Jaccard) -----------
a_sorted = a.sort_values("jaccard", ascending=False)
a_sorted.to_csv(base / "table_agreement_sorted.csv", index=False)

# show all or trim if huge
show_ag = a_sorted.copy()
if len(show_ag) > max_labels:
    # show top 20 + bottom 20 to highlight extremes
    head = show_ag.head(20)
    tail = show_ag.tail(20)
    show_ag = pd.concat([head, tail])

fig, ax = plt.subplots(figsize=(max(10, len(show_ag)*0.35), 5))
ax.bar(show_ag["image"], show_ag["jaccard"])
ax.set_title(f"Agreement per image (Jaccard index) — {date}")
ax.set_xlabel("Image")
ax.set_ylabel("Jaccard (0–1)")
ax.set_xticklabels([pretty_image_label(x) for x in show_ag["image"]], rotation=80, ha="right")
savefig(base / "fig_agreement_jaccard.png")

print(f"✅ Wrote tables to: {base}")
print(f"✅ Wrote figures:\n - {base/'fig_tool_totals.png'}\n - {base/'fig_risk_per_image.png'}\n - {base/'fig_agreement_jaccard.png'}")
