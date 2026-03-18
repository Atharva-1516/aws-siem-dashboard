import json
from collections import Counter
from datetime import datetime

import boto3
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components


st.set_page_config(page_title="AWS SIEM Dashboard", layout="wide")


@st.cache_data(ttl=20)
def load_alerts():
    dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
    table = dynamodb.Table("SIEMAlerts")
    response = table.scan()
    items = response.get("Items", [])
    return items


def normalize_severity(value):
    if not value:
        return "LOW"
    value = str(value).upper()
    if value in {"HIGH", "MEDIUM", "LOW"}:
        return value
    return "LOW"


def safe_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() == "true"
    return False


def format_event_time(value):
    if not value:
        return None
    try:
        dt = pd.to_datetime(value, utc=True, errors="coerce")
        if pd.isna(dt):
            return None
        return dt.to_pydatetime()
    except Exception:
        return None


def event_bucket(event_name):
    name = (event_name or "").lower()

    if "securitygroup" in name:
        return "Sec Group"
    if "consolelogin" in name or "root" in name:
        return "Root Access"
    if "user" in name or "policy" in name or "role" in name:
        return "IAM Change"
    if "s3" in name:
        return "S3 Access"
    return "Other"


items = load_alerts()

if not items:
    st.warning("No alerts found in DynamoDB.")
    st.stop()

df = pd.DataFrame(items)

for col in [
    "AlertId",
    "AWSRegion",
    "Severity",
    "SourceIP",
    "UserIdentity",
    "EventName",
    "EventTime",
    "IPCountry",
    "IPCity",
    "ISP",
    "IPReputation",
    "IsSuspicious",
]:
    if col not in df.columns:
        df[col] = None

df["Severity"] = df["Severity"].apply(normalize_severity)
df["IsSuspicious"] = df["IsSuspicious"].apply(safe_bool)
df["ParsedTime"] = df["EventTime"].apply(format_event_time)
df = df.sort_values("ParsedTime", ascending=False, na_position="last").reset_index(drop=True)

total_alerts = len(df)
high_alerts = int((df["Severity"] == "HIGH").sum())
medium_alerts = int((df["Severity"] == "MEDIUM").sum())
suspicious_alerts = int(df["IsSuspicious"].sum())

latest_row = df.iloc[0]
latest_event = latest_row.get("EventName") or "N/A"
latest_ip = latest_row.get("SourceIP") or "N/A"
latest_time = latest_row.get("ParsedTime")
latest_time_str = latest_time.strftime("%Y-%m-%d %H:%M:%S UTC") if latest_time else "N/A"

pattern_note = "Repeated cloud activity observed"
if "root" in str(latest_row.get("UserIdentity", "")).lower():
    pattern_note = "Security-sensitive action performed by root user"
elif "securitygroup" in str(latest_event).lower():
    pattern_note = "Network access rules are being modified"

# Alerts table
alerts_data = []
for idx, row in df.head(12).iterrows():
    parsed = row.get("ParsedTime")
    alerts_data.append(
        {
            "id": idx + 1,
            "time": parsed.strftime("%Y-%m-%d %H:%M:%S") if parsed else str(row.get("EventTime") or "N/A"),
            "sev": row.get("Severity", "LOW"),
            "event": str(row.get("EventName") or "N/A"),
            "ip": str(row.get("SourceIP") or "N/A"),
            "region": str(row.get("AWSRegion") or "N/A"),
        }
    )

# Chart data by HH:MM bucket
chart_counter = {}
for _, row in df.iterrows():
    parsed = row.get("ParsedTime")
    label = parsed.strftime("%H:%M") if parsed else "Unknown"
    if label not in chart_counter:
        chart_counter[label] = {"label": label, "high": 0, "med": 0, "low": 0}
    sev = row.get("Severity", "LOW")
    if sev == "HIGH":
        chart_counter[label]["high"] += 1
    elif sev == "MEDIUM":
        chart_counter[label]["med"] += 1
    else:
        chart_counter[label]["low"] += 1

chart_data = sorted(chart_counter.values(), key=lambda x: x["label"])[-8:]
max_chart_val = max(
    [max(d["high"], d["med"], d["low"]) for d in chart_data] + [1]
)

# Timeline
timeline = []
for _, row in df.head(6).iterrows():
    parsed = row.get("ParsedTime")
    severity = row.get("Severity", "LOW")
    color = {
        "HIGH": "var(--red)",
        "MEDIUM": "var(--orange)",
        "LOW": "var(--green)",
    }.get(severity, "var(--cyan)")
    timeline.append(
        {
            "time": parsed.strftime("%H:%M:%S") if parsed else "N/A",
            "text": f"{severity}: {row.get('EventName', 'N/A')} from {row.get('SourceIP', 'N/A')}",
            "color": color,
        }
    )

# Top source IPs
ip_counts = df["SourceIP"].fillna("N/A").astype(str).value_counts().head(5)
max_ip_count = max(ip_counts.max(), 1)
sources = []
for ip, count in ip_counts.items():
    pct = int((count / max_ip_count) * 100)
    sources.append({"ip": ip, "count": int(count), "pct": pct})

# Threat distribution
bucket_counts = Counter(event_bucket(x) for x in df["EventName"].fillna("").astype(str))
threat_labels = ["Sec Group", "Root Access", "IAM Change", "S3 Access", "Other"]
max_bucket = max(bucket_counts.values()) if bucket_counts else 1
threat_distribution = []
for label in threat_labels:
    count = bucket_counts.get(label, 0)
    pct = int((count / max_bucket) * 100) if max_bucket else 0
    color = {
        "Sec Group": "linear-gradient(90deg,var(--red),var(--orange))",
        "Root Access": "var(--red)",
        "IAM Change": "var(--orange)",
        "S3 Access": "var(--cyan)",
        "Other": "var(--text-dim)",
    }[label]
    threat_distribution.append(
        {
            "label": label,
            "pct": pct,
            "display_pct": f"{pct}%",
            "color": color,
        }
    )

risk_level = "LOW"
if high_alerts > 0:
    risk_level = "HIGH"
elif medium_alerts > 0:
    risk_level = "ELEVATED"

html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AWS SIEM Dashboard — Atharva Suryawanshi</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;400;600;700;900&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg-base: #030b12;
    --bg-panel: #070f1a;
    --bg-card: #0a1525;
    --bg-card-hover: #0e1e35;
    --border: #0d2a45;
    --border-glow: #0a4a7a;
    --cyan: #00d4ff;
    --cyan-dim: #0099cc;
    --cyan-glow: rgba(0, 212, 255, 0.15);
    --green: #00ff9d;
    --green-dim: #00b870;
    --red: #ff3366;
    --red-dim: #cc1144;
    --orange: #ff8800;
    --yellow: #ffd700;
    --text-primary: #c8e8ff;
    --text-secondary: #4a7fa5;
    --text-dim: #2a4a65;
    --mono: 'Share Tech Mono', monospace;
    --sans: 'Exo 2', sans-serif;
  }}

  * {{ margin: 0; padding: 0; box-sizing: border-box; }}

  body {{
    background: var(--bg-base);
    color: var(--text-primary);
    font-family: var(--sans);
    min-height: 100vh;
    overflow-x: hidden;
  }}

  body::before {{
    content: '';
    position: fixed;
    inset: 0;
    background: repeating-linear-gradient(
      0deg,
      transparent,
      transparent 2px,
      rgba(0,0,0,0.08) 2px,
      rgba(0,0,0,0.08) 4px
    );
    pointer-events: none;
    z-index: 9999;
  }}

  .ambient {{
    position: fixed;
    border-radius: 50%;
    filter: blur(120px);
    pointer-events: none;
    z-index: 0;
    opacity: 0.07;
  }}
  .ambient-1 {{ width: 600px; height: 600px; background: var(--cyan); top: -200px; left: -200px; }}
  .ambient-2 {{ width: 400px; height: 400px; background: var(--green); bottom: -100px; right: -100px; animation: pulse 6s ease-in-out infinite; }}
  .ambient-3 {{ width: 300px; height: 300px; background: var(--red); top: 40%; right: 15%; animation: pulse 8s ease-in-out infinite 2s; }}

  @keyframes pulse {{ 0%,100%{{opacity:0.06}} 50%{{opacity:0.14}} }}
  @keyframes fadeInUp {{ from{{opacity:0;transform:translateY(20px)}} to{{opacity:1;transform:translateY(0)}} }}
  @keyframes blink {{ 0%,100%{{opacity:1}} 50%{{opacity:0}} }}
  @keyframes countUp {{ from{{opacity:0;transform:scale(0.8)}} to{{opacity:1;transform:scale(1)}} }}
  @keyframes borderPulse {{ 0%,100%{{border-color:var(--border)}} 50%{{border-color:var(--cyan-dim)}} }}
  @keyframes slideIn {{ from{{opacity:0;transform:translateX(-10px)}} to{{opacity:1;transform:translateX(0)}} }}
  @keyframes growUp {{ from{{height:0!important;opacity:0}} to{{opacity:1}} }}
  @keyframes growRight {{ from{{width:0}} }}

  .wrapper {{
    position: relative;
    z-index: 1;
    max-width: 1600px;
    margin: 0 auto;
    padding: 24px;
  }}

  header {{
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    margin-bottom: 32px;
    animation: fadeInUp 0.6s ease both;
  }}

  .header-left {{
    display: flex;
    flex-direction: column;
    gap: 6px;
  }}

  .header-tag {{
    font-family: var(--mono);
    font-size: 11px;
    color: var(--cyan);
    letter-spacing: 3px;
    text-transform: uppercase;
    display: flex;
    align-items: center;
    gap: 8px;
  }}

  .header-tag::before {{
    content: '';
    display: inline-block;
    width: 6px;
    height: 6px;
    background: var(--green);
    border-radius: 50%;
    box-shadow: 0 0 8px var(--green);
    animation: blink 1.5s ease-in-out infinite;
  }}

  h1 {{
    font-size: 2.2rem;
    font-weight: 900;
    letter-spacing: -1px;
    line-height: 1;
    background: linear-gradient(135deg, #ffffff 0%, var(--cyan) 60%, var(--cyan-dim) 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }}

  .header-sub {{
    font-family: var(--mono);
    font-size: 12px;
    color: var(--text-secondary);
    letter-spacing: 1px;
  }}

  .header-right {{
    text-align: right;
    display: flex;
    flex-direction: column;
    gap: 8px;
    align-items: flex-end;
  }}

  .live-badge {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: rgba(0, 255, 157, 0.08);
    border: 1px solid var(--green-dim);
    border-radius: 4px;
    padding: 4px 12px;
    font-family: var(--mono);
    font-size: 11px;
    color: var(--green);
    letter-spacing: 2px;
  }}

  .live-badge::before {{
    content: '';
    width: 6px;
    height: 6px;
    background: var(--green);
    border-radius: 50%;
    box-shadow: 0 0 6px var(--green);
    animation: blink 1s ease infinite;
  }}

  #clock {{
    font-family: var(--mono);
    font-size: 22px;
    color: var(--cyan);
    letter-spacing: 2px;
  }}

  .analyst-id {{
    font-family: var(--mono);
    font-size: 10px;
    color: var(--text-dim);
    letter-spacing: 1px;
  }}

  .kpi-grid {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin-bottom: 24px;
    animation: fadeInUp 0.6s ease 0.1s both;
  }}

  .kpi-card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px 24px;
    position: relative;
    overflow: hidden;
    cursor: default;
    transition: all 0.3s ease;
  }}

  .kpi-card::before {{
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: var(--accent-color, var(--cyan));
    box-shadow: 0 0 16px var(--accent-color, var(--cyan));
  }}

  .kpi-card::after {{
    content: '';
    position: absolute;
    inset: 0;
    background: radial-gradient(ellipse at top left, var(--accent-glow, var(--cyan-glow)), transparent 70%);
    pointer-events: none;
    opacity: 0;
    transition: opacity 0.3s;
  }}

  .kpi-card:hover {{ border-color: var(--border-glow); transform: translateY(-2px); }}
  .kpi-card:hover::after {{ opacity: 1; }}

  .kpi-card.cyan  {{ --accent-color: var(--cyan); --accent-glow: rgba(0,212,255,0.1); }}
  .kpi-card.red   {{ --accent-color: var(--red); --accent-glow: rgba(255,51,102,0.1); }}
  .kpi-card.orange{{ --accent-color: var(--orange); --accent-glow: rgba(255,136,0,0.1); }}
  .kpi-card.yellow{{ --accent-color: var(--yellow); --accent-glow: rgba(255,215,0,0.1); }}

  .kpi-label {{
    font-family: var(--mono);
    font-size: 10px;
    color: var(--text-secondary);
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: 12px;
    display: flex;
    align-items: center;
    gap: 8px;
  }}

  .kpi-label span {{
    font-size: 14px;
    color: var(--accent-color, var(--cyan));
  }}

  .kpi-number {{
    font-family: var(--mono);
    font-size: 3rem;
    font-weight: 700;
    color: var(--accent-color, var(--cyan));
    text-shadow: 0 0 30px var(--accent-color, var(--cyan));
    line-height: 1;
    animation: countUp 0.8s cubic-bezier(0.16,1,0.3,1) both;
  }}

  .kpi-trend {{
    font-family: var(--mono);
    font-size: 10px;
    color: var(--text-dim);
    margin-top: 8px;
    display: flex;
    align-items: center;
    gap: 4px;
  }}

  .kpi-trend.up {{ color: var(--red); }}
  .kpi-trend.down {{ color: var(--green); }}

  .main-grid {{
    display: grid;
    grid-template-columns: 1fr 380px;
    gap: 20px;
    margin-bottom: 20px;
    animation: fadeInUp 0.6s ease 0.2s both;
  }}

  .panel {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
    animation: borderPulse 4s ease infinite;
  }}

  .panel-header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 20px;
    border-bottom: 1px solid var(--border);
    background: rgba(0,0,0,0.2);
  }}

  .panel-title {{
    font-family: var(--mono);
    font-size: 11px;
    color: var(--cyan);
    letter-spacing: 2px;
    text-transform: uppercase;
    display: flex;
    align-items: center;
    gap: 8px;
  }}

  .panel-title::before {{
    content: '';
    display: inline-block;
    width: 8px;
    height: 8px;
    background: var(--cyan);
    clip-path: polygon(50% 0%,100% 50%,50% 100%,0% 50%);
    box-shadow: 0 0 8px var(--cyan);
  }}

  .panel-badge {{
    font-family: var(--mono);
    font-size: 10px;
    padding: 3px 8px;
    border-radius: 3px;
    border: 1px solid;
  }}

  .alerts-table {{
    width: 100%;
    border-collapse: collapse;
  }}

  .alerts-table th {{
    font-family: var(--mono);
    font-size: 9px;
    letter-spacing: 2px;
    color: var(--text-dim);
    text-transform: uppercase;
    text-align: left;
    padding: 10px 16px;
    border-bottom: 1px solid var(--border);
    background: rgba(0,0,0,0.15);
  }}

  .alerts-table td {{
    font-family: var(--mono);
    font-size: 12px;
    padding: 11px 16px;
    border-bottom: 1px solid rgba(13,42,69,0.5);
    color: var(--text-primary);
    white-space: nowrap;
    transition: background 0.2s;
  }}

  .alerts-table tbody tr:hover td {{ background: var(--bg-card-hover); }}

  .row-id {{
    font-family: var(--mono);
    font-size: 10px;
    color: var(--text-dim);
    width: 30px;
  }}

  .severity-badge {{
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 3px 10px;
    border-radius: 3px;
    font-family: var(--mono);
    font-size: 10px;
    letter-spacing: 1px;
    font-weight: 600;
    border: 1px solid;
  }}

  .severity-badge::before {{
    content: '';
    width: 5px;
    height: 5px;
    border-radius: 50%;
    background: currentColor;
    box-shadow: 0 0 6px currentColor;
  }}

  .sev-high   {{ color: var(--red); border-color: rgba(255,51,102,0.3); background: rgba(255,51,102,0.08); }}
  .sev-medium {{ color: var(--orange); border-color: rgba(255,136,0,0.3); background: rgba(255,136,0,0.08); }}
  .sev-low    {{ color: var(--green); border-color: rgba(0,255,157,0.3); background: rgba(0,255,157,0.08); }}

  .event-name {{ color: var(--cyan); font-size: 11px; }}
  .source-ip {{ color: var(--text-secondary); font-size: 11px; }}
  .time-cell {{ color: var(--text-dim); font-size: 11px; }}

  .side-panels {{
    display: flex;
    flex-direction: column;
    gap: 16px;
  }}

  .chart-container {{ padding: 20px; }}
  .chart-bars {{ display: flex; gap: 12px; align-items: flex-end; height: 120px; margin-bottom: 8px; }}
  .bar-group {{ display: flex; flex-direction: column; align-items: center; gap: 4px; flex: 1; }}
  .bar-wrap {{ display: flex; gap: 3px; align-items: flex-end; }}
  .bar {{
    width: 18px;
    border-radius: 3px 3px 0 0;
    transition: all 0.5s cubic-bezier(0.16,1,0.3,1);
    position: relative;
    animation: growUp 1s cubic-bezier(0.16,1,0.3,1) both;
  }}
  .bar:hover {{ filter: brightness(1.4); }}
  .bar-label {{
    font-family: var(--mono);
    font-size: 9px;
    color: var(--text-dim);
    letter-spacing: 1px;
    text-align: center;
  }}

  .chart-legend {{
    display: flex;
    gap: 16px;
    margin-top: 12px;
  }}

  .legend-item {{
    display: flex;
    align-items: center;
    gap: 6px;
    font-family: var(--mono);
    font-size: 9px;
    color: var(--text-secondary);
    letter-spacing: 1px;
  }}

  .legend-dot {{
    width: 8px;
    height: 8px;
    border-radius: 2px;
  }}

  .notes-content {{ padding: 16px 20px; display: flex; flex-direction: column; gap: 12px; }}

  .note-item {{
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding-bottom: 12px;
    border-bottom: 1px solid rgba(13,42,69,0.5);
  }}

  .note-item:last-child {{ border-bottom: none; padding-bottom: 0; }}

  .note-key {{
    font-family: var(--mono);
    font-size: 9px;
    color: var(--text-dim);
    letter-spacing: 2px;
    text-transform: uppercase;
  }}

  .note-val {{
    font-family: var(--mono);
    font-size: 12px;
    color: var(--cyan);
  }}

  .note-val.highlight {{
    color: var(--orange);
    text-shadow: 0 0 8px rgba(255,136,0,0.4);
  }}

  .bottom-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 16px;
    animation: fadeInUp 0.6s ease 0.3s both;
  }}

  .timeline {{ padding: 16px 20px; display: flex; flex-direction: column; gap: 10px; }}

  .tl-item {{
    display: flex;
    gap: 12px;
    align-items: flex-start;
    animation: slideIn 0.4s ease both;
  }}

  .tl-dot {{
    width: 8px;
    height: 8px;
    border-radius: 50%;
    margin-top: 3px;
    flex-shrink: 0;
    box-shadow: 0 0 8px currentColor;
  }}

  .tl-time {{
    font-family: var(--mono);
    font-size: 10px;
    color: var(--text-dim);
    white-space: nowrap;
    width: 80px;
    flex-shrink: 0;
  }}

  .tl-text {{
    font-family: var(--mono);
    font-size: 11px;
    color: var(--text-secondary);
    line-height: 1.4;
  }}

  .gauge-wrap {{ padding: 20px; display: flex; flex-direction: column; align-items: center; gap: 16px; }}
  .threat-items {{ width: 100%; display: flex; flex-direction: column; gap: 8px; }}
  .threat-bar-row {{ display: flex; align-items: center; gap: 10px; }}
  .threat-bar-label {{
    font-family: var(--mono);
    font-size: 10px;
    color: var(--text-secondary);
    width: 80px;
    flex-shrink: 0;
  }}
  .threat-bar-track {{
    flex: 1;
    height: 4px;
    background: var(--border);
    border-radius: 2px;
    overflow: hidden;
  }}
  .threat-bar-fill {{
    height: 100%;
    border-radius: 2px;
    animation: growRight 1.2s cubic-bezier(0.16,1,0.3,1) both;
  }}
  .threat-bar-pct {{
    font-family: var(--mono);
    font-size: 10px;
    color: var(--text-dim);
    width: 40px;
    text-align: right;
  }}
  .gauge-label {{
    font-family: var(--mono);
    font-size: 9px;
    color: var(--text-dim);
    letter-spacing: 2px;
    text-align: center;
  }}

  .source-list {{ padding: 16px 20px; display: flex; flex-direction: column; gap: 8px; }}
  .source-item {{
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 12px;
    background: rgba(0,0,0,0.2);
    border: 1px solid var(--border);
    border-radius: 4px;
    transition: all 0.2s;
    animation: slideIn 0.4s ease both;
  }}
  .source-item:hover {{ border-color: var(--cyan-dim); background: var(--bg-card-hover); }}
  .source-ip-badge {{ font-family: var(--mono); font-size: 11px; color: var(--cyan); flex: 1; }}
  .source-count {{ font-family: var(--mono); font-size: 10px; color: var(--text-dim); }}
  .source-bar-mini {{
    width: 60px;
    height: 3px;
    background: var(--border);
    border-radius: 2px;
    overflow: hidden;
  }}
  .source-bar-mini-fill {{
    height: 100%;
    background: var(--cyan);
    border-radius: 2px;
    box-shadow: 0 0 6px var(--cyan);
  }}

  ::-webkit-scrollbar {{ width: 4px; height: 4px; }}
  ::-webkit-scrollbar-track {{ background: var(--bg-base); }}
  ::-webkit-scrollbar-thumb {{ background: var(--border-glow); border-radius: 2px; }}

  .table-wrap {{ overflow-x: auto; max-height: 380px; overflow-y: auto; }}

  @media (max-width: 1200px) {{
    .kpi-grid {{ grid-template-columns: repeat(2,1fr); }}
    .main-grid {{ grid-template-columns: 1fr; }}
    .bottom-grid {{ grid-template-columns: 1fr 1fr; }}
  }}

  @media (max-width: 768px) {{
    .bottom-grid {{ grid-template-columns: 1fr; }}
    h1 {{ font-size: 1.5rem; }}
    .kpi-number {{ font-size: 2rem; }}
  }}
</style>
</head>
<body>

<div class="ambient ambient-1"></div>
<div class="ambient ambient-2"></div>
<div class="ambient ambient-3"></div>

<div class="wrapper">
  <header>
    <div class="header-left">
      <div class="header-tag">AWS CloudTrail · SIEM · SOC Operations</div>
      <h1>AWS SIEM Dashboard</h1>
      <div class="header-sub">ANALYST // ATHARVA SURYAWANSHI · REGION: us-east-1</div>
    </div>
    <div class="header-right">
      <div class="live-badge">LIVE FEED</div>
      <div id="clock">--:--:--</div>
      <div class="analyst-id">SESSION: ATH-SOC-2026 · CLEARANCE: L2</div>
    </div>
  </header>

  <div class="kpi-grid">
    <div class="kpi-card cyan">
      <div class="kpi-label"><span>◈</span> Total Alerts</div>
      <div class="kpi-number" id="kpi-total">{total_alerts}</div>
      <div class="kpi-trend up">▲ Live cloud monitoring enabled</div>
    </div>
    <div class="kpi-card red">
      <div class="kpi-label"><span>◈</span> High Severity</div>
      <div class="kpi-number" id="kpi-high" style="color:var(--red);text-shadow:0 0 30px var(--red)">{high_alerts}</div>
      <div class="kpi-trend up">▲ Immediate review recommended</div>
    </div>
    <div class="kpi-card orange">
      <div class="kpi-label"><span>◈</span> Medium Severity</div>
      <div class="kpi-number" id="kpi-med" style="color:var(--orange);text-shadow:0 0 30px var(--orange)">{medium_alerts}</div>
      <div class="kpi-trend">→ Ongoing monitoring state</div>
    </div>
    <div class="kpi-card yellow">
      <div class="kpi-label"><span>◈</span> Suspicious Alerts</div>
      <div class="kpi-number" id="kpi-sus" style="color:var(--yellow);text-shadow:0 0 30px var(--yellow)">{suspicious_alerts}</div>
      <div class="kpi-trend down">▼ Behavior-driven detections</div>
    </div>
  </div>

  <div class="main-grid">
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">Recent Security Alerts</div>
        <span class="panel-badge" style="color:var(--green);border-color:rgba(0,255,157,0.3);background:rgba(0,255,157,0.05)">{total_alerts} EVENTS</span>
      </div>
      <div class="table-wrap">
        <table class="alerts-table">
          <thead>
            <tr>
              <th>#</th>
              <th>Event Time (UTC)</th>
              <th>Severity</th>
              <th>Event Name</th>
              <th>Source IP</th>
              <th>Region</th>
            </tr>
          </thead>
          <tbody id="alert-tbody"></tbody>
        </table>
      </div>
    </div>

    <div class="side-panels">
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">Alert Summary</div>
        </div>
        <div class="chart-container">
          <div class="chart-bars" id="chart-bars"></div>
          <div class="chart-legend">
            <div class="legend-item"><div class="legend-dot" style="background:var(--red)"></div>HIGH</div>
            <div class="legend-item"><div class="legend-dot" style="background:var(--orange)"></div>MEDIUM</div>
            <div class="legend-item"><div class="legend-dot" style="background:var(--green)"></div>LOW</div>
          </div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">Analyst Notes</div>
          <span class="panel-badge" style="color:var(--orange);border-color:rgba(255,136,0,0.3);background:rgba(255,136,0,0.05)">AUTO</span>
        </div>
        <div class="notes-content">
          <div class="note-item">
            <div class="note-key">Latest Event</div>
            <div class="note-val">{latest_event}</div>
          </div>
          <div class="note-item">
            <div class="note-key">Source IP</div>
            <div class="note-val highlight">{latest_ip}</div>
          </div>
          <div class="note-item">
            <div class="note-key">Latest Event Time</div>
            <div class="note-val">{latest_time_str}</div>
          </div>
          <div class="note-item">
            <div class="note-key">Common Pattern</div>
            <div class="note-val" style="color:var(--text-secondary)">{pattern_note}</div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <div class="bottom-grid">
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">Event Timeline</div>
      </div>
      <div class="timeline" id="timeline"></div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">Threat Distribution</div>
      </div>
      <div class="gauge-wrap">
        <div class="threat-items" id="threat-items"></div>
        <div class="gauge-label">RISK LEVEL: <span style="color:var(--orange)">{risk_level}</span></div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">Top Source IPs</div>
      </div>
      <div class="source-list" id="source-list"></div>
    </div>
  </div>
</div>

<script>
  function updateClock() {{
    const now = new Date();
    document.getElementById('clock').textContent = now.toISOString().slice(11,19) + ' UTC';
  }}
  setInterval(updateClock, 1000);
  updateClock();

  const alerts = {json.dumps(alerts_data)};
  const chartData = {json.dumps(chart_data)};
  const timelineEvents = {json.dumps(timeline)};
  const sources = {json.dumps(sources)};
  const threatDistribution = {json.dumps(threat_distribution)};
  const maxVal = {max_chart_val};

  const sevClass = {{ HIGH:'sev-high', MEDIUM:'sev-medium', LOW:'sev-low' }};

  const tbody = document.getElementById('alert-tbody');
  alerts.forEach((a, i) => {{
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="row-id">${{String(a.id).padStart(2,'0')}}</td>
      <td class="time-cell">${{a.time}}</td>
      <td><span class="severity-badge ${{sevClass[a.sev] || 'sev-low'}}">${{a.sev}}</span></td>
      <td class="event-name">${{a.event}}</td>
      <td class="source-ip">${{a.ip}}</td>
      <td class="source-ip">${{a.region}}</td>
    `;
    tr.style.animationDelay = `${{i * 0.08}}s`;
    tbody.appendChild(tr);
  }});

  const chartH = 100;
  const barsEl = document.getElementById('chart-bars');

  chartData.forEach((d, i) => {{
    const grp = document.createElement('div');
    grp.className = 'bar-group';
    const wrap = document.createElement('div');
    wrap.className = 'bar-wrap';

    if (d.high > 0) {{
      const b = document.createElement('div');
      b.className = 'bar';
      b.style.cssText = `height:${{(d.high/maxVal)*chartH}}px;background:var(--red);box-shadow:0 0 10px var(--red);animation-delay:${{i*0.1}}s`;
      wrap.appendChild(b);
    }}
    if (d.med > 0) {{
      const b = document.createElement('div');
      b.className = 'bar';
      b.style.cssText = `height:${{(d.med/maxVal)*chartH}}px;background:var(--orange);box-shadow:0 0 10px var(--orange);animation-delay:${{i*0.1+0.1}}s`;
      wrap.appendChild(b);
    }}
    if (d.low > 0) {{
      const b = document.createElement('div');
      b.className = 'bar';
      b.style.cssText = `height:${{(d.low/maxVal)*chartH}}px;background:var(--green);box-shadow:0 0 10px var(--green);animation-delay:${{i*0.1+0.2}}s`;
      wrap.appendChild(b);
    }}
    if (!d.high && !d.med && !d.low) {{
      const b = document.createElement('div');
      b.className = 'bar';
      b.style.cssText = `height:4px;background:var(--border);`;
      wrap.appendChild(b);
    }}

    const lbl = document.createElement('div');
    lbl.className = 'bar-label';
    lbl.textContent = d.label;
    grp.appendChild(wrap);
    grp.appendChild(lbl);
    barsEl.appendChild(grp);
  }});

  const tlEl = document.getElementById('timeline');
  timelineEvents.forEach((e, i) => {{
    const item = document.createElement('div');
    item.className = 'tl-item';
    item.style.animationDelay = `${{i*0.1}}s`;
    item.innerHTML = `
      <div class="tl-dot" style="color:${{e.color}};background:${{e.color}}"></div>
      <div class="tl-time">${{e.time}}</div>
      <div class="tl-text">${{e.text}}</div>
    `;
    tlEl.appendChild(item);
  }});

  const srcEl = document.getElementById('source-list');
  sources.forEach((s, i) => {{
    const item = document.createElement('div');
    item.className = 'source-item';
    item.style.animationDelay = `${{i*0.1}}s`;
    item.innerHTML = `
      <div class="source-ip-badge">${{s.ip}}</div>
      <div class="source-bar-mini">
        <div class="source-bar-mini-fill" style="width:${{s.pct}}%"></div>
      </div>
      <div class="source-count">${{s.count}} events</div>
    `;
    srcEl.appendChild(item);
  }});

  const threatEl = document.getElementById('threat-items');
  threatDistribution.forEach((t, i) => {{
    const row = document.createElement('div');
    row.className = 'threat-bar-row';
    row.innerHTML = `
      <div class="threat-bar-label">${{t.label}}</div>
      <div class="threat-bar-track">
        <div class="threat-bar-fill" style="width:${{t.pct}}%;background:${{t.color}};animation-delay:${{0.3 + i*0.2}}s"></div>
      </div>
      <div class="threat-bar-pct">${{t.display_pct}}</div>
    `;
    threatEl.appendChild(row);
  }});
</script>
</body>
</html>
"""

components.html(html, height=1550, scrolling=True)
