import boto3
import pandas as pd
import streamlit as st
import time
st.caption("Auto-refreshing every 10 seconds...")
time.sleep(10)
st.rerun()

st.set_page_config(page_title="AWS SIEM Dashboard", layout="wide")

dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
table = dynamodb.Table("SIEMAlerts")

@st.cache_data(ttl=30)
def load_alerts():
    response = table.scan()
    items = response.get("Items", [])
    if not items:
        return pd.DataFrame()

    df = pd.DataFrame(items)
    if "EventTime" in df.columns:
        df = df.sort_values("EventTime", ascending=False)
    return df

st.title("AWS SIEM Dashboard")

df = load_alerts()

if df.empty:
    st.warning("No alerts found in DynamoDB.")
    st.stop()

col1, col2, col3 = st.columns(3)
with col1:
    st.metric("Total Alerts", len(df))
with col2:
    high_count = len(df[df["Severity"] == "HIGH"]) if "Severity" in df.columns else 0
    st.metric("High Severity", high_count)
with col3:
    med_count = len(df[df["Severity"] == "MEDIUM"]) if "Severity" in df.columns else 0
    st.metric("Medium Severity", med_count)

severity_options = ["All"] + sorted(df["Severity"].dropna().unique().tolist()) if "Severity" in df.columns else ["All"]
event_options = ["All"] + sorted(df["EventName"].dropna().unique().tolist()) if "EventName" in df.columns else ["All"]

selected_severity = st.selectbox("Filter by Severity", severity_options)
selected_event = st.selectbox("Filter by Event Name", event_options)

filtered_df = df.copy()

if selected_severity != "All":
    filtered_df = filtered_df[filtered_df["Severity"] == selected_severity]

if selected_event != "All":
    filtered_df = filtered_df[filtered_df["EventName"] == selected_event]

display_columns = [
    col for col in [
        "EventTime",
        "Severity",
        "EventName",
        "UserIdentity",
        "SourceIP",
        "IPCountry",
        "IPCity",
        "ISP",
        "IPReputation",
        "AWSRegion",
        "AlertId"
    ] if col in filtered_df.columns
]

st.subheader("Alerts")
st.dataframe(filtered_df[display_columns], use_container_width=True)

if "Severity" in df.columns:
    st.subheader("Alerts by Severity")
    severity_counts = df["Severity"].value_counts()
    st.bar_chart(severity_counts)

if "EventName" in df.columns:
    st.subheader("Alerts by Event Type")
    event_counts = df["EventName"].value_counts()
    st.bar_chart(event_counts)
