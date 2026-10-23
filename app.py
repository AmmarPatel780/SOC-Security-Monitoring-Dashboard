
import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import timedelta
from pathlib import Path

st.set_page_config(
    page_title="SOC Security Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Security Operations Center")
st.caption("Windows Authentication Log Analysis")

st.sidebar.header("Security Monitoring")

source = st.sidebar.radio(
    "Select data source",
    ["Local Windows Logs", "Upload CSV"]
)

if source == "Local Windows Logs":
    path = Path(__file__).parent / "windows_events.csv"

    if not path.exists():
        st.error("windows_events.csv not found!")
        st.stop()

    df = pd.read_csv(path)

else:
    uploaded = st.sidebar.file_uploader(
        "Upload Windows security events",
        type=["csv"]
    )

    if uploaded is None:
        st.info("Upload a CSV file to begin analysis.")
        st.stop()

    df = pd.read_csv(uploaded)

required = [
    "Timestamp", "User", "EventID",
    "Status", "SourceIP"
]

if not all(col in df.columns for col in required):
    st.error("CSV is missing required columns.")
    st.stop()

df["Timestamp"] = pd.to_datetime(
    df["Timestamp"], errors="coerce"
)

df["EventID"] = pd.to_numeric(
    df["EventID"], errors="coerce"
)

df = df.dropna(subset=["Timestamp", "EventID"])
df = df[df["EventID"].isin([4624, 4625])].copy()

df["Status"] = df["EventID"].map({
    4624: "Success",
    4625: "Failed"
})

df["User"] = df["User"].fillna("Unknown")
df["SourceIP"] = df["SourceIP"].fillna("Unknown")

df = df.sort_values("Timestamp", ascending=False)

failed = df[df["Status"] == "Failed"]
successful = df[df["Status"] == "Success"]

st.subheader("Security Overview")

c1, c2, c3 = st.columns(3)

c1.metric("Total Events", len(df))
c2.metric("Successful Logins", len(successful))
c3.metric("Failed Logins", len(failed))

st.subheader("Authentication Activity")

if not df.empty:
    activity = df.copy()
    activity["Minute"] = activity["Timestamp"].dt.floor("min")

    counts = activity.groupby(
        ["Minute", "Status"]
    ).size().reset_index(name="Count")

    fig = px.line(
        counts,
        x="Minute",
        y="Count",
        color="Status",
        title="Windows Login Activity"
    )

    st.plotly_chart(fig, width="stretch")

st.subheader("Suspicious Login Detection")

threshold = st.slider(
    "Failed login alert threshold",
    min_value=3,
    max_value=20,
    value=5
)

alerts = []

for (user, ip), group in failed.groupby(
    ["User", "SourceIP"]
):
    times = sorted(group["Timestamp"])
    left = 0

    for right, current in enumerate(times):
        while current - times[left] > timedelta(minutes=5):
            left += 1

        count = right - left + 1

        if count >= threshold:
            alerts.append({
                "User": user,
                "Source IP": ip,
                "Failed Attempts": count,
                "Window End": current,
                "Severity": "High"
            })
            break

if alerts:
    st.warning(
        f"{len(alerts)} suspicious authentication pattern(s) detected"
    )
    st.dataframe(pd.DataFrame(alerts), width="stretch")
else:
    st.success("No patterns exceeded the configured threshold.")

st.subheader("Security Event Explorer")

status = st.selectbox(
    "Filter events",
    ["All", "Success", "Failed"]
)

filtered = (
    df if status == "All"
    else df[df["Status"] == status]
)

st.dataframe(filtered, width="stretch")

st.download_button(
    "Export Security Report",
    filtered.to_csv(index=False),
    file_name="security_report.csv",
    mime="text/csv"
)

st.caption(
    "Alerts are rule-based indicators, not proof of an attack."
)
