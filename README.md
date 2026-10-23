# SOC Security Monitoring Dashboard

A Python-based Security Operations Center (SOC) dashboard designed to analyze Windows authentication events and identify potentially suspicious login activity.

## Project Overview

This project demonstrates foundational security monitoring and event analysis using Windows Security logs, Python, Pandas, Streamlit, and Plotly.

The dashboard processes exported Windows authentication events and provides visualizations, filtering, and rule-based detection.

## Features

- Analyze Windows Security Event IDs 4624 and 4625
- Import authentication events from CSV files
- Visualize successful and failed authentication activity
- Detect repeated failed logins within five-minute windows
- Configure failed-login detection thresholds
- Filter and explore security events
- Export event reports to CSV

## Technologies Used

- Python 3
- Streamlit
- Pandas
- Plotly
- Windows Event Viewer
- PowerShell

## Security Detection Logic

The dashboard identifies repeated authentication failures associated with the same username and source IP address within a five-minute window.

Alerts are investigative indicators and do not automatically confirm malicious activity.

## How to Run

1. Install Python 3.
2. Download the project.
3. Install dependencies:

   `py -m pip install -r requirements.txt`

4. Start the dashboard:

   `py -m streamlit run app.py`

5. Open `http://localhost:8501` in your browser.
6. Upload a compatible CSV export of Windows authentication events.

## Project Validation

Tested locally using 239 Windows authentication event records:

- 221 successful authentication events
- 18 failed authentication events

These results came from a local Windows Security log export. Raw event data is not included in this repository for privacy reasons.

## Future Improvements

- Incident investigation dashboard
- More advanced detection rules
- Authentication log normalization
- Security alert reporting
- Automated log refresh
- Unit testing

## Project Status

Version 1.0: Working Windows authentication log analysis dashboard.
