# ui/streamlit_app.py
import streamlit as st
import pandas as pd
from sqlalchemy import create_engine, text
import os
from datetime import datetime

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://dev:dev@localhost:5432/dwthreat")
engine = create_engine(DATABASE_URL, future=True)

st.set_page_config(page_title="DW Threat Monitor", layout="wide")

st.title("Dark-Web Threat Monitor — Dashboard")

# sidebar filters
with st.sidebar:
    st.header("Filters")
    org = st.text_input("Organization (name)", "")
    since_days = st.number_input("Show items from last N days", min_value=1, max_value=365, value=30)
    min_severity = st.selectbox("Min severity (show >=)", ["low","medium","high","critical"], index=0)
    run_query = st.button("Refresh")

st.header("Run Dark-Web Scan")

new_org = st.text_input("Organization to scan", "")
run_scan = st.button("Generate Seeds + Crawl")

import subprocess

if run_scan and new_org:
    st.info(f"Generating seeds for {new_org}… please wait")
    with st.spinner("Finding onion links..."):
        subprocess.run(["python", "-m", "tools.seed_generator", new_org], check=False)

    seed_file = f"seeds/{new_org}.txt"
    if not os.path.exists(seed_file):
        st.error("No seeds generated. Try a different query.")
    else:
        st.success("Seeds generated successfully!")

        st.info("Starting Tor crawler… this may take several minutes")
        with st.spinner("Crawling onion sites…"):
            subprocess.run([
                "python", "-m", "services.crawler.crawler_tor",
                new_org, seed_file, "--rotate"
            ], check=False)

        st.success("Crawling completed.")


# helper to load data
def load_crawled(limit=200, org_filter=None, since_days=30):
    q = "SELECT id, org_id, url, status_code, fetched_at, substring(content_snippet,1,400) AS snippet FROM crawled_pages"
    params = {}
    conds = []
    if org_filter:
        conds.append("org_id = (SELECT id FROM orgs WHERE name = :org LIMIT 1)")
        params["org"] = org_filter
    if since_days:
        conds.append("fetched_at >= now() - interval ':days days'")
        params["days"] = since_days
    if conds:
        q += " WHERE " + " AND ".join(conds)
    q += " ORDER BY fetched_at DESC LIMIT :lim"
    params["lim"] = limit
    df = pd.read_sql(text(q), engine.connect(), params=params)
    return df

def load_threats(limit=200, org_filter=None, since_days=30, min_sev="low"):
    q = "SELECT t.id, t.org_id, o.name as org_name, t.crawled_page_id, t.indicator_type, substring(t.indicator,1,200) as indicator, t.severity, t.created_at FROM threats t JOIN orgs o ON o.id = t.org_id"
    params = {}
    conds = []
    if org_filter:
        conds.append("t.org_id = (SELECT id FROM orgs WHERE name = :org LIMIT 1)")
        params["org"] = org_filter
    if since_days:
        conds.append("t.created_at >= now() - interval ':days days'")
        params["days"] = since_days
    # severity mapping order
    order_map = {"low":1,"medium":2,"high":3,"critical":4}
    if min_sev:
        # filter severities >= requested
        conds.append(" (CASE WHEN t.severity='low' THEN 1 WHEN t.severity='medium' THEN 2 WHEN t.severity='high' THEN 3 WHEN t.severity='critical' THEN 4 ELSE 0 END) >= :minsev")
        params["minsev"] = order_map.get(min_sev,1)
    if conds:
        q += " WHERE " + " AND ".join(conds)
    q += " ORDER BY t.created_at DESC LIMIT :lim"
    params["lim"] = limit
    df = pd.read_sql(text(q), engine.connect(), params=params)
    return df

if run_query:
    crawled = load_crawled(limit=500, org_filter=org if org else None, since_days=since_days)
    threats = load_threats(limit=500, org_filter=org if org else None, since_days=since_days, min_sev=min_severity)
    st.subheader("Recent Crawled Pages")
    st.dataframe(crawled)

    st.subheader("Detected Threats")
    st.dataframe(threats)

    if not threats.empty:
        st.markdown("### Threat Details (latest 10)")
        for _, row in threats.head(10).iterrows():
            st.write(f"**Org:** {row['org_name']}  — **Type:** {row['indicator_type']}  — **Severity:** {row['severity']}")
            st.code(row['indicator'])
else:
    st.info("Set filters and click Refresh to load data.")

