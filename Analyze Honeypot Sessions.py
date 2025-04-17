import os
import pandas as pd
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan

# === Configuration ===
HONEYPOTS = {
    "Tanner": "http://54.160.237.7:64298",
    "Static": "http://52.72.42.245:64298",
    "Glastopf": "http://54.221.97.79:64298",
}
AUTH = ("", "")
DATE_RANGE = {
    "gte": "2025-03-01T19:00:00-06:00",
    "lte": "2025-03-22T19:00:00-05:00"
}
SESSION_TIMEOUT_MINUTES = 30
CACHE_PATH = "attack_data.parquet"
FORCE_REFRESH = False  # Set to True if you want to re-fetch from Elasticsearch

# === Query for scan ===
def build_es_query():
    return {
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": DATE_RANGE}},
                    {"term": {"dest_port": 80}}
                ],
                "must_not": [
                    {"wildcard": {"src_ip.keyword": "138.247.*"}},
                    {"term": {"type.keyword": "Heralding"}},
                    {"term": {"proto.keyword": "vnc"}},
                    {"terms": {"dest_port": [21, 22, 23, 25, 110, 143, 3389, 5900]}},
                    {"terms": {"flow.dest_port": [21, 22, 23, 25, 110, 143, 3389, 5900]}},
                    {"wildcard": {"alert.signature.keyword": "*CINS*"}},
                    {"wildcard": {"alert.signature.keyword": "*Dshield*"}},
                    {"wildcard": {"alert.signature.keyword": "*Spamhaus*"}},
                    {"wildcard": {"alert.signature.keyword": "*Poor Reputation*"}},
                    {"wildcard": {"alert.signature.keyword": "*Block Listed Source*"}},
                    {"wildcard": {"alert.signature.keyword": "*Known Scanner*"}}
                ]
            }
        }
    }

# === Pull logs from all honeypots ===
def fetch_all_data():
    all_data = []
    for name, url in HONEYPOTS.items():
        print(f"Fetching data from {name}...")
        es = Elasticsearch(url, basic_auth=AUTH, verify_certs=False)
        query = build_es_query()
        results = scan(
            client=es,
            query=query,
            index="logstash-*",
            _source=["@timestamp", "src_ip", "flow_id"],
            preserve_order=False
        )
        for res in results:
            src = res.get("_source", {})
            try:
                all_data.append({
                    "honeypot": name,
                    "ip": src["src_ip"],
                    "timestamp": datetime.fromisoformat(src["@timestamp"].replace("Z", "+00:00"))
                })
            except Exception as e:
                print(f"Skipped a record due to parsing error: {e}")
    return pd.DataFrame(all_data)

# === Load or Fetch Data (with Caching) ===
if os.path.exists(CACHE_PATH) and not FORCE_REFRESH:
    print(f"Loading cached data from '{CACHE_PATH}'...")
    df = pd.read_parquet(CACHE_PATH)
else:
    print("Pulling fresh data from Elasticsearch...")
    df = fetch_all_data()
    if df.empty:
        print("No data found.")
        exit()
    df.to_parquet(CACHE_PATH, index=False)
    print(f"Data cached to '{CACHE_PATH}'.")

# === Sort & Session Grouping ===
df.sort_values(by=["honeypot", "ip", "timestamp"], inplace=True)

def assign_sessions(group, timeout=SESSION_TIMEOUT_MINUTES):
    group = group.sort_values("timestamp")
    group["time_diff"] = group["timestamp"].diff().fillna(pd.Timedelta(seconds=0))
    group["new_session"] = group["time_diff"] > timedelta(minutes=timeout)
    group["session_id"] = group["new_session"].cumsum()
    return group

df = df.groupby(["honeypot", "ip"], group_keys=False).apply(assign_sessions).reset_index(drop=True)

# === Session Stats Per Honeypot ===
print("\n=== Session Summary Per Honeypot ===")
for honeypot in df["honeypot"].unique():
    subset = df[df["honeypot"] == honeypot]
    session_counts = subset.groupby("ip")["session_id"].nunique()
    avg_sessions = session_counts.mean()
    total_sessions = session_counts.sum()
    unique_ips = session_counts.count()

    print(f"\n--- {honeypot} ---")
    print(f"Unique attacker IPs: {unique_ips}")
    print(f"Total sessions: {total_sessions}")
    print(f"Average sessions per IP: {round(avg_sessions, 2)}")

# === Calculate Session Durations ===
session_durations = (
    df.groupby(["honeypot", "ip", "session_id"])["timestamp"]
    .agg(["min", "max"])
    .reset_index()
)
session_durations["duration"] = session_durations["max"] - session_durations["min"]

# === Average Session Duration Per IP ===
avg_durations_per_ip = (
    session_durations.groupby(["honeypot", "ip"])["duration"]
    .mean()
    .reset_index(name="avg_session_duration")
)

# === Aggregate Average Duration Per Honeypot ===
print("\n=== Average Session Duration Per Honeypot ===")
for honeypot in avg_durations_per_ip["honeypot"].unique():
    durations = avg_durations_per_ip[avg_durations_per_ip["honeypot"] == honeypot]["avg_session_duration"]
    mean_duration = durations.mean()
    print(f"{honeypot}: {mean_duration}")
