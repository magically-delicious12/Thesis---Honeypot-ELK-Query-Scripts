from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib
from datetime import datetime
import os

# Use non-interactive backend
matplotlib.use('Agg')

# === Configuration ===
HONEYPOTS = {
    "Snare": "http://54.160.237.7:64298",
    "Static": "http://52.72.42.245:64298",
    "Glastopf": "http://54.221.97.79:64298",
}
AUTH = ("", "")
DATE_RANGE = {
    "gte": "2025-03-01T19:00:00-06:00",
    "lte": "2025-03-22T19:00:00-05:00"
}
CACHE_PATH = "attack_data.parquet"
FORCE_REFRESH = False  # Set to True to ignore cache and re-fetch

# === Query Builder ===
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

# === Data Fetching ===
def fetch_all_data():
    all_data = []
    for name, url in HONEYPOTS.items():
        print(f"🔍 Fetching data from {name}...")
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
            src = res.get('_source', {})
            src_ip = src.get("src_ip")
            timestamp = src.get("@timestamp")
            flow_id = src.get("flow_id")

            if src_ip and timestamp and flow_id:
                try:
                    all_data.append({
                        "honeypot": name,
                        "ip": src_ip,
                        "timestamp": pd.to_datetime(timestamp),
                        "flow_id": flow_id
                    })
                except Exception as e:
                    print(f"⚠️ Skipped bad record: {e}")

    return pd.DataFrame(all_data)


# === Load or Fetch Data ===
if not os.path.exists(CACHE_PATH) or FORCE_REFRESH:
    df = fetch_all_data()
    df.to_parquet(CACHE_PATH)
    print(f"✅ Data saved to {CACHE_PATH}")
else:
    df = pd.read_parquet(CACHE_PATH)
    print(f"✅ Loaded cached data from {CACHE_PATH}")

# === Preprocess & Aggregate ===
df['date'] = df['timestamp'].dt.date

# Group by honeypot, date, and src_ip to count flow events
grouped = df.groupby(['honeypot', 'date', 'ip'])['flow_id'].nunique().reset_index(name='flow_count')

# Create pivot tables for each honeypot
pivot_tables = {}
global_max = 0
for honeypot in grouped['honeypot'].unique():
    sub_df = grouped[grouped['honeypot'] == honeypot]
    pivot = sub_df.pivot(index='date', columns='ip', values='flow_count').fillna(0)
    pivot_tables[honeypot] = pivot
    max_val = pivot.max().max()
    if max_val > global_max:
        global_max = max_val

# === Plotting ===
fig, axes = plt.subplots(nrows=3, ncols=1, figsize=(20, 24), sharex=True, sharey=True)

for ax, (honeypot, pivot) in zip(axes, pivot_tables.items()):
    pivot.plot(ax=ax, linewidth=2)
    ax.set_title(f"{honeypot} — Attacks on Port 80 per Source IP", fontsize=28, fontweight='bold')
    ax.set_ylabel("TCP Flows", fontsize=24)
    ax.grid(True, linestyle='--', linewidth=0.8, alpha=0.7)
    ax.set_ylim(0, global_max + 1)
    ax.legend().remove()  # 🔇 Removes clutter

# X-axis label and ticks
axes[-1].set_xlabel("Date", fontsize=24)
for ax in axes:
    ax.tick_params(axis='x', labelrotation=45, labelsize=20)
    ax.tick_params(axis='y', labelsize=20)

plt.tight_layout()
output_file = "RAAHHHHH2 G1 Individual_Honeypot_Flow_ByIP.png"
plt.savefig(output_file, dpi=450)
print(f"📈 Plot saved to {output_file}")

# === Summary Statistics ===
print("\n🔎 Summary Statistics:")
print(f"📦 Total records: {len(df):,}")
print(f"📅 Date range: {df['timestamp'].min().date()} to {df['timestamp'].max().date()}")

print("\n📊 Records by Honeypot:")
print(df['honeypot'].value_counts())

print("\n🌐 Unique Source IPs by Honeypot:")
print(df.groupby('honeypot')['ip'].nunique())

print("\n🔁 Unique Flow IDs by Honeypot:")
print(df.groupby('honeypot')['flow_id'].nunique())

