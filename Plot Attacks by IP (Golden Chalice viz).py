from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib
import os

# Use non-interactive backend (avoid GUI lockups)
matplotlib.use('Agg')

# Connect to Elasticsearch
es = Elasticsearch(
    "http://52.72.42.245:64298",
    basic_auth=("", ""),
    verify_certs=False,
)

# Updated query
query = {
    "query": {
        "bool": {
            "filter": [
                {
                    "range": {
                        "@timestamp": {
                            "gte": "2025-03-01T19:00:00-06:00",
                            "lte": "2025-03-22T19:00:00-05:00",
                        }
                    }
                },
                {
                    "term": {
                        "dest_port": 80
                    }
                }
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
            ],
        }
    }
}

if os.path.exists("attack_data.parquet"):
    df = pd.read_parquet("attack_data.parquet")
else:
    # Pull matching documents
    results = scan(
        client=es,
        query=query,
        index="logstash-*",
        _source=["@timestamp", "src_ip", "flow_id"],
        preserve_order=False
    )

    # Parse and collect data
    data = []
    for i, res in enumerate(results):
        src = res.get('_source', {})

        src_ip = src.get("src_ip")
        timestamp = src.get("@timestamp")
        flow_id = src.get("flow_id")

        if i < 5:
            print(f"Sample #{i}: src_ip={src_ip}, timestamp={timestamp}, flow_id={flow_id}")

        if src_ip and timestamp and flow_id:
            try:
                data.append({
                    "src_ip": src_ip,
                    "timestamp": pd.to_datetime(timestamp),
                    "flow_id": flow_id
                })
            except Exception as e:
                print(f"Skipping record with bad timestamp: {timestamp} — {e}")

        if i % 10000 == 0:
            print(f"Processed {i} documents...")

    print(f"Total parsed rows: {len(data)}")

    # Convert to DataFrame
    df = pd.DataFrame(data)

    df.to_parquet("attack_data.parquet")
    print("✅ Cached to attack_data.parquet")


# Group by date and src_ip, count unique flow_ids
df['date'] = df['timestamp'].dt.date
agg_df = df.groupby(['date', 'src_ip'])['flow_id'].nunique().reset_index()
agg_df.rename(columns={'flow_id': 'unique_attacks'}, inplace=True)

# Pivot for plotting
pivot_df = agg_df.pivot(index='date', columns='src_ip', values='unique_attacks').fillna(0)

# Plotting
plt.figure(figsize=(18, 10))
for ip in pivot_df.columns:
    plt.plot(pivot_df.index, pivot_df[ip], label=ip, linewidth=1)

# Enhanced publication-ready plot (no legend, bold labels, thicker lines)
plt.figure(figsize=(18, 10))

for ip in pivot_df.columns:
    plt.plot(pivot_df.index, pivot_df[ip], linewidth=3)

#plt.title("Unique Attack Count per IP Over Time", fontsize=16, fontweight='bold')
#plt.figure(figsize=(7, 5))  # Narrow + tall = better for columns

plt.xlabel("Date", fontsize=38, fontweight='bold')
plt.ylabel("Unique TCP Flows", fontsize=38, fontweight='bold')
plt.xticks(rotation=45, fontsize=34)
plt.yticks(fontsize=34)
plt.grid(True, linestyle='--', linewidth=0.5, alpha=0.7)

plt.tight_layout()
plt.savefig("Static 4.5 TRYattack_timeline_clean.png", dpi=450)
print("✅ Enhanced plot saved as 'Staticattack_timeline_clean.png'")
