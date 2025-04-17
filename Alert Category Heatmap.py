from elasticsearch import Elasticsearch
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import os
from pathlib import Path

# === Configuration ===
USE_LOG_SCALE = True
HONEYPOTS = {
    "Tanner": "http://54.160.237.7:64298",
    "Static": "http://52.72.42.245:64298",
    "Glastopf": "http://54.221.97.79:64298",
}
AUTH = ("", "")
HEADERS = {"verify_certs": False}
DATE_RANGE = {
    "gte": "2025-03-01T19:00:00-06:00",
    "lte": "2025-03-22T19:00:00-05:00"
}

# === Helper Functions ===
def clean_category_label(label):
    return label  # Extend this if needed later

def build_es_query(include_aggs=True):
    base_query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [{"range": {"@timestamp": DATE_RANGE}}, {"term": {"dest_port": 80}}],
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

    if include_aggs:
        base_query["aggs"] = {
            "by_day": {
                "date_histogram": {
                    "field": "@timestamp",
                    "calendar_interval": "1d"
                },
                "aggs": {
                    "by_category": {
                        "terms": {
                            "field": "alert.category.keyword",
                            "size": 100
                        }
                    }
                }
            }
        }

    return base_query

def get_all_categories(es_url):
    es = Elasticsearch(es_url, basic_auth=AUTH, **HEADERS)
    query = build_es_query(include_aggs=False)
    query["aggs"] = {
        "all_categories": {
            "terms": {
                "field": "alert.category.keyword",
                "size": 500
            }
        }
    }
    response = es.search(index="logstash-*", body=query)
    categories = [bucket["key"] for bucket in response["aggregations"]["all_categories"]["buckets"]]
    return categories

def query_elasticsearch(es_url, honeypot_name):
    es = Elasticsearch(es_url, basic_auth=AUTH, **HEADERS)
    query = build_es_query()
    
    ip_query = build_es_query(include_aggs=False)
    ip_query["aggs"] = {
        "unique_ips": {"cardinality": {"field": "src_ip.keyword"}}
    }
    ip_response = es.search(index="logstash-*", body=ip_query)
    unique_ip_count = ip_response["aggregations"]["unique_ips"]["value"]
    print(f"[{honeypot_name}] Unique attacker IPs (post-filter): {unique_ip_count}")

    response = es.search(index="logstash-*", body=query)
    return response

def parse_aggregation(response):
    records = []
    for day in response["aggregations"]["by_day"]["buckets"]:
        date = day["key_as_string"][:10]
        for cat in day["by_category"]["buckets"]:
            records.append({
                "date": date,
                "category": cat["key"],
                "count": cat["doc_count"]
            })
    return pd.DataFrame(records)

def generate_label_code(index):
    if index < 26:
        return chr(65 + index)
    else:
        first = chr(64 + (index // 26))
        second = chr(65 + (index % 26))
        return first + second

def plot_heatmap(df, honeypot_name, all_categories):
    df["date"] = pd.to_datetime(df["date"])
    df["clean_label"] = df["category"].apply(clean_category_label)

    all_clean = [clean_category_label(cat) for cat in all_categories]
    label_map = {label: generate_label_code(i) for i, label in enumerate(all_clean)}
    df["label_code"] = df["clean_label"].map(label_map)

    # Save label code mapping for this honeypot
    legend_df = pd.DataFrame({
        "label_code": list(label_map.values()),
        "clean_label": list(label_map.keys()),
        "category": all_categories
    })
    legend_file = f"4.9 No Scaling{honeypot_name}_alert_category_legend_with_codes.csv"
    legend_df.to_csv(legend_file, index=False)
    print(f"[{honeypot_name}] Saved legend to {legend_file}")

    df_pivot = df.pivot(index="label_code", columns="date", values="count").fillna(0)
    df_pivot = df_pivot.loc[df_pivot.sum(axis=1).sort_values(ascending=True).index]
    df_plot = np.log1p(df_pivot) if USE_LOG_SCALE else df_pivot
    color_label = "Log(Alert Count)" if USE_LOG_SCALE else "Alert Count"
    file_suffix = "_log" if USE_LOG_SCALE else "_raw"

    df_plot.columns = [d.strftime("%m-%d") for d in df_plot.columns]

    plt.figure(figsize=(18, 12))
    ax = sns.heatmap(
        df_plot,
        cmap="Greys",
        annot=False,
        linewidths=0.5,
        cbar_kws={'label': color_label}
    )

    plt.title(f"Alert Categories Over Time", fontsize=40, pad=20)
    plt.xlabel("Date", fontsize=36, labelpad=16)
    plt.ylabel("Suricata Alert Code", fontsize=36, labelpad=16)
    ax.set_xticklabels(ax.get_xticklabels(), rotation=45, ha='right', fontsize=28)
    ax.set_yticklabels(ax.get_yticklabels(), rotation=90, fontsize=28)
    cbar = ax.collections[0].colorbar
    cbar.ax.tick_params(labelsize=28)
    cbar.set_label(color_label, size=32)

    plt.tight_layout(rect=[0, 0, 1, 0.97])

    filename = f"4.9 No Scaling{honeypot_name}_category_heatmap{file_suffix}.png"
    plt.savefig(filename, dpi=300)
    plt.close()
    print(f"4.9 No Scaling[{honeypot_name}] Saved heatmap to {filename}")




# === Main Execution ===
CACHE_DIR = Path("cache")
CACHE_DIR.mkdir(exist_ok=True)

for honeypot_name, es_url in HONEYPOTS.items():
    try:
        print(f"\n=== Processing {honeypot_name} ===")
        cache_file = CACHE_DIR / f"{honeypot_name}_alert_data.csv"

        all_categories = get_all_categories(es_url)

        if cache_file.exists():
            print(f"[{honeypot_name}] Loading data from cache.")
            df = pd.read_csv(cache_file, parse_dates=["date"])
        else:
            response = query_elasticsearch(es_url, honeypot_name)
            df = parse_aggregation(response)
            if df.empty:
                print(f"[{honeypot_name}] No data returned.")
                continue
            df.to_csv(cache_file, index=False)
            print(f"[{honeypot_name}] Cached data to {cache_file}")

        # === Filter out categories with zero total alerts ===
        total_counts = df.groupby("category")["count"].sum()
        valid_categories = total_counts[total_counts > 0].index.tolist()
        df = df[df["category"].isin(valid_categories)]

        # Update the category list for legend/code mapping
        filtered_categories = [cat for cat in all_categories if cat in valid_categories]

        plot_heatmap(df, honeypot_name, filtered_categories)

    except Exception as e:
        print(f"[{honeypot_name}] Error: {e}")
