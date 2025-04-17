from elasticsearch import Elasticsearch
from collections import defaultdict
from datetime import datetime
import math

# === Configuration ===
USE_LOG_SCALE = True
HONEYPOTS = {
    "Tanner": "http://18.207.96.107:64298",
    "Static": "http://54.226.248.213:64298",
    "Glastopf": "http://3.84.206.182:64298",
}
AUTH = ("", "")
HEADERS = {"verify_certs": False}
DATE_RANGE = {
    "gte": "2025-03-01T19:00:00-06:00",
    "lte": "2025-03-22T19:00:00-05:00"
}

INDEX = "logstash-*"

# === Query Builder for Alert Categories with Unique Flow ID Count ===
def build_es_query():
    filters = [
        {"range": {"@timestamp": DATE_RANGE}}
        {"term": {"dest_port": 80}},  # <-- this is now properly its own dict
    ]
    
    must_not = [
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

    return {
        "size": 0,
        "query": {
            "bool": {
                "filter": filters,
                "must_not": must_not
            }
        },
        "aggs": {
            "categories": {
                "terms": {
                    "field": "alert.signature.keyword",
                    "size": 250
                },
                "aggs": {
                    "unique_flows": {
                        "cardinality": {
                            "field": "flow_id"
                        }
                    }
                }
            },
            "total_unique_flows": {
                "cardinality": {
                    "field": "flow_id"
                }
            }
        }
    }

# === Shannon Entropy Calculation ===
def compute_entropy(counts):
    total = sum(counts.values())
    if total == 0:
        return 0.0
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy

# === Run Entropy Analysis per Honeypot ===
def run_entropy_analysis():
    results = {}
    for honeypot_name, honeypot_url in HONEYPOTS.items():
        es = Elasticsearch(honeypot_url, basic_auth=AUTH, verify_certs=False)
        query = build_es_query()
        response = es.search(index=INDEX, body=query)

        buckets = response.get("aggregations", {}).get("categories", {}).get("buckets", [])
        category_counts = {
            b["key"]: b["unique_flows"]["value"] 
            for b in buckets
        }

        entropy = compute_entropy(category_counts)
        total_alerts = response.get("aggregations", {}).get("total_unique_flows", {}).get("value", 0)

        results[honeypot_name] = {
            "entropy": entropy,
            "total_alerts": total_alerts,
            "unique_categories": len(category_counts),
            "category_counts": category_counts
        }

    return results

# === Main Execution ===
if __name__ == "__main__":
    results = run_entropy_analysis()
    for honeypot, data in results.items():
        print(f"\nHoneypot: {honeypot}")
        print(f"  Entropy: {data['entropy']:.3f}")
        print(f"  Total Unique Attacks (by flow_id): {data['total_alerts']}")
        print(f"  Unique Categories: {data['unique_categories']}")
        print(f"  Top Categories:")
        for cat, count in sorted(data["category_counts"].items(), key=lambda x: -x[1])[:5]:
            print(f"    {cat}: {count}")
