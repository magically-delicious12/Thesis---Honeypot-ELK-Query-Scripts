from elasticsearch import Elasticsearch
from collections import defaultdict
from datetime import datetime
import os

# === Configuration ===
USE_LOG_SCALE = True
HONEYPOTS = {
   "Tanner": "http://54.234.62.158:64298",
   # "Static": "http://3.89.243.238:64298",
   # "Glastopf": "http://3.94.146.65:64298",
}
AUTH = ("", "")
HEADERS = {"verify_certs": False}
DATE_RANGE = {
    "gte": "2025-03-01T19:00:00-06:00",
    "lte": "2025-03-22T19:00:00-05:00"
}

CATEGORY_OF_INTEREST = "Web Application Attack"

# === Query Builders ===
def build_es_query(category=None):
    filters = [
        {"range": {"@timestamp": DATE_RANGE}},
    ]
    if category:
        filters.append({"term": {"alert.category.keyword": category}})
    
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
            "signatures": {
                "terms": {
                    "field": "alert.signature.keyword",
                    "size": 1000
                }
            }
        }
    }

# === Execution ===
def run():
    all_results = defaultdict(dict)
    category_counts = {}
    total_counts = {}

    for honeypot, url in HONEYPOTS.items():
        print(f"Querying {honeypot}...")

        es = Elasticsearch(url, basic_auth=AUTH, **HEADERS)

        # Query: Specific category
        category_query = build_es_query(CATEGORY_OF_INTEREST)
        category_response = es.search(index="logstash-*", body=category_query)
        category_total = sum(bucket["doc_count"] for bucket in category_response["aggregations"]["signatures"]["buckets"])
        category_counts[honeypot] = category_total

        for bucket in category_response["aggregations"]["signatures"]["buckets"]:
            signature = bucket["key"]
            count = bucket["doc_count"]
            all_results[honeypot][signature] = count

        # Query: All alerts (with same exclusions but no category filter)
        total_query = build_es_query()
        total_response = es.search(index="logstash-*", body=total_query)
        total_count = sum(bucket["doc_count"] for bucket in total_response["aggregations"]["signatures"]["buckets"])
        total_counts[honeypot] = total_count

    # === Save to File ===
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    safe_category = CATEGORY_OF_INTEREST.replace(" ", "_")
    filename = f"alerts_{safe_category}_{timestamp}.txt"
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"Alert Signatures for Category: '{CATEGORY_OF_INTEREST}'\n")
        f.write(f"Date Range: {DATE_RANGE['gte']} → {DATE_RANGE['lte']}\n\n")

        for honeypot in HONEYPOTS:
            f.write(f"--- {honeypot} ---\n")
            total = total_counts.get(honeypot, 0)
            cat_total = category_counts.get(honeypot, 0)
            percent = (cat_total / total * 100) if total > 0 else 0
            f.write(f"Total alerts in category: {cat_total}\n")
            f.write(f"Total alerts overall:     {total}\n")
            f.write(f"Category % of total:      {percent:.2f}%\n\n")

            sorted_items = sorted(all_results[honeypot].items(), key=lambda x: x[1], reverse=True)
            for sig, count in sorted_items:
                f.write(f"{count:>5}  {sig}\n")
            f.write("\n")

    print(f"\n✅ Results saved to: {filename}")

if __name__ == "__main__":
    run()
