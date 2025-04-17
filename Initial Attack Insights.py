from elasticsearch import Elasticsearch

# Connect to Elasticsearch
es = Elasticsearch(
    "http://13.218.228.10:64298",
    basic_auth=("", ""),
    verify_certs=False
)

index_name = "logstash-*"

# Define base query filter
base_query = {
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
                }
            ],
            "must_not": [
                {"wildcard": {"src_ip.keyword": "138.247.*"}},
                {"term": {"type.keyword": "Heralding"}},
                {"term": {"proto.keyword": "vnc"}},
                {"terms": {"dest_port": [21, 22, 23, 25, 110, 143, 3389, 5900]}},
                {"terms": {"flow.dest_port": [21, 22, 23, 25, 110, 143, 3389, 5900]}},
            ],
        }
    }
}

# ------------------------------------
# DATA VERIFICATION SECTION
# ------------------------------------
print("🔍 Data Verification:")

# Total document count
doc_count = es.count(index=index_name, body=base_query)["count"]
print(f"  Total matching documents: {doc_count}")

# Unique source IPs
ip_query = {
    **base_query,
    "size": 0,
    "aggs": {
        "unique_ips": {
            "cardinality": {
                "field": "src_ip.keyword"
            }
        }
    }
}
ip_count = es.search(index=index_name, body=ip_query)["aggregations"]["unique_ips"]["value"]
print(f"  Unique IP addresses: {ip_count}")

# Unique flow_id count
flow_query = {
    **base_query,
    "size": 0,
    "aggs": {
        "unique_flows": {
            "cardinality": {
                "field": "flow_id"
            }
        }
    }
}
flow_count = es.search(index=index_name, body=flow_query)["aggregations"]["unique_flows"]["value"]
print(f"  Unique flow_id values: {flow_count}")

# ------------------------------------
# ATTACK METHODOLOGY SECTION
# ------------------------------------

print("\n🛡️ Top 20 Attack Types (alert.signature.keyword):")
attack_type_query = {
    **base_query,
    "size": 0,
    "aggs": {
        "attack_types": {
            "terms": {
                "field": "alert.signature.keyword",
                "size": 20
            }
        }
    }
}
resp = es.search(index=index_name, body=attack_type_query)
for bucket in resp["aggregations"]["attack_types"]["buckets"]:
    print(f"{bucket['key']} — {bucket['doc_count']} hits")


print("\n📂 Top 10 Uploaded File Types (fileinfo.magic.keyword):")
filetype_query = {
    **base_query,
    "size": 0,
    "aggs": {
        "file_types": {
            "terms": {
                "field": "fileinfo.magic.keyword",
                "size": 10
            }
        }
    }
}
resp = es.search(index=index_name, body=filetype_query)
for bucket in resp["aggregations"]["file_types"]["buckets"]:
    print(f"{bucket['key']} — {bucket['doc_count']} files")


print("\n📄 Top 10 Uploaded Filenames (fileinfo.filename.keyword):")
filename_query = {
    **base_query,
    "size": 0,
    "aggs": {
        "file_names": {
            "terms": {
                "field": "fileinfo.filename.keyword",
                "size": 10
            }
        }
    }
}
resp = es.search(index=index_name, body=filename_query)
for bucket in resp["aggregations"]["file_names"]["buckets"]:
    print(f"{bucket['key']} — {bucket['doc_count']} times")



fields_to_agg = {
    "alert.category.keyword": "Top 10 Alert Categories",
    "alert.metadata.confidence.keyword": "Top 10 Alert Metadata: Confidence Flags",
    "alert.metadata.signature_severity.keyword": "Top 10 Alert Metadata: Signature Severity",
    "alert.severity": "Top 10 Alert Severities (numeric)",
    "alert.signature_id": "Top 10 Alert Signature IDs",
    "alert.signature.keyword": "Top 10 Alert Signatures (Text)",
    "app_proto.keyword": "Top 10 Application Protocols",
    "event_type.keyword": "Top 10 Event Types",
    "fileinfo.filename.keyword": "Top 10 Uploaded Filenames",
    "fileinfo.magic.keyword": "Top 10 Uploaded File Types",
    "ip_rep.keyword": "Top 10 IP Reputation Tags",
    "path.keyword": "Top 10 Web Request Paths",
    "type.keyword": "Top 10 Log Types (Container Source)"
}

for field, label in fields_to_agg.items():
    print(f"\n{label} ({field}):")
    query = {
        **base_query,
        "size": 0,
        "aggs": {
            "top_terms": {
                "terms": {
                    "field": field,
                    "size": 10
                }
            }
        }
    }
    try:
        resp = es.search(index=index_name, body=query)
        buckets = resp["aggregations"]["top_terms"]["buckets"]
        if buckets:
            for bucket in buckets:
                print(f"{bucket['key']} — {bucket['doc_count']}")
        else:
            print("No results found.")
    except Exception as e:
        print(f"Error retrieving {field}: {e}")
