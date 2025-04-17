from elasticsearch import Elasticsearch

# Connect to your Elasticsearch server
es = Elasticsearch(
    "http://52.72.42.245:64298",  
    basic_auth=("", ""),
    verify_certs=False  # Set to True if using HTTPS with valid certs
)

# Set your index pattern
index_name = "logstash-*"  # Replace with your actual index (e.g., "logstash-*")

# Define the shared time and IP filter
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
                {"term": {"alert.signature.keyword": "ET INFO Reserved Internal IP Traffic"}},
                {"term": {"proto.keyword": "vnc"}},
                {"terms": {"dest_port": [21, 22, 23, 25, 110, 143, 3389, 5900]}},
                {"terms": {"flow.dest_port": [21, 22, 23, 25, 110, 143, 3389, 5900]}},
            ],
        }
    }
}

flow_id_query = {
    **base_query,
    "size": 0,
    "aggs": {
        "unique_flow_ids": {
            "cardinality": {
                "field": "flow_id"
            }
        }
    }
}
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


# Run both queries
flow_id_result = es.search(index=index_name, body=flow_id_query)
ip_result = es.search(index=index_name, body=ip_query)

# Extract values
unique_flows = flow_id_result["aggregations"]["unique_flow_ids"]["value"]
unique_ips = ip_result["aggregations"]["unique_ips"]["value"]

result = es.count(index=index_name, body=base_query)
print("Filtered doc count:", result["count"])

# Compute average
if unique_ips == 0:
    print("No IPs found.")
else:
    average_requests_per_ip = unique_flows / unique_ips
    print(f"Unique flow_ids: {unique_flows}")
    print(f"Unique IPs: {unique_ips}")
    print(f"Average attacks per IP: {average_requests_per_ip:.2f}")

#############################################new code to answer "how many IP's with X attacks?#####################33


# Composite aggregation to group IPs and count unique flow_ids per IP
flow_per_ip_query = {
    **base_query,
    "size": 0,
    "aggs": {
        "ip_buckets": {
            "composite": {
                "size": 1000,
                "sources": [
                    {"ip": {"terms": {"field": "src_ip.keyword"}}}
                ]
            },
            "aggs": {
                "unique_flows": {
                    "cardinality": {
                        "field": "flow_id"
                    }
                }
            }
        }
    }
}

# Scroll through composite results to get all IPs
after_key = None
ip_over_50 = []

while True:
    if after_key:
        flow_per_ip_query["aggs"]["ip_buckets"]["composite"]["after"] = after_key
    response = es.search(index=index_name, body=flow_per_ip_query)
    buckets = response["aggregations"]["ip_buckets"]["buckets"]

    for bucket in buckets:
        count = bucket["unique_flows"]["value"]
        if count > 50:
            ip_over_50.append((bucket["key"]["ip"], count))

    if "after_key" in response["aggregations"]["ip_buckets"]:
        after_key = response["aggregations"]["ip_buckets"]["after_key"]
    else:
        break

print(f"Number of IPs with more than 50 unique flow_ids: {len(ip_over_50)}")

# Optional: print them
# for ip, count in ip_over_200:
#     print(f"{ip}: {count}")




################################Answering the question: Average session length across all IP's? (difference between first and last contact)
from datetime import datetime
from dateutil import parser as date_parser

# Session duration query: get first and last timestamp per IP
session_query = {
    **base_query,
    "size": 0,
    "aggs": {
        "ip_buckets": {
            "composite": {
                "size": 1000,
                "sources": [
                    {"ip": {"terms": {"field": "src_ip.keyword"}}}
                ]
            },
            "aggs": {
                "first_seen": {"min": {"field": "@timestamp"}},
                "last_seen": {"max": {"field": "@timestamp"}}
            }
        }
    }
}

# Scroll through all IPs
after_key = None
session_lengths = []

while True:
    if after_key:
        session_query["aggs"]["ip_buckets"]["composite"]["after"] = after_key
    response = es.search(index=index_name, body=session_query)
    buckets = response["aggregations"]["ip_buckets"]["buckets"]

    for bucket in buckets:
        ip = bucket["key"]["ip"]
        first = date_parser.parse(bucket["first_seen"]["value_as_string"])
        last = date_parser.parse(bucket["last_seen"]["value_as_string"])
        session_seconds = (last - first).total_seconds()
        session_lengths.append(session_seconds)

    if "after_key" in response["aggregations"]["ip_buckets"]:
        after_key = response["aggregations"]["ip_buckets"]["after_key"]
    else:
        break

# Calculate average session length
if session_lengths:
    avg_session = sum(session_lengths) / len(session_lengths)
    print(f"Average session length across IPs: {avg_session:.2f} seconds")
else:
    print("No session data found.")
from datetime import timedelta
print(f"Avg session length: {timedelta(seconds=avg_session)}")


from datetime import datetime, timedelta
from dateutil import parser as date_parser

# ----------------------------
# A. Get All IP Session Durations
# ----------------------------

print("\nGathering all session lengths...")

session_query = {
    **base_query,
    "size": 0,
    "aggs": {
        "ip_buckets": {
            "composite": {
                "size": 1000,
                "sources": [
                    {"ip": {"terms": {"field": "src_ip.keyword"}}}
                ]
            },
            "aggs": {
                "first_seen": {"min": {"field": "@timestamp"}},
                "last_seen": {"max": {"field": "@timestamp"}}
            }
        }
    }
}

after_key = None
ip_sessions = []

while True:
    if after_key:
        session_query["aggs"]["ip_buckets"]["composite"]["after"] = after_key
    response = es.search(index=index_name, body=session_query)
    buckets = response["aggregations"]["ip_buckets"]["buckets"]

    for bucket in buckets:
        ip = bucket["key"]["ip"]
        first = date_parser.parse(bucket["first_seen"]["value_as_string"])
        last = date_parser.parse(bucket["last_seen"]["value_as_string"])
        duration = (last - first).total_seconds()
        ip_sessions.append((ip, duration))

    if "after_key" in response["aggregations"]["ip_buckets"]:
        after_key = response["aggregations"]["ip_buckets"]["after_key"]
    else:
        break

# ----------------------------
# Top N Longest Sessions
# ----------------------------

top_n = 50  # ← Change this to 5, 10, 25, etc. as needed

print(f"\nTop {top_n} Longest Sessions:")

# Sort and enumerate top N IPs by session length
for i, (ip, duration) in enumerate(sorted(ip_sessions, key=lambda x: x[1], reverse=True)[:top_n], start=1):
    print(f"{i}. {ip} — {timedelta(seconds=duration)}")

# INVESTIGATION
for ip, duration in sorted(ip_sessions, key=lambda x: x[1], reverse=True)[:5]:
    print(f"{ip}: {timedelta(seconds=duration)}")

    # Re-run the query for just that IP to see actual timestamps
    ip_specific_query = {
        **base_query,
        "query": {
            "bool": {
                "must": [
                    {"term": {"src_ip.keyword": ip}}
                ],
                "filter": base_query["query"]["bool"]["filter"],
                "must_not": base_query["query"]["bool"]["must_not"]
            }
        },
        "size": 1,
        "sort": [{"@timestamp": "asc"}],
        "_source": ["@timestamp"]
    }

    first = es.search(index=index_name, body=ip_specific_query)["hits"]["hits"][0]["_source"]["@timestamp"]

    ip_specific_query["sort"] = [{"@timestamp": "desc"}]
    last = es.search(index=index_name, body=ip_specific_query)["hits"]["hits"][0]["_source"]["@timestamp"]

    print(f"    First seen: {first}")
    print(f"    Last seen:  {last}")


print("\nTop 10 IPs by unique flow_id count:")
for ip, count in sorted(ip_over_50, key=lambda x: x[1], reverse=True)[:10]:
    print(f"{ip}: {count} unique flow_ids")

# --------------------------------------
# C. Average Session Length for IPs with >50 Unique flow_ids
# --------------------------------------

print("\nIdentifying IPs with >50 unique flow_ids...")

flowid_query = {
    **base_query,
    "size": 0,
    "aggs": {
        "ip_buckets": {
            "composite": {
                "size": 1000,
                "sources": [
                    {"ip": {"terms": {"field": "src_ip.keyword"}}}
                ]
            },
            "aggs": {
                "flow_count": {
                    "cardinality": {
                        "field": "flow_id"
                    }
                }
            }
        }
    }
}

after_key = None
active_ip_set = set()

while True:
    if after_key:
        flowid_query["aggs"]["ip_buckets"]["composite"]["after"] = after_key
    response = es.search(index=index_name, body=flowid_query)
    buckets = response["aggregations"]["ip_buckets"]["buckets"]

    for bucket in buckets:
        if bucket["flow_count"]["value"] > 50:
            active_ip_set.add(bucket["key"]["ip"])

    if "after_key" in response["aggregations"]["ip_buckets"]:
        after_key = response["aggregations"]["ip_buckets"]["after_key"]
    else:
        break

# Filter to only IPs in that set
filtered_sessions = [duration for ip, duration in ip_sessions if ip in active_ip_set]

if filtered_sessions:
    avg_filtered = sum(filtered_sessions) / len(filtered_sessions)
    print(f"\nAvg session length for IPs with >50 unique flow_ids: {timedelta(seconds=avg_filtered)}")
else:
    print("\nNo qualifying IPs found.")


