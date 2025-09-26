from scapy.all import IP, TCP, UDP, ICMP, sniff
import datetime
import time
import joblib
from pymongo import MongoClient
from langchain_community.graphs import Neo4jGraph
from collections import deque, defaultdict

# -------------------
# Neo4j Setup
# -------------------
NEO4j_URL = "neo4j+s://0b0dcfc9.databases.neo4j.io"
NEO4j_USERNAME = "neo4j"
NEO4j_PASSWORD = "w_EuMPCRLOOg6ZpDCV6NYkZQ1FEb5AHVmw5BXAryamE"
graph = Neo4jGraph(url=NEO4j_URL, username=NEO4j_USERNAME, password=NEO4j_PASSWORD)

# -------------------
# MongoDB Setup
# -------------------
client = MongoClient("mongodb://localhost:27017")
db = client.Adtapter_visualization
collection = db['CVE_predictor']

# -------------------
# Constants
# -------------------
start = time.time()

flag_meanings = {
    'S': 1, 'SA': 2, 'A': 3, 'R': 4, 'PA': 5,
    'FA': 6, 'RA': 7, 'RST': 8, 'UDP': 9, 'ICMP': 10
}

protocol_map = {6: 1, 17: 2, 1: 0}  # TCP=6, UDP=17, ICMP=1

label_map = {0: 'Normal', 1: 'DDoS', 2: 'Probe', 3: 'R2L', 4: 'U2R'}

service_map = {80: "http", 443: "https", 21: "ftp", 22: "ssh", 25: "smtp", 53: "dns"}

# -------------------
# Flow + Connection Tracking
# -------------------
flows = {}
window = deque(maxlen=100)  # last 100 connections
stats = defaultdict(lambda: {"count": 0, "services": defaultdict(int), "src_ports": defaultdict(int)})

def update_flow(packet):
    """Track cumulative src_bytes/dst_bytes per flow"""
    if not (IP in packet and (TCP in packet or UDP in packet)):
        return None

    proto = "TCP" if TCP in packet else "UDP"
    sport = packet[TCP].sport if TCP in packet else packet[UDP].sport
    dport = packet[TCP].dport if TCP in packet else packet[UDP].dport
    key = (packet[IP].src, packet[IP].dst, sport, dport, proto)

    flows.setdefault(key, {"src_bytes": 0, "dst_bytes": 0})

    payload_len = len(packet[TCP].payload) if TCP in packet else len(packet[UDP].payload)
    flows[key]["src_bytes"] += payload_len

    rev_key = (packet[IP].dst, packet[IP].src, dport, sport, proto)
    if rev_key in flows:
        flows[rev_key]["dst_bytes"] += payload_len

    return flows[key]

def update_stats(data):
    """Update host/service statistics"""
    dst = data["dst_ip"]
    service = service_map.get(data["service"], str(data["service"]))
    src_port = data["src_port"]

    # push connection into window
    window.append((data["src_ip"], dst, src_port, service))

    # update stats
    stats[dst]["count"] += 1
    stats[dst]["services"][service] += 1
    stats[dst]["src_ports"][src_port] += 1

    # calculate metrics
    dst_count = stats[dst]["count"]
    same_srv = stats[dst]["services"][service]
    diff_srv = dst_count - same_srv
    same_src_port = stats[dst]["src_ports"][src_port]

    # across all hosts, same service
    total_srv = sum(s[service] for s in (stats[d]["services"] for d in stats))
    diff_host_srv = total_srv - same_srv

    return {
        "dst_host_count": dst_count,
        "dst_host_srv_count": same_srv,
        "dst_host_same_srv_rate": same_srv / dst_count if dst_count > 0 else 0,
        "dst_host_diff_srv_rate": diff_srv / dst_count if dst_count > 0 else 0,
        "dst_host_same_src_port_rate": same_src_port / dst_count if dst_count > 0 else 0,
        "dst_host_srv_diff_host_rate": diff_host_srv / total_srv if total_srv > 0 else 0,
        "dst_host_rerror_rate": 0,  # not implemented
        "dst_host_srv_rerror_rate": 0,  # not implemented
    }

# -------------------
# Neo4j Query
# -------------------
def knowledge_graph(attack_type):
    query = f"""
    MATCH (a:AttackType {{name: '{attack_type}'}})-[:ASSOCIATED_WITH]->(c:CVE)
    RETURN c.id AS cve_id;
    """
    try:
        res = graph.query(query)
        return [record['cve_id'] for record in res]
    except Exception as e:
        print(f"Neo4j Query Failed: {e}")
        return []

# -------------------
# Prediction
# -------------------
def prediction(data):
    try:
        model = joblib.load("XG_model.joblib")

        flag_value = flag_meanings.get(data.get('flag', 'A'), 0)
        protocol_value = protocol_map.get(data.get('protocol_type', 1), 1)
        service_str = service_map.get(data.get('service', 0), "other")

        # TODO: Replace with encoder used in training
        service_encoded = hash(service_str) % 100  

        input_data = [[
            protocol_value, service_encoded, flag_value,
            data.get('src_bytes', 0), data.get('dst_bytes', 0),
            data.get('dst_host_count', 0), data.get('dst_host_srv_count', 0),
            data.get('dst_host_same_srv_rate', 0), data.get('dst_host_diff_srv_rate', 0),
            data.get('dst_host_same_src_port_rate', 0), data.get('dst_host_srv_diff_host_rate', 0),
            data.get('dst_host_rerror_rate', 0), data.get('dst_host_srv_rerror_rate', 0)
        ]]

        pred = model.predict(input_data)[0]
        return label_map.get(int(pred), "Unknown")
    except Exception as e:
        print(f"Prediction Error: {e}")
        return "Error"

# -------------------
# Save Mongo
# -------------------
def save_data(data):
    try:
        collection.insert_one({**data, "date": datetime.datetime.utcnow()})
    except Exception as e:
        print(f"MongoDB Insert Error: {e}")

# -------------------
# Packet Processing
# -------------------
def check_access_attempt(packet):
    data = {"protocol_type": None, "src_ip": None, "dst_ip": None, "flag": None, "service": None}

    if IP in packet:
        data.update({
            "protocol_type": packet[IP].proto,
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst
        })

        if TCP in packet:
            flow = update_flow(packet)
            data.update({
                "flag": str(packet[TCP].flags),
                "src_bytes": flow["src_bytes"],
                "dst_bytes": flow["dst_bytes"],
                "service": packet[TCP].dport,
                "src_port": packet[TCP].sport,
                "dst_port": packet[TCP].dport
            })
        elif UDP in packet:
            flow = update_flow(packet)
            data.update({
                "flag": "UDP",
                "src_bytes": flow["src_bytes"],
                "dst_bytes": flow["dst_bytes"],
                "src_port": packet[UDP].sport,
                "dst_port": packet[UDP].dport,
                "service": packet[UDP].dport
            })
        elif ICMP in packet:
            data.update({
                "flag": "ICMP",
                "src_bytes": len(packet[ICMP].payload),
                "dst_bytes": 0,
                "service": None
            })

    if None in [data["protocol_type"], data["src_ip"], data["dst_ip"], data["flag"], data["service"]]:
        return

    # Update host/service stats
    data.update(update_stats(data))

    # After 30 sec, start prediction
    if time.time() > start + 30:
        try:
            data['predicted'] = prediction(data)
            data['cve_id'] = knowledge_graph(data['predicted'])
        except Exception as e:
            print(f"Prediction/Storage Error: {e}")
            data['predicted'] = "Error"
            data['cve_id'] = []
    else:
        data['predicted'] = "Normal"
        data['cve_id'] = []

    save_data(data)

# -------------------
# Start sniffing
# -------------------
sniff(iface='Wi-Fi', prn=check_access_attempt)
