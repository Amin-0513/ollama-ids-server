from flask import Flask, jsonify, request
from pymongo import MongoClient
import geocoder
from flask_cors import CORS
from bson.objectid import ObjectId
import requests

app = Flask(__name__)
# Allow CORS for all /api/* endpoints (change origins to specific host in prod)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# MongoDB connection
client = MongoClient('mongodb://localhost:27017')
db = client['Adtapter_visualization']
collection = db['WiFi']
collection2 = db['newdataset']
collection3 = db['CVE_predictor']

# Get location information
g = geocoder.ip('me')
if g and getattr(g, "latlng", None):
    my_lat, my_lng = g.latlng  # lat, lng
else:
    # sensible defaults (floats) to avoid nulls reaching the frontend/Leaflet
    my_lat, my_lng = 0.0, 0.0
    app.logger.warning("Unable to retrieve latitude/longitude via geocoder.ip('me'). Using defaults 0.0,0.0.")


def get_cvss_score(cve_id, timeout=5):
    """Return cvss3 or cvss2 if found, otherwise an explanatory string."""
    try:
        url = f"https://cve.circl.lu/api/cve/{cve_id}"
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            return data.get('cvss3') or data.get('cvss2') or "No CVSS score available"
        return f"Error: Unable to fetch data (status: {resp.status_code})"
    except Exception as e:
        return f"Exception occurred: {str(e)}"


def get_ip_country_info(ip, timeout=5):
    """
    Query freeipapi for IP info. Return fallback values on error.
    Note: freeipapi has usage limits - add error handling.
    """
    try:
        resp = requests.get(f"https://freeipapi.com/api/json/{ip}", timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            return {
                'countryName': data.get('countryName') or 'Private_ip',
                'city': data.get('cityName') or 'Private_ip',
                'latitude': data.get('latitude', my_lat),
                'longitude': data.get('longitude', my_lng),
            }
        else:
            app.logger.debug(f"freeipapi returned status {resp.status_code} for ip {ip}")
            return {'countryName': 'Private_ip', 'city': 'Private_ip', 'latitude': my_lat, 'longitude': my_lng}
    except Exception as e:
        app.logger.debug(f"Exception while calling freeipapi for {ip}: {e}")
        return {'countryName': 'Private_ip', 'city': 'Private_ip', 'latitude': my_lat, 'longitude': my_lng}


@app.route('/api/data', methods=['GET'])
def get_data():
    docs = list(collection.find({}))
    json_data = []
    for item in docs:
        json_data.append({
            'id': str(item.get('_id')),
            'src_ip': item.get('src_ip', ''),
            'dst_ip': item.get('dst_ip', ''),
            'src_country_name': item.get('src_country_name', '') or 'Unknown',
            'des_country_name': item.get('des_country_name', '') or 'Unknown',
            'src_latitude': float(item.get('src_latitude') or 0.0),
            'src_longitude': float(item.get('src_longitude') or 0.0),
            'des_latitude': float(item.get('des_latitude') or 0.0),
            'des_longitude': float(item.get('des_longitude') or 0.0),
            'src_port': item.get('src_port', ''),
            'dst_port': item.get('dst_port', ''),
            'service': item.get('service', ''),
            'date': item.get('date', ''),
            'prediction': item.get('prediction', ''),
            'src_city': item.get('src_city', '') or 'Unknown',
            'des_city': item.get('des_city', '') or 'Unknown',
        })
    return jsonify(json_data), 200


@app.route('/api/data33/', methods=['GET'])
def get_data3():
    docs = collection3.find()
    json_data = []
    # sample fixed coordinates (you can change as needed)
    src_location = {'countryName': 'Singapore', 'city': 'Singapore', 'latitude': 1.289987, 'longitude': 103.850281}
    dst_location = {'countryName': 'Private_ip', 'city': 'Private_ip', 'latitude': 33.5973, 'longitude': 73.0479}

    for item in docs:
        json_data.append({
            'id': str(item.get('_id')),
            'protocol_type': item.get('protocol_type', ''),
            'src_ip': item.get('src_ip', ''),
            'dst_ip': item.get('dst_ip', ''),
            'src_port': item.get('src_port', ''),
            'dst_port': item.get('dst_port', ''),
            'service': item.get('service', ''),
            'src_bytes': item.get('src_bytes', 0),
            'dst_bytes': item.get('dst_bytes', 0),
            'dst_host_diff_srv_rate': item.get('dst_host_diff_srv_rate', 0),
            'flag': item.get('flag', ''),
            'dst_host_srv_diff_host_rate': item.get('dst_host_srv_diff_host_rate', 0),
            'dst_host_srv_count': item.get('dst_host_srv_count', 0),
            'dst_host_same_src_port_rate': item.get('dst_host_same_src_port_rate', 0),
            'dst_host_same_srv_rate': item.get('dst_host_same_srv_rate', 0),
            'dst_host_count': item.get('dst_host_count', 0),
            'prediction': item.get('prediction', ''),
            'cve_id': item.get('cve_id', ''),
            'src_long': src_location['longitude'],
            'src_lati': src_location['latitude'],
            'dst_long': dst_location['longitude'],
            'dst_lati': dst_location['latitude'],
            'src_country': src_location['countryName'],
            'src_city': src_location['city'],
            'dst_country': dst_location['countryName'],
            'dst_city': dst_location['city'],
            'date': item.get('date', ''),
        })
    return jsonify(json_data), 200


@app.route('/api/data2/<id>', methods=['GET'])
def get_data_by_id(id):
    # Validate ObjectId
    try:
        object_id = ObjectId(id)
    except Exception as e:
        return jsonify({"error": "Invalid ID format", "details": str(e)}), 400

    data = collection3.find_one({'_id': object_id})
    if not data:
        return jsonify({"error": "Record not found"}), 404

    attack_type = str(data.get('prediction', '')).strip()
    external_url = f"http://127.0.0.1:8000/{attack_type}" if attack_type else None

    description = "No description available"
    if external_url:
        try:
            resp = requests.get(external_url, timeout=5)
            if resp.status_code == 200:
                description = resp.text
            else:
                description = f"Error retrieving data (status {resp.status_code})"
        except Exception as e:
            description = f"External API request failed: {str(e)}"
    else:
        description = "No attack type provided"

    src_location = {'countryName': 'Singapore', 'city': 'Singapore', 'latitude': 1.289987, 'longitude': 103.850281}
    dst_location = {'countryName': 'Private_ip', 'city': 'Private_ip', 'latitude': 33.5973, 'longitude': 73.0479}

    json_data = {
        'id': str(data.get('_id')),
        'protocol_type': data.get('protocol_type', ''),
        'src_ip': data.get('src_ip', ''),
        'dst_ip': data.get('dst_ip', ''),
        'src_port': data.get('src_port', ''),
        'dst_port': data.get('dst_port', ''),
        'service': data.get('service', ''),
        'src_bytes': data.get('src_bytes', 0),
        'dst_bytes': data.get('dst_bytes', 0),
        'dst_host_diff_srv_rate': data.get('dst_host_diff_srv_rate', 0),
        'flag': data.get('flag', ''),
        'dst_host_srv_diff_host_rate': data.get('dst_host_srv_diff_host_rate', 0),
        'dst_host_srv_count': data.get('dst_host_srv_count', 0),
        'dst_host_same_src_port_rate': data.get('dst_host_same_src_port_rate', 0),
        'dst_host_same_srv_rate': data.get('dst_host_same_srv_rate', 0),
        'dst_host_count': data.get('dst_host_count', 0),
        'prediction': data.get('prediction', ''),
        'cve_id': data.get('cve_id', ''),
        'src_long': src_location['longitude'],
        'src_lati': src_location['latitude'],
        'dst_long': dst_location['longitude'],
        'dst_lati': dst_location['latitude'],
        'src_country': src_location['countryName'],
        'src_city': src_location['city'],
        'dst_country': dst_location['countryName'],
        'dst_city': dst_location['city'],
        'date': data.get('date', ''),
        'description': description
    }

    return jsonify(json_data), 200


@app.route('/api/distant_cities', methods=['GET'])
def get_distant_cities():
    distincts = collection.distinct("src_country_name")
    safe_keys = [(k if k is not None else "Unknown") for k in distincts]
    city_counts = {city: collection.count_documents({"src_country_name": city}) for city in safe_keys}
    return jsonify(city_counts), 200


@app.route('/api/distant_country', methods=['GET'])
def get_distant_country():
    distincts = collection.distinct("des_country_name")
    safe_keys = [(k if k is not None else "Unknown") for k in distincts]
    country_counts = {country: collection.count_documents({"des_country_name": country}) for country in safe_keys}
    return jsonify(country_counts), 200


def count_predictions(prediction_type):
    return jsonify({'count': collection2.count_documents({'prediction': prediction_type})}), 200


@app.route('/api/predictions/count_normal', methods=['GET'])
def count_normal_predictions():
    return count_predictions('Normal')


@app.route('/api/predictions/count_ddos', methods=['GET'])
def count_ddos_predictions():
    return count_predictions('DDos')


@app.route('/api/predictions/count_u2l', methods=['GET'])
def count_u2l_predictions():
    return count_predictions('U2L')


@app.route('/api/predictions/count_r2l', methods=['GET'])
def count_r2l_predictions():
    return count_predictions('R2L')


@app.route('/api/predictions/count_probe', methods=['GET'])
def count_probe_predictions():
    return count_predictions('Probe')


if __name__ == '__main__':
    # Run on port 5000 to match front-end calls to http://127.0.0.1:5000
    app.run(host='0.0.0.0', port=5000, debug=True)
