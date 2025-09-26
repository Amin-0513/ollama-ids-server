from scapy.all import IP, TCP, UDP, ICMP, sniff
import geocoder
import requests
from pymongo import MongoClient
import datetime
from pathlib import Path

class GeographicalInfo:
    def __init__(self):
        # Setup MongoDB client and database
        self.client = MongoClient("mongodb://localhost:27017")
        self.db = self.client.Adtapter_visualization
        self.mylog, self.my_li = geocoder.ip('me').latlng

    ################ MongoDB #######################
    def save_data(self, data):
        try:
            collection = self.db['WiFi']
            doc = {
                "src_ip": data['src_ip'],
                "dst_ip": data['dst_ip'],
                "src_country_name": data['src_CountryName'],
                "des_country_name": data['des_CountryName'],
                "src_latitude": data['src_latitude'],
                "src_longitude": data['src_longitude'],
                "des_latitude": data['des_latitude'],
                "des_longitude": data['des_longitude'],
                "src_city": data['src_city'],
                "des_city": data['des_city'],
                "src_port": data['src_port'],
                "dst_port": data['dst_port'],
                "service": data['service'],
                "date": datetime.datetime.utcnow()
            }
            inserted = collection.insert_one(doc)
            return inserted.inserted_id
        except Exception as e:
            print(f"Error inserting data into MongoDB: {e}")
            return None

    ################ Extracting IP information #######################
    def get_ip_country_info(self, ip):
        dataip = {}
        a = "Private_ip"
        ip_address = ip
        dataC = "-"
        dataLo = 0
        dataLi = 0
        dataci = '-'
        
        try:
            url = f"https://freeipapi.com/api/json/{ip_address}"
            response = requests.get(url).json()
            dataC = response.get('countryName', '-')
            dataLo = response.get('latitude', 0)
            dataLi = response.get('longitude', 0)
            dataci = response.get('cityName', '-')
        except requests.exceptions.RequestException as e:
            print(f"Error retrieving data for IP {ip}: {e}")
            dataC, dataci, dataLo, dataLi = "-", "-", 0, 0
        
        if dataC == '-':
            dataip['countryName'] = a
            dataip['city'] = a
            dataip['latitude'] = self.mylog
            dataip['longitude'] = self.my_li
        else:
            dataip['countryName'] = dataC
            dataip['city'] = dataci
            dataip['latitude'] = dataLo
            dataip['longitude'] = dataLi
        
        return dataip

    ################ Handling Packets #######################
    def check_access_attempt(self, packet):
        data = {}
        
        if IP in packet:
            data['src_ip'] = packet[IP].src
            data['dst_ip'] = packet[IP].dst
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Fetch country info for both source and destination IP
            datai = self.get_ip_country_info(src_ip)
            datai1 = self.get_ip_country_info(dst_ip)
            
            data["src_CountryName"] = datai['countryName']
            data["des_CountryName"] = datai1['countryName']
            data['src_city'] = datai['city']
            data['des_city'] = datai1['city']
            data["src_latitude"] = datai['latitude']
            data["src_longitude"] = datai['longitude']
            data["des_latitude"] = datai1['latitude']
            data["des_longitude"] = datai1['longitude']
            
            if TCP in packet:
                data['flag'] = packet[TCP].flags      
                data['src_port'] = packet[TCP].sport
                data['dst_port'] = packet[TCP].dport
                data['service'] = packet[TCP].dport
            elif UDP in packet:
                data['flag'] = "UDP"
                data['src_port'] = packet[UDP].sport
                data['dst_port'] = packet[UDP].dport
                data['service'] = packet[UDP].dport 
            elif ICMP in packet:
                data['flag'] = "ICMP"
        
        # Save the data
        self.save_data(data)
        return data

# Create an instance of GeographicalInfo
geo_info = GeographicalInfo()

# Start sniffing for packets on the 'Wi-Fi' interface (this will run continuously)
packets = sniff(iface='Wi-Fi', prn=geo_info.check_access_attempt, filter="tcp")

# Extracted data storage
extracted_data = []

# Loop through packets to extract data
for packet in packets:
    extracted_data.append(geo_info.check_access_attempt(packet))

# Print the extracted data
for data in extracted_data:
    print(data)
