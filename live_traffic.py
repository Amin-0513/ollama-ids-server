from scapy.all import IP, TCP, UDP, ICMP, sniff
import ipaddress
import geocoder
import requests
from pathlib import Path
from pymongo import MongoClient
import datetime
#mongodb+srv://amin:BBrXLIN1VzqF1H38@atlascluster.syhusk7.mongodb.net/
client=MongoClient("mongodb://localhost:27017")
db=client.Adtapter_visualization
mylog=0
my_li=0
g = geocoder.ip('me')
mylog, my_li = g.latlng
################ Mango DB #######################
def save_data(data):
    collection=db['WiFi']
    doc={
        "src_ip": data['src_ip'],
        "dst_ip" : data['dst_ip'],
        "src_country_name" : data['src_CountryName'],
        "des_country_name" : data['des_CountryName'],
        "src_latitude" : data['src_latitude'],
        "src_longitude" : data['src_longitude'],
        "des_latitude" : data['des_latitude'],
        "des_longitude" : data['des_longitude'],
        "src_city" : data['src_city'],
        "des_city" : data['des_city'],
        #"flag" : data['flag'],
        "src_port" : data['src_port'],
        "dst_port" : data['dst_port'],
        "service" :data['service'],
        "date":datetime.datetime.utcnow()
    }
    inserted=collection.insert_one(doc)
    return inserted.inserted_id

################ Extracting IP information #######################
def get_ip_country_info(ip):
    dataip={}
    a="Private_ip"
    ip_address=ip
    dataC="-"
    dataLo=0
    dataLi=0
    dataci='-'
    url = f"https://freeipapi.com/api/json/{ip_address}"
    response = requests.get(url).json()
    dataC = response['countryName']
    dataLo = response['latitude']
    dataLi = response['longitude']
    dataci=response['cityName']
    if dataC=='-':
        dataip['countryName']=a
        dataip['city']=a
        dataip['latitude']=mylog
        dataip['longitude']=my_li
    else:
        dataip['countryName']=dataC
        dataip['city']=dataci
        dataip['latitude']=dataLo
        dataip['longitude']=dataLi
    return dataip
    
    

def check_access_attempt(packet):
    pattern = r'\((.*?)\)'
    data = {}
    datai={}
    datai1={}
    if IP in packet:
        data['src_ip'] = packet[IP].src
        data['dst_ip'] = packet[IP].dst
        a=packet[IP].src
        b=packet[IP].dst
        datai=get_ip_country_info(a)
        datai1=get_ip_country_info(b)
        data["src_CountryName"]=datai['countryName']
        data["des_CountryName"]=datai1['countryName']
        data['src_city']=datai['city']
        data['des_city']=datai1['city']
        data["src_latitude"]=datai['latitude']
        data["src_longitude"]=datai['longitude']
        data["des_latitude"]=datai1['latitude']
        data["des_longitude"]=datai1['longitude']
        if TCP in packet:
            data['flag'] = packet[TCP].flags      
            data['src_port'] = packet[TCP].sport
            data['dst_port'] = packet[TCP].dport
            data['service'] = packet[TCP].dport
            #print(f"Incoming TCP connection attempt from {data['src_ip']}:{data['src_port']} to {data['dst_ip']}:{data['dst_port']}")
        elif UDP in packet:
            data['flag'] = "UDP"
            data['src_port'] = packet[UDP].sport
            data['dst_port'] = packet[UDP].dport
            data['service'] = packet[TCP].dport 
            #print(f"Incoming UDP connection attempt from {data['src_ip']}:{data['src_port']} to {data['dst_ip']}:{data['dst_port']}")
        elif ICMP in packet:
            data['flag'] = "ICMP"
            #print(f"Incoming ICMP packet from {data['src_ip']} to {data['dst_ip']}")
    save_data(data)
    return data

# Start sniffing for TCP packets on the specified interface

packets = sniff(iface='Wi-Fi', prn=check_access_attempt, filter="tcp")

extracted_data = []

for packet in packets:
    
    extracted_data.append(check_access_attempt(packet))

# Print the extracted data
for data in extracted_data:
    print(data)
