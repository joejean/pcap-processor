import pyshark
from pymongo import MongoClient

client = MongoClient()

db = client.networkData

cap = pyshark.FileCapture("/home/joe/Documents/CRISSP/big.pcap", keep_packets=False)
src_ip = dest_ip = "0.0.0.0"
src_port = dest_port = 0

for packet in cap:
    layers = [l.layer_name for l in packet.layers]
    if "ip" in layers:
        src_ip = packet.ip.src
        dest_ip = packet.ip.dst
    if 'tcp' in layers:
        src_port = packet.tcp.port
        dest_port = packet.tcp.dstport
    frame_arrival_time = packet.frame_info.time
    frame_length = packet.frame_info.len
    protocols = packet.frame_info.protocols 
    transport_layer = packet.transport_layer

    result = db.packets.insert_one({
        "source_ip": src_ip,
        "destination_ip" : dest_ip,
        "source_port": src_port,
        "destination_port": dest_port,
        "frame_arrival_time": frame_arrival_time,
        "frame_length" : frame_length,
        "protocols": [protocols.split(":")],
        "transport_layer": transport_layer
        })

print("DONE")

    


