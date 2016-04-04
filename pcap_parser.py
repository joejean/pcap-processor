from datetime import datetime
import pyshark
import geoip2.database
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk


def initialize_es_index(es, index):
    if not es.indices.exists(index=index):
        mapping = {
            "mappings": {
                            "packet": {
                              "properties": {
                                "frame_arrival_time": {
                                    "type": "date",
                                    "format": "date_optional_time",
                                },
                                "source_ip" :{
                                    "type": "string"
                                },
                                "dest_geo":{
                                    "type": "geo_point"
                                },
                                "location":{
                                   "type": "geo_point"
                                    
                                },
                                "transport_layer":{
                                    "type": "string"
                                },
                                "source_ip":{
                                    "type": "string"
                                },
                                "destination_ip" :{
                                    "type": "string"
                                },
                                "source_port":{
                                    "type": "string"
                                },
                                "destination_port":{
                                    "type": "string"
                                }
                              }
                            }
                        }
        }
        res = es.indices.create(index,ignore=400,body=mapping)
        print(res)
    else:
        print("The ElasticSearch INDEX {} already exists. We will just update\
         it with the new data.".format(index))


def get_ipgeo(ip):
    """This function gets an ip address and return it's location info"""
    reader = geoip2.database.Reader("GeoLite2-City.mmdb")
    try:
        response = reader.city(ip)
    except:
        response = {}
    return response


def process_packet(es, es_index_name, pcap, buffer_size):
    src_ip = dest_ip = "0.0.0.0"
    src_port = dest_port = 0
    src_geo = dest_geo = {}
    packet_buffer = []
    
    for packet in pcap:
        packet_dict = {}
        layers = [l.layer_name for l in packet.layers]
        if "ip" in layers:
            src_ip = packet.ip.src
            src_geo = get_ipgeo(src_ip)
            dest_ip = packet.ip.dst
            dest_geo = get_ipgeo(dest_ip)
        if 'tcp' in layers:
            src_port = packet.tcp.port
            dest_port = packet.tcp.dstport
            #[float(src_geo.location.latitude),\
            #float(src_geo.location.longitude)]
        if src_geo:
            if src_geo.location.latitude is not None and src_geo.location.longitude is not None:
                packet_dict.update({
                    "location" : {
                    "lat": src_geo.location.latitude,
                    "lon": src_geo.location.longitude
                    }
                })
        
        packet_dict.update({
            "_index": es_index_name,
            "_type": 'packet',
            "source_ip": src_ip,
            "destination_ip" : dest_ip,
            "source_port": src_port,
            "destination_port": dest_port,
            "frame_arrival_time": str((datetime.fromtimestamp(float(packet.frame_info.time_epoch))).isoformat()),
            "frame_length" : packet.frame_info.len,
            "protocols": [(packet.frame_info.protocols).split(":")],
            "transport_layer": packet.transport_layer
            })

        packet_buffer.append(packet_dict)

        if len(packet_buffer) == buffer_size:
            res = bulk(es, actions=packet_buffer, stats_only=True)
            packet_buffer = []
            break

#This function is the main entry point of the program
def process_pcap_file(pcap_file_path="/home/joe/Documents/CRISSP/big.pcap"):
    ES_INDEX = "crissp" 
    BUFFER_SIZE = 1000
    es = Elasticsearch()
    pcap = pyshark.FileCapture(pcap_file_path, keep_packets=False)
    initialize_es_index(es, ES_INDEX)
    process_packet(es, ES_INDEX, pcap, BUFFER_SIZE)
    print("SUCCESS: Processing of {} is done!".format(pcap_file_path))

if __name__ == "__main__":
    process_pcap_file()

    





    


