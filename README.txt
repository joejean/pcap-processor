
To Maka This Work:
1) Install Elasticsearch (https://www.elastic.co/downloads/elasticsearch)
2) Install Kibana (https://www.elastic.co/downloads/kibana)
NOTE: Please make sure both of those are running properly before proceeding. 
3) Create a directory with a name of your choice
4) Add the pcap_parser/ directory to the directory you created in step 3
4.1) From Within the pcap_parser directory type: pip install -r requirements.txt
5) cd to the directory created in step 3
4) type: python parser/watch_ directory
5) Add a new pcap file in the directory created in step 3 
6) If everything went well, you will see a nice message (instead of an error) in your terminal saying that the new pcap is detected and will be processed.

7) Go to http://localhost:5601/app/kibana
8) Add 'crissp' as the new index

