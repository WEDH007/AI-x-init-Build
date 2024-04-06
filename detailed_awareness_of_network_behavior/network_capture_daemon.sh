#!/bin/bash

while true; do
    # Define variables
    LOG_FILE="/root/AI-x-init-Build/detailed_awareness_of_network_behavior/captured_traffic.pcap"
    CSV_FILE="/root/AI-x-init-Build/detailed_awareness_of_network_behavior/captured_traffic.csv"
    API_ENDPOINT="http://127.0.0.1:8000/detect-attacks"

    # Extract necessary fields from Zeek logs into a CSV format
    zeek-cut -d -F ts id.orig_h id.orig_p id.resp_h id.resp_p proto service \
        orig_bytes resp_bytes conn_state missed_bytes orig_pkts orig_ip_bytes \
        resp_pkts resp_ip_bytes query qclass qtype rcode AA RD RA rejected \
        version cipher resumed established subject issuer trans_depth method \
        uri version request_body_len response_body_len status_code user_agent \
        orig_mime_types resp_mime_types weird_name weird_addl weird_notice \
        < $LOG_FILE/*.log > $CSV_FILE

    # Send CSV data to API
    curl -X POST -F "file=@$CSV_FILE" $API_ENDPOINT

    # Clean up
    rm $CSV_FILE

    # Sleep for a minute
    sleep 60
done
