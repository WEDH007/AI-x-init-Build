import subprocess
import requests
import time
import os
import pandas as pd

while True:
    # Define variables
    CAPTURE_FILE = "/root/AI-x-init-Build/detailed_awareness_of_network_behavior/captured_traffic.pcap"
    CSV_FILE = "/root/AI-x-init-Build/detailed_awareness_of_network_behavior/captured_traffic.csv"
    API_ENDPOINT = "http://127.0.0.1:8000/detect-attacks"

    # Capture network traffic
    subprocess.run(["tcpdump", "-i", "eth0", "-w", CAPTURE_FILE, "-c", "60"])

    # Convert captured traffic to CSV
    tshark_command = [
        "tshark", "-r", CAPTURE_FILE, "-T", "fields",
        "-e", "frame.time_epoch",            # ts
        "-e", "ip.src",                     # src_ip
        "-e", "tcp.srcport",                # src_port
        "-e", "ip.dst",                     # dst_ip
        "-e", "tcp.dstport",                # dst_port
        "-e", "ip.proto",                   # proto
        "-e", "col.service",                # service
        "-e", "col.duration",               # duration
        "-e", "tcp.len",                    # src_bytes
        "-e", "ip.len",                     # dst_bytes
        "-e", "col.conn_state",             # conn_state
        "-e", "col.missed_bytes",           # missed_bytes
        "-e", "col.src_pkts",               # src_pkts
        "-e", "tcp.src_ip_bytes",           # src_ip_bytes
        "-e", "col.dst_pkts",               # dst_pkts
        "-e", "tcp.dst_ip_bytes",           # dst_ip_bytes
        "-e", "dns.qry.name",               # dns_query
        "-e", "dns.qry.class",              # dns_qclass
        "-e", "dns.qry.type",               # dns_qtype
        "-e", "dns.rcode",                  # dns_rcode
        "-e", "dns.flags.aa",               # dns_AA
        "-e", "dns.flags.rd",               # dns_RD
        "-e", "dns.flags.ra",               # dns_RA
        "-e", "dns.flags.rejected",         # dns_rejected
        "-e", "ssl.handshake.version",      # ssl_version
        "-e", "ssl.handshake.ciphersuite",  # ssl_cipher
        "-e", "ssl.connection.resumed",     # ssl_resumed
        "-e", "ssl.connection.established", # ssl_established
        "-e", "ssl.handshake.cert_subject", # ssl_subject
        "-e", "ssl.handshake.cert_issuer",  # ssl_issuer
        "-e", "http.trans_depth",           # http_trans_depth
        "-e", "http.request.method",        # http_method
        "-e", "http.request.uri",           # http_uri
        "-e", "http.request.referrer",      # http_referrer
        "-e", "http.request.version",       # http_version
        "-e", "http.request.body_len",      # http_request_body_len
        "-e", "http.response.body_len",     # http_response_body_len
        "-e", "http.response.code",         # http_status_code
        "-e", "http.user_agent",            # http_user_agent
        "-e", "http.content_type",          # http_orig_mime_types
        "-e", "http.content_type",          # http_resp_mime_types
        "-e", "weird.name",                 # weird_name
        "-e", "weird.addl",                 # weird_addl
        "-e", "weird.notice",               # weird_notice
        "-E", "header=y", "-E", "separator=,"
    ]

    # Execute tshark command and write output to CSV
    with open(CSV_FILE, "w") as csv_output:
        subprocess.run(tshark_command, stdout=csv_output)

    # Rename columns using pandas to match the specified field names
    df = pd.read_csv(CSV_FILE)
    column_names = [
        "ts", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "service", "duration",
        "src_bytes", "dst_bytes", "conn_state", "missed_bytes", "src_pkts", "src_ip_bytes",
        "dst_pkts", "dst_ip_bytes", "dns_query", "dns_qclass", "dns_qtype", "dns_rcode",
        "dns_AA", "dns_RD", "dns_RA", "dns_rejected", "ssl_version", "ssl_cipher",
        "ssl_resumed", "ssl_established", "ssl_subject", "ssl_issuer", "http_trans_depth",
        "http_method", "http_uri", "http_referrer", "http_version", "http_request_body_len",
        "http_response_body_len", "http_status_code", "http_user_agent", "http_orig_mime_types",
        "http_resp_mime_types", "weird_name", "weird_addl", "weird_notice"
    ]
    df.columns = column_names

    # Save modified CSV
    df.to_csv(CSV_FILE, index=False)

    # Send CSV data to API
    with open(CSV_FILE, "rb") as f:
        files = {"file": f}
        response = requests.post(API_ENDPOINT, files=files)

    # Clean up
    os.remove(CAPTURE_FILE)
    os.remove(CSV_FILE)

    # Sleep for a minute
    time.sleep(60)
