import subprocess
import requests
import time
import os

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
        "-e", "frame.time", "-e", "ip.src", "-e", "tcp.srcport", "-e", "ip.dst",
        "-e", "tcp.dstport", "-e", "_ws.col.Protocol", "-e", "_ws.col.Info",
        "-e", "tcp.len", "-e", "tcp.analysis.bytes_in_flight", "-e", "tcp.analysis.lost_segment",
        "-e", "tcp.analysis.retransmission", "-e", "tcp.analysis.duplicate_ack",
        "-e", "tcp.analysis.fast_retransmission", "-e", "tcp.analysis.out_of_order",
        "-e", "tcp.analysis.window_full", "-e", "tcp.analysis.window_update",
        "-e", "tcp.analysis.zero_window", "-e", "tcp.analysis.zero_window_probe",
        "-e", "tcp.analysis.zero_window_probe_ack", "-e", "ip.ttl", "-e", "tcp.window_size",
        "-e", "tcp.window_size_scalefactor", "-e", "tcp.flags.fin", "-e", "tcp.flags.syn",
        "-e", "tcp.flags.ack", "-e", "tcp.flags.reset", "-e", "tcp.flags.push",
        "-e", "tcp.flags.urg", "-e", "tcp.flags.cwr", "-e", "tcp.analysis.initial_rtt",
        "-e", "ip.len", "-e", "ip.flags.mf", "-e", "ip.flags.df", "-e", "ip.flags.rb",
        "-e", "ip.frag_offset", "-e", "ip.dsfield", "-e", "tcp.stream", "-e", "udp.stream",
        "-e", "frame.number", "-e", "dns.qry.name", "-e", "dns.qry.type",
        "-e", "dns.flags.response", "-e", "dns.flags.rcode", "-e", "dns.a",
        "-e", "dns.aaaa", "-e", "dns.cname", "-e", "dns.resp.name", "-e", "dns.resp.type",
        "-e", "dns.resp.class", "-e", "dns.resp.ttl", "-e", "dns.count.queries",
        "-e", "dns.count.answers", "-e", "dns.count.auth_rr", "-e", "dns.count.add_rr",
        "-e", "ssl.handshake.version", "-e", "ssl.handshake.ciphersuite",
        "-e", "ssl.record.content_type", "-e", "ssl.handshake.cert_type",
        "-e", "http.request.version", "-e", "http.request.method", "-e", "http.request.uri",
        "-e", "http.request_in", "-e", "http.request.full_uri", "-e", "http.response.version",
        "-e", "http.response.code", "-e", "http.user_agent", "-e", "http.content_type",
        "-e", "http.response_in", "-e", "http.content_length", "-E", "header=y", "-E", "separator=,"
    ]
    
    with open(CSV_FILE, "w") as csv_output:
        subprocess.run(tshark_command, stdout=csv_output)

    # Send CSV data to API
    files = {"file": open(CSV_FILE, "rb")}
    response = requests.post(API_ENDPOINT, files=files)

    # Clean up
    os.remove(CAPTURE_FILE)
    os.remove(CSV_FILE)

    # Sleep for a minute
    time.sleep(60)
