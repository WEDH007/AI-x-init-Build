import pandas as pd
import requests
import threading
import time
import os
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw

# Protocol map
protocol_map = {6: 'tcp', 17: 'udp', 1: 'icmp'}

def capture_network_traffic(output_file='captured_network_data.csv'):
    """ Function to capture network traffic and save it to a CSV file """
    columns_order = [
        'ts', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'proto', 'service',
        'duration', 'src_bytes', 'dst_bytes', 'conn_state', 'missed_bytes',
        'src_pkts', 'src_ip_bytes', 'dst_pkts', 'dst_ip_bytes', 'dns_query',
        'dns_qclass', 'dns_qtype', 'dns_rcode', 'dns_AA', 'dns_RD', 'dns_RA',
        'dns_rejected', 'ssl_version', 'ssl_cipher', 'ssl_resumed',
        'ssl_established', 'ssl_subject', 'ssl_issuer', 'http_trans_depth',
        'http_method', 'http_uri', 'http_referrer', 'http_version',
        'http_request_body_len', 'http_response_body_len', 'http_status_code',
        'http_user_agent', 'http_orig_mime_types', 'http_resp_mime_types',
        'weird_name', 'weird_addl', 'weird_notice'
    ]
    df = pd.DataFrame(columns=columns_order)
    default_values = {column: '-' for column in columns_order}
    default_values.update({
        'ts': lambda: time.time(),
        'duration': 0, 'src_bytes': 0, 'dst_bytes': 0,
        'missed_bytes': 0, 'src_pkts': 0, 'src_ip_bytes': 0,
        'dst_pkts': 0, 'dst_ip_bytes': 0, 'http_request_body_len': 0, 'http_response_body_len': 0
    })

    def packet_callback(packet):
        """ Process each packet """
        row = {key: default_values[key]() if callable(default_values[key]) else default_values[key] for key in columns_order}
        if IP in packet:
            row['src_ip'] = packet[IP].src
            row['dst_ip'] = packet[IP].dst
            row['proto'] = protocol_map.get(packet[IP].proto, str(packet[IP].proto))
        row.update(parse_dns(packet))
        row.update(parse_http(packet))
        
        nonlocal df
        df = pd.concat([df, pd.DataFrame([row])], ignore_index=True)
        if len(df) >= 100:  # Save every 100 packets to limit I/O operations
            df.to_csv(output_file, mode='a', header=not os.path.exists(output_file), index=False)
            df.drop(df.index, inplace=True)

    sniff(prn=packet_callback, store=0)

def parse_dns(packet):
    """ Parse DNS fields from packet if present """
    if DNS in packet:
        return {
            'service': 'dns',
            'dns_query': packet[DNSQR].qname.decode() if DNSQR in packet else '-',
            'dns_qclass': packet[DNSQR].qclass if DNSQR in packet else '-',
            'dns_qtype': packet[DNSQR].qtype if DNSQR in packet else '-',
            'dns_rcode': packet[DNS].rcode,
            'dns_AA': 'T' if packet[DNS].aa else 'F',
            'dns_RD': 'T' if packet[DNS].rd else 'F',
            'dns_RA': 'T' if packet[DNS].ra else 'F',
            'dns_rejected': 'T' if packet[DNS].rcode != 0 else 'F'
        }
    return {}

def parse_http(packet):
    """ Attempt to extract HTTP data from packet payload """
    if Raw in packet:
        payload = bytes(packet[Raw]).decode('iso-8859-1', errors='ignore')
        if "HTTP" in payload:
            lines = payload.split('\r\n')
            first_line = lines[0].split()
            if len(first_line) == 3:
                return {
                    'service': 'http',
                    'http_method': first_line[0],
                    'http_uri': first_line[1],
                    'http_version': first_line[2],
                    'http_referrer': next((line.split(": ", 1)[1] for line in lines if line.lower().startswith('referrer: ')), '-')
                }
    return {}

def send_data():
    """ Function to send data every 30 seconds """
    url = "http://127.0.0.1:8000/detect-attacks/"
    while True:
        time.sleep(10)
        try:
            with open('captured_network_data.csv', 'rb') as f:
                files = {'file': ('captured_network_data.csv', f, 'text/csv')}
                response = requests.post(url, files=files)
                print(response.text)
        except Exception as e:
            print(f"Failed to send data: {e}")

if __name__ == "__main__":
    # Thread for capturing network traffic
    capture_thread = threading.Thread(target=capture_network_traffic)
    capture_thread.start()

    # Thread for sending the data
    send_thread = threading.Thread(target=send_data)
    send_thread.start()
