import pandas as pd
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw
import time

# Define the output CSV file
output_file = 'captured_network_data.csv'

# List of all columns in the specified order
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

# Initialize a DataFrame with the specified columns and default values
df = pd.DataFrame(columns=columns_order)
default_values = {
    'ts': lambda: time.time(),
    'src_ip': '-', 'src_port': '-', 'dst_ip': '-', 'dst_port': '-', 
    'proto': '-', 'service': '-', 'conn_state': '-',
    'duration': 0, 'src_bytes': 0, 'dst_bytes': 0, 
    'missed_bytes': 0, 'src_pkts': 0, 'src_ip_bytes': 0, 
    'dst_pkts': 0, 'dst_ip_bytes': 0, 'dns_query': '-', 
    'dns_qclass': '-', 'dns_qtype': '-', 'dns_rcode': '-', 
    'dns_AA': '-', 'dns_RD': '-', 'dns_RA': '-', 
    'dns_rejected': '-', 'ssl_version': '-', 'ssl_cipher': '-', 
    'ssl_resumed': '-', 'ssl_established': '-', 'ssl_subject': '-', 
    'ssl_issuer': '-', 'http_trans_depth': '-', 'http_method': '-', 
    'http_uri': '-', 'http_referrer': '-', 'http_version': '-', 
    'http_request_body_len': 0, 'http_response_body_len': 0, 'http_status_code': '-', 
    'http_user_agent': '-', 'http_orig_mime_types': '-', 'http_resp_mime_types': '-', 
    'weird_name': '-', 'weird_addl': '-', 'weird_notice': '-'
}

# Protocol map for translating protocol numbers to names
protocol_map = {
    6: 'tcp',  # TCP
    17: 'udp',  # UDP
    1: 'icmp',  # ICMP
}

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

def packet_callback(packet):
    """ Callback function to process each packet """
    row = {key: default_values[key]() if callable(default_values[key]) else default_values[key] for key in columns_order}
    
    # Basic IP and transport layer data
    if IP in packet:
        row['src_ip'] = packet[IP].src
        row['dst_ip'] = packet[IP].dst
        proto = packet[IP].proto
        row['proto'] = protocol_map.get(proto, str(proto))  # Use the mapping

    # DNS and HTTP data
    row.update(parse_dns(packet))
    row.update(parse_http(packet))

    # Append row to DataFrame and check capture limit
    global df
    df = pd.concat([df, pd.DataFrame([row])], ignore_index=True)
    if len(df) >= 25:  # Capture limit for demonstration
        df.to_csv(output_file, index=False)
        print(f"Capture complete. Data saved to '{output_file}'.")
        quit()

# Start packet capture
print("Starting packet capture...")
sniff(prn=packet_callback, store=0)
