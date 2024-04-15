import subprocess
import time
import csv
import zeek 


def run_zeek():
    # Command to start Zeek on interface eth0 with specific script settings
    zeek_process = subprocess.Popen(['zeek', '-C', '-i', 'eth0', '--exec', 'event zeek_init() { Log::disable_stream(Connection::LOG); }'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return zeek_process

def map_fields(zeek_data):
    # Field mapping from Zeek log names to desired CSV column names
    field_mapping = {
        'ts': 'ts', 'id.orig_h': 'src_ip', 'id.orig_p': 'src_port',
        'id.resp_h': 'dst_ip', 'id.resp_p': 'dst_port', 'proto': 'proto',
        'service': 'service', 'duration': 'duration', 'orig_bytes': 'src_bytes',
        'resp_bytes': 'dst_bytes', 'conn_state': 'conn_state', 'missed_bytes': 'missed_bytes',
        'orig_pkts': 'src_pkts', 'orig_ip_bytes': 'src_ip_bytes', 'resp_pkts': 'dst_pkts',
        'resp_ip_bytes': 'dst_ip_bytes', 'query': 'dns_query', 'qclass_name': 'dns_qclass',
        'qtype_name': 'dns_qtype', 'rcode_name': 'dns_rcode', 'AA': 'dns_AA', 'RD': 'dns_RD',
        'RA': 'dns_RA', 'rejected': 'dns_rejected', 'version': 'ssl_version', 'cipher': 'ssl_cipher',
        'resumed': 'ssl_resumed', 'established': 'ssl_established', 'certificate.subject': 'ssl_subject',
        'certificate.issuer': 'ssl_issuer', 'trans_depth': 'http_trans_depth', 'method': 'http_method',
        'host': 'http_uri', 'referrer': 'http_referrer', 'version': 'http_version',
        'request_body_len': 'http_request_body_len', 'response_body_len': 'http_response_body_len',
        'status_code': 'http_status_code', 'user_agent': 'http_user_agent', 'orig_mime_types': 'http_orig_mime_types',
        'resp_mime_types': 'http_resp_mime_types', 'name': 'weird_name', 'addl': 'weird_addl', 'notice': 'weird_notice'
    }

    # Map the fields according to the dictionary
    mapped_data = {new_key: zeek_data.get(old_key) for old_key, new_key in field_mapping.items() if old_key in zeek_data}
    return mapped_data

def write_csv(data):
    # Write the mapped data to a CSV file
    with open('network_data.csv', 'a', newline='') as csvfile:
        fieldnames = data.keys()
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        if csvfile.tell() == 0:  # Write header only if file is empty
            writer.writeheader()
        writer.writerow(data)

def main():
    zeek_output_fields = [
        'ts', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'service',
        'duration', 'orig_bytes', 'resp_bytes', 'conn_state', 'missed_bytes', 'orig_pkts', 'orig_ip_bytes',
        'resp_pkts', 'resp_ip_bytes', 'query', 'qclass_name', 'qtype_name', 'rcode_name', 'AA', 'RD', 'RA',
        'rejected', 'version', 'cipher', 'resumed', 'established', 'certificate.subject', 'certificate.issuer',
        'trans_depth', 'method', 'host', 'referrer', 'version', 'request_body_len', 'response_body_len',
        'status_code', 'user_agent', 'orig_mime_types', 'resp_mime_types', 'name', 'addl', 'notice'
    ]

    zeek = run_zeek()
    try:
        while True:
            zeek_output = zeek.stdout.readline().decode().strip().split()
            if zeek_output:
                data = map_fields(dict(zip(zeek_output_fields, zeek_output)))
                write_csv(data)
            time.sleep(30)
    finally:
        zeek.terminate()

if __name__ == '__main__':
    main()
