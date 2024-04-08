import pyshark

    LOG_FILE="/opt/zeek/logs/current/"
    CSV_FILE="/root/AI-x-init-Build/detailed_awareness_of_network_behavior/captured_traffic.csv"
    API_ENDPOINT="http://127.0.0.1:8000/detect-attacks"


import csv
import requests
import time

# API endpoint URL for model serving framework
API_ENDPOINT = "http://localhost:8501/upload_csv"  # Example URL, replace with your actual endpoint

# Function to send CSV file to the API endpoint
def send_csv_to_api(csv_filename):
    try:
        # Open the CSV file and prepare it for uploading
        with open(csv_filename, 'rb') as file:
            # Send a POST request with the CSV file
            response = requests.post(API_ENDPOINT, files={'file': file})
            if response.status_code == 200:
                # Successfully uploaded CSV file
                print("CSV file uploaded successfully")
            else:
                # Failed to upload CSV file, handle error
                print("Error:", response.text)
    except Exception as e:
        # Exception occurred, handle error
        print("Error:", str(e))

# Preprocessing function (example, replace with your actual preprocessing logic)
def preprocess_network_traffic(packet):
    # Extract relevant features from the packet and preprocess them
    # This is a placeholder, replace with your actual preprocessing logic
    data = {
        "source_ip": packet.ip.src,
        "destination_ip": packet.ip.dst,
        "source_port": packet.tcp.srcport if "tcp" in packet else None,
        "destination_port": packet.tcp.dstport if "tcp" in packet else None,
        # Add other relevant features here
    }
    return data

# Function to capture packets using PyShark and save them to a CSV file
def capture_and_save_packets(interface="eth0", csv_filename="captured_packets.csv", capture_duration=30):
    # Open a CSV file for writing
    with open(csv_filename, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        
        # Write header row to CSV file
        csv_writer.writerow(["source_ip", "destination_ip", "source_port", "destination_port"])  # Add other headers as needed
        
        # Capture packets on the specified network interface
        capture = pyshark.LiveCapture(interface=interface)
        start_time = time.time()
        # Continuously capture and process packets
        for packet in capture.sniff_continuously():
            try:
                # Preprocess the packet data
                preprocessed_data = preprocess_network_traffic(packet)
                # Write preprocessed data to CSV file
                csv_writer.writerow([preprocessed_data["source_ip"], preprocessed_data["destination_ip"], preprocessed_data["source_port"], preprocessed_data["destination_port"]])
            except KeyboardInterrupt:
                # Stop packet capture if KeyboardInterrupt (Ctrl+C) is received
                break
            except Exception as e:
                # Exception occurred, handle error and continue packet capture
                print("Error:", str(e))
                continue

            # Check if capture duration has elapsed
            if time.time() - start_time >= capture_duration:
                break

    # Send the generated CSV file to the API endpoint
    send_csv_to_api(csv_filename)

if __name__ == "__main__":
    # Start capturing and saving packets to a CSV file
    capture_and_save_packets(interface="eth0", csv_filename="captured_packets.csv", capture_duration=30)
