import requests

url = "http://127.0.0.1:8000/detect-attacks/"

payload = {}
files=[
  ('file',('subset_21.csv',open('/root/AI-x-init-Build/detailed_awareness_of_network_behavior/subset_21.csv','rb'),'text/csv'))
]
headers = {}

response = requests.request("POST", url, headers=headers, data=payload, files=files)

print(response.text)
