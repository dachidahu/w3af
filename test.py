import requests
import json

data = {'scan_profile': file('profiles/fast_scan.pw3af').read(),
        'target_urls': ['http://testphp.vulnweb.com']}

response = requests.post('http://127.0.0.1:5000/scans/',
                         data=json.dumps(data),
                         headers={'content-type': 'application/json'})
print response.content
