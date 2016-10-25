import json
import requests
params = {'apikey': '<key>',
'query': 'type:peexe size:90kb+ positives:5+ engines:Phdet.E tag:trojan sources:2000+ fs:2010-01-01T19:59:59'}
response = requests.get('https://www.virustotal.com/vtapi/v2/file/search', params=params)
response_json = response.json()

with open('results.json', 'w') as results:
    json.dump(response_json, results)
