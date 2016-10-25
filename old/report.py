import json
import requests
from azure.storage.blob import BlockBlobService
from azure.storage.blob import ContentSettings

with open('results.json') as data_file:
        data = json.load(data_file)

        for hash in data['hashes']:
                print(hash)
                params = {'apikey': '<key>', 'resource': hash, 'allinfo': '1'}
                response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
                sample = response.json()

                with open(hash + '.json', 'w') as ofile:
                    json.dump(sample, ofile)
