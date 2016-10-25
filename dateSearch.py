import os
import sys
import json
import requests
from datetime import date
from dateutil.rrule import rrule, MONTHLY

# Create target path for hashes to be placed in
if not os.path.exists("./samples"):
    os.makedirs("./samples")

# Pull sample hashes from VT between defined date range and antivirus detection signature

a = date(2012, 1, 01)
b = date(2016, 4, 01)

print "Use engines:<signature> format to pull specific families."
wat = raw_input("Other queries (key:val): ")

for dt in rrule(MONTHLY, dtstart=a, until=b):
    d1 = dt.strftime("%Y-%m-%d")
    dt2 = rrule(MONTHLY, dtstart=a, until=b).after(dt, inc=False)
    d2 = dt2.strftime("%Y-%m-%d")

    params = {'apikey': '<key>', 'query':
            'tag:trojan (fs:'+d1+'T00:00:00+ AND fs:'+d2+'T00:00:00-) '+wat}
    print params
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/search', params=params)
    response_json = response.json()

    with open("./samples/"+d1+'-'+d2+'.json', 'w') as results:
        json.dump(response_json, results, sort_keys=True, indent=4)
