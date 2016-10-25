import sys
import os.path
import glob
import json
import requests
import math
from copy import deepcopy, copy

# If required dirs don't exist, make them
if not os.path.exists("./bins"):
    os.makedirs("./bins")
if not os.path.exists("./reports"):
    os.makedirs("./reports")

# Require pre-downloaded hashes of samples in VT json format
if not os.path.exists("./samples"):
    print '[!] No samples directory found.'
    sys.exit(0)

# Prompt for max samples/mo to dl
MAX_SPM = raw_input("[?] Max samples/mo to dl: ")

# Function to get evenly distributed percentages based on samples/mo
def hashSlice(myList,num):
    if len(myList)<=num: return myList #Might not be enough elements
    if num==0: return []
    if num==1: return [myList[int(round((len(myList)-1)/2))]]
    return [myList[int(round((len(myList)-1)/(2*num)))]]+hashSlice(myList[int(round((len(myList)-1)/(num))):],num-1)

# Sample downloader function
def dl(samples):
    count = 0
    n = 0

    # Process each sample in list of samples
    for hash in samples:
        n+=1
        print '[{0}/{1}] Downloading: {2}'.format(n, len(samples), hash)

        #Set up api call to download binary
        params = {'apikey': '827c1759df1a8d0c77e49ef87336b23d942808b2f6a33a855990947a2ff52c12', 'hash': hash}
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/download', params=params)
        sample = response.content
        if not os.path.exists("./bins"):
            os.makedirs(directory)
        target = open('./bins/'+hash, 'wb')
        target.write(sample)
        target.close()

        # Set up API call to download the report
        params = {'apikey': '827c1759df1a8d0c77e49ef87336b23d942808b2f6a33a855990947a2ff52c12', 'resource': hash, 'allinfo': '1'}
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
        sample = response.json()

        # Write downloaded report to json file with the sample hash as the file name
        with open('./reports/'+hash+'.json', 'w') as ofile:
            json.dump(sample, ofile)

# Enumerate all json files containing hashes to download
flist = glob.glob(os.path.join('./samples', '*.json'))
sList = []

# Extract hashes from hash json file
for f in sorted(flist):
    sList.append([])
    with open(f, "rb") as data_file:
        data = json.load(data_file)
        for hash in data['hashes']:
            sList[-1].append(hash)
    sList [-1] = hashSlice(sList[-1], int(MAX_SPM))


# Display stats for API call usage
samples = set(i for j in sList for i in j)
print ('[*] Total files to download: {0}\n[!] Total API calls: {1}'.format(len(samples), len(samples)*2))

# Begin download process
cont = raw_input("[?] Contine to download: ")
if ('Y' in cont) or ('y' in cont):
    dl(samples)
    print "[*] All samples & reports downloaded! Goodbye."
else:
    print "[!] Goodbye."
