import json
import glob
import os.path

filelist = glob.glob(os.path.join('.', '*.json'))
for infile in sorted(filelist):
    #do some fancy stuff
        print str(infile)

result = []
for f in filelist:
    with open(f, "rb") as infile:
        data = json.load(infile)
        for hash in data['hashes']:
            result.append(hash)

with open("hashes.json", "wb") as outfile:
    outfile.write('{\n    "hashes" : ')
    json.dump(result, outfile, sort_keys=True, indent=4, separators=(',', ': '))
    outfile.write('\n}')
