import glob
import json

nth = 0
count = 0
cnt = 0
for f in glob.glob("*.json"):
    with open(f, "rb") as data_file:
        data = json.load(data_file)
        for hash in data['hashes']:
            count +=1
            cnt += 1
        print('# of hashes in {0} {1}'.format(f, cnt))
        cnt = 0
print('Total # of hashes: {0}'.format(count))
