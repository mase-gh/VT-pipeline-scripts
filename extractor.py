#!/usr/bin/python
import MySQLdb, json, string, os
from glob import glob

# Files to grab cuckoo data from
pattern = 'report.json'

# Location of cuckoo reports
start_dir = '/home/cuckoo/cuckoo/storage/analyses'
files = []
errs = 0

# File size helper function
def convert_bytes(num):
    for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if num < 1024.0:
            return "%3.1f %s" % (num, x)
        num /= 1024.0

# Function to get size of file for debug
def file_size(file_path):
    if os.path.isfile(file_path):
        file_info = os.stat(file_path)
        return convert_bytes(file_info.st_size)

# Enumerate all results.json files
for dir,_,_ in os.walk(start_dir):
        files.extend(glob(os.path.join(dir,pattern)))

# Connect to the malware db
mdb = MySQLdb.connect(host='<host>',
        user='<user>',
        passwd='<password>',
        db='<db to use>')

# Create cursor to work w/ db
cur = mdb.cursor()

# For each report file found, extract data
for f in files:
    api = []
    table = ''

    # Create python json object from the report file
    with open(f) as report:
        print file_size(f)
        rep = json.load(report)

    # Extract the sample hash, name & ID
    shash = rep['target']['file']['sha256']
    sname = rep['target']['file']['name']
    sid   = rep['info']['id']

    # Decide whether we need to extract compile date from cuckoo report or VT report
    # We do this b/c Turla is found in PDFs which do not have a pe compile time signature
    if sname == shash:
        try:
            with open('/home/cuckoo/turla/reports/' + rep['target']['file']['sha256'] + '.json') as vt_scan:
                vtr = json.load(vt_scan)
                table = 'turla'
                sdate = vtr['first_seen']
        except:
            sdate = '0000-00-00 00:00:00'
            errs += 1
            pass
    elif sname == 'nginx.exe':
        sdate = rep['static']['pe_timestamp']
        table = 'nginx'
    else:
        table = 'irc'
        sdate = rep['static']['pe_timestamp']

    # Try to insert initial row for the sample in question.
    # If it failes, log it and continue
    try:
        cur.execute("INSERT INTO " +table+ " (sample_hash, sample_id, date) VALUES (%s,%s,%s)", (shash, sid, sdate))
        print "Inserting %s " % shash
    except:
        print 'Failed to insert: %s ' % shash
        print shash, sid, sdate
        pass

    # Enumerate all API calls recorded by cuckoo during the run
    try:
        for a in rep['behavior']['apistats']:
            api.extend(rep['behavior']['apistats'][a])
            for k in rep['behavior']['apistats'][a].keys():

                # This is a hack. Try to insert each API as a new column.
                # Upon duplicate column failures, continue.
                # In SQL <5.7 we could use 'ALTER IGNORE TABLE' to insert all columns in one query and ignore failures.
                try:
                    cur.execute("ALTER TABLE " +table+ " ADD "+k+" BOOLEAN DEFAULT 0")
                except:
                    pass

            # Try to update the initial entered row with bool values of whether or not the API call was made.
            try:
                sql = "UPDATE " +table+ " SET" + ",".join(len(api) * [" %s = 1"]) + " WHERE sample_hash = '" +shash+"'"
                cur.execute(sql % tuple(api))
            except:
                pass
    except:
        pass

    # Commit DB changes and move to next report
    mdb.commit()

# Close DB connection after all reports are processed
mdb.close()
print 'Total date errors: %d' % errs


