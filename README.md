Various pipeline use scripts
============================

To gather samples from VirusTotal, use this file structure:

* The root directory should be the name of the sample in question
  - ./bins -- Contains the downloaded binaries
  - ./samples -- Contains the hashes returned from date search
  - ./reports -- Contains the VT scan reports

The Cuckoo data extractor is built for our specific use case but is
easily extendable to any use case. Just be sure to know what
heuristics you want to push to the MDB. Cuckoo dumps all reports
generated to json files in "cuckoo/storage/analyses/<scan id>/reports/".
More data is stored in the <scan id> folder which is seen in the
web interface.
