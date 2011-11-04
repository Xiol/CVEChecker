# CVE -> RHSA Report Generator

import MySQLdb
import sys

rawdata = ""

if sys.stdin.isatty():
    print "No input detected. You need to pipe a whitespace separated list of CVEs in!"
    sys.exit(1)
else:
    rawdata = sys.stdin.read()

cves = rawdata.split()

conn = MySQLdb.connect(host="localhost",user="cve",passwd="bluem00n",db="cve_rhsa")
c = conn.cursor()

for cve in cves:
    c.execute("""SELECT rhsa FROM cverhsa WHERE cve=%s""", (cve,))
    rhsalink = c.fetchone()
    if not rhsalink == None:
        print cve + " -- Resolved: " + rhsalink[0]
    else:
        print cve + " -- Not found. Please confirm with Google!"
