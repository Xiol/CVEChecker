# CVE -> RHSA Report Generator

import MySQLdb
import sys
import urllib2
from BeautifulSoup import BeautifulSoup


CVE_BASE_URL = "https://www.redhat.com/security/data/cve/"

rawdata = ""

if sys.stdin.isatty():
    print "No input detected. You need to pipe a whitespace separated list of CVEs in!"
    sys.exit(1)
else:
    rawdata = sys.stdin.read()

cves = rawdata.split()

conn = MySQLdb.connect(host="localhost",user="cve",passwd="bluem00n",db="cve_rhsa")
c = conn.cursor()

def get_cve_info(cve):
        cveurl = CVE_BASE_URL + cve + ".html"
        try:
            html = urllib2.urlopen(cveurl).read()
        except HTTPError:
            # 404 or general screwup
            return cve + " -- Not found on Red Hat's website. Google it, might be Windows only."
        
        soup = BeautifulSoup(html)
        statement = ' '.join([text for text in soup.find(text="Statement").findNext('p').findAll(text=True)])
        return cve + " -- Red Hat Statement: "+ cveurl +": \""+ statement + "\""

for cve in cves:
    c.execute("""SELECT rhsa FROM cverhsa WHERE cve=%s""", (cve,))
    rhsalink = c.fetchone()
    if not rhsalink == None:
        print cve + " -- Resolved: " + rhsalink[0]
    else:
        print get_cve_info(cve)
