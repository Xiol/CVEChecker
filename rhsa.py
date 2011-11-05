# CVE -> RHSA Report Generator

import sys
import re
import urllib2
from BeautifulSoup import BeautifulSoup

CVE_BASE_URL = "https://www.redhat.com/security/data/cve/"

def get_cve_info(cve):
        cveurl = CVE_BASE_URL + cve + ".html"
        try:
            html = urllib2.urlopen(cveurl).read()
        except HTTPError:
            # 404 or general screwup
            return cve + " -- Not found on Red Hat's website. Google it, might be Windows only."

        soup = BeautifulSoup(html)

        if soup.find(text=re.compile(".*Red Hat Enterprise Linux version 5.*")) is not None:
            # If we've found the above, we have an RHSA (in theory!)
            rhsa = soup.find(text=re.compile(".*Red Hat Enterprise Linux version 5.*")).findNext('a')['href']
            return cve + " -- Resolved: " + rhsa

        else:
            statement = ' '.join([text for text in soup.find(text="Statement").findNext('p').findAll(text=True)])
            return cve + " -- Red Hat Statement: "+ cveurl +": \""+ statement + "\""


if __name__ == '__main__':

    rawdata = ""

    if sys.stdin.isatty():
        print "No input detected. You need to pipe a whitespace separated list of CVEs in!"
        sys.exit(1)
    else:
        rawdata = sys.stdin.read()

    cves = rawdata.split()

    for cve in cves:
        print get_cve_info(cve)
