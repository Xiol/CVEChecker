#!/usr/bin/env python -OO
# CVE -> RHSA Report Generator
#
# Requires Beautiful Soup: http://www.crummy.com/software/BeautifulSoup/
# Currently only tested with Python 2.6, but no reason it shouldn't work
# with older Python versions (minimum 2.3). Not compatible with Python 3.
#
# Use like: ./rhsa.py < cvelist.txt, where cvelist.txt is a whitespace
# separated list of CVE numbers in the format CVE-YYYY-XXXX.
#
# This will find the CVE on the CVE_BASE_URL site and scrape for the
# related RHSA. If it can't find the CVE, chances are it doesn't affect
# Red Hat or Linux. If it can't find an RHSA, then it'll be something
# they don't intend to fix, so output the statement from Red Hat. 
# Otherwise, consider resolved and output the link to the RHSA.
# This of course assumes you ARE running the latest CentOS/RHEL release 
# versions of the software you're checking the CVEs for.
#
# No guarantees anything this outputs is correct or proper.

import sys
import re
import urllib2
from time import sleep
from BeautifulSoup import BeautifulSoup

CVE_BASE_URL = "https://www.redhat.com/security/data/cve/"
RHEL_VERSION = "5"

rhsa_r = re.compile(".*Red Hat Enterprise Linux version "+RHEL_VERSION+".*")

def get_cve_info(cve, platform='x86_64'):
    if platform not in ['x86_64','x86']:
        return "Platform must be 'x86_64' or 'x86'."

    cve = cve.strip()
    cveurl = CVE_BASE_URL + cve + ".html"
    try:
        html = urllib2.urlopen(cveurl).read()
    except urllib2.HTTPError:
        # 404 or general screwup
        return cve + " -- !!FIX!! Not found on Red Hat's website. Google it, might be Windows only or bad CVE reference."
    except urllib2.URLError:
        return

    soup = BeautifulSoup(html)

    if soup.find(text=rhsa_r) is not None:
        # If we've found the above, we have an RHSA (in theory!)
        rhsa = soup.find(text=rhsa_r).findNext('a')['href']
        rhsa_soup = BeautifulSoup(urllib2.urlopen(rhsa).read())
        ver = rhsa_soup.find('a',attrs={"name": "Red Hat Enterprise Linux (v. "+RHEL_VERSION+" server)"}).findNext(text="SRPMS:").findNext('td').contents[0]
        ver = ver.replace(".src.", '.'+platform+'.')
        return cve + " -- Resolved in version "+ver+": " + rhsa
    elif soup.find(text="Statement"):
        statement = ' '.join([text for text in soup.find(text="Statement").findNext('p').findAll(text=True)])
        return cve + " -- Red Hat Statement: "+ cveurl +": \""+ statement + "\""
    else:
        return cve + " -- !!FIX!! No RHSA for version "+RHEL_VERSION+", no statement either. See: " + cveurl


if __name__ == '__main__':
    rawdata = ""

    if sys.stdin.isatty():
        print "No input detected. You need to pipe a whitespace separated list of CVEs in!"
        print "e.g. `./rhsa.py < cvelist.txt` or your preferred method."
        sys.exit(1)
    else:
        rawdata = sys.stdin.read()

    cves = rawdata.split()

    for cve in cves:
        print get_cve_info(cve)
        sleep(0.3) # to be nice!
