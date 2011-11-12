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
import sqlite3
import os
from time import sleep
from BeautifulSoup import BeautifulSoup

CVE_BASE_URL = "https://www.redhat.com/security/data/cve/"
RHEL_VERSION = "5"

rhsa_r = re.compile(".*Red Hat Enterprise Linux version "+RHEL_VERSION+".*")

curdir = os.path.join(os.getcwd(), os.path.dirname(__file__))

conn = sqlite3.connect(os.path.join(curdir, 'cache.db'))
cur = conn.cursor()

cur.execute("CREATE TABLE IF NOT EXISTS cache (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP, cve TEXT NOT NULL, result TEXT NOT NULL)")
cur.execute("CREATE INDEX IF NOT EXISTS cve_idx ON cache (cve)")
conn.commit()
cur.close()

def get_cve_info(cve, platform='x86_64'):
    if platform not in ['x86_64','i386']:
        return "Platform must be 'x86_64' or 'i386'."

    cve = cve.strip()

    cachechk = _retr_cve(cve)
    if cachechk is not None:
        return cachechk

    cveurl = CVE_BASE_URL + cve + ".html"
    try:
        html = urllib2.urlopen(cveurl).read()
    except urllib2.HTTPError:
        # 404 or general screwup
        result = "!!FIX!! Not found on Red Hat's website. Google it, might be Windows only or bad CVE reference."
        _add_cve(cve, result)
        return cve + " -- " + result
    except urllib2.URLError:
        return

    soup = BeautifulSoup(html)

    if soup.find(text=rhsa_r) is not None:
        # If we've found the above, we have an RHSA (in theory!)
        rhsa = soup.find(text=rhsa_r).findNext('a')['href']
        rhsa_soup = BeautifulSoup(urllib2.urlopen(rhsa).read())
        ver = rhsa_soup.find('a',attrs={"name": "Red Hat Enterprise Linux (v. "+RHEL_VERSION+" server)"}).findNext(text="SRPMS:").findNext('td').contents[0]
        ver = ver.replace(".src.", '.'+platform+'.')
        result = "Resolved in version "+ver+": " + rhsa
        _add_cve(cve, result)
        return cve + " -- " + result
    elif soup.find(text="Statement"):
        statement = ' '.join([text for text in soup.find(text="Statement").findNext('p').findAll(text=True)])
        result = "Red Hat Statement: \""+ statement + "\" - " + cveurl
        _add_cve(cve, result)
        return cve + " -- " + result
    else:
        result = "!!FIX!! No RHSA for version "+RHEL_VERSION+", no statement either. See: " + cveurl
        _add_cve(cve, result)
        return cve + " -- " + result

def _add_cve(cve, result):
    cur = conn.cursor()
    cur.execute("""INSERT INTO cache(cve, result) VALUES (?, ?)""", (cve, result,))
    conn.commit()
    cur.close()

def _retr_cve(cve):
    cur = conn.cursor()
    cur.execute("""SELECT cve,result FROM cache WHERE cve=? LIMIT 1""", (cve,))
    result = cur.fetchone()
    cur.close()
    if result is not None:
        result =  ' -- '.join([t for t in result if t is not None])
    return result

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
