#!/usr/bin/env python -OO
# This Source Code Form is subject to the terms of the Mozilla
# Public License, v. 2.0. If a copy of the MPL was not distributed
# with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# CVE -> RHSA Report Generator
#
# Requires Python 2.6 and Beautiful Soup:
#    http://www.crummy.com/software/BeautifulSoup/
#
# Use like: ./rhsa.py < cvelist.txt, where cvelist.txt is a whitespace
# separated list of CVE numbers in the format CVE-YYYY-XXXX.
#
# This will find the CVE on the cve_base_url site and scrape for the
# related RHSA. If it can't find the CVE, chances are it doesn't affect
# Red Hat or Linux. If it can't find an RHSA, then it'll be something
# they don't intend to fix, so output the statement from Red Hat.
# Otherwise, consider resolved and output the link to the RHSA.
# This of course assumes you ARE running the latest CentOS/RHEL release
# versions of the software you're checking the CVEs for.
#
# No guarantees anything this outputs is correct or proper.
#
# vim:ts=4:sw=4:sts=4:ai:si:nu

import sys
import re
import urllib2
import sqlite3
import os
#import snmp
from BeautifulSoup import BeautifulSoup


class CVEChecker:
    def __init__(self, rhel_version="5", platform="x86_64", host=None):
        if platform not in ['x86_64', 'i386']:
            raise ValueError("Platform must be 'x86_64' or 'i386'.")
        self.rhel_version = rhel_version
        self.platform = platform
        self.host = None # workaround
#        self.cve_base_url = "https://www.redhat.com/security/data/cve/"
        self.cve_base_url = "https://access.redhat.com/security/cve/"
        self.mitre_url = "http://cve.mitre.org/cgi-bin/cvename.cgi?name="
        self.rhsa5_r = re.compile(".*Red Hat Enterprise Linux version 5.*")
        self.rhsa6_r = re.compile(".*Red Hat Enterprise Linux version 6.*")
        self.rhsa7_r = re.compile(".*Red Hat Enterprise Linux version 7.*")
        self.rhsax_r = re.compile(".*Red Hat Enterprise Linux version [4321].*")
        self.sc_r = re.compile(".*Red Hat Software Collections \d for RHEL.*")
        self.cve_r = re.compile(r"^CVE-\d{4}-\d{4}$")
        self.pkghdr5 = "Red Hat Enterprise Linux (v. 5 server)"
        self.pkghdr6 = "Red Hat Enterprise Linux Server (v. 6)"
        self.pkghdr7 = "Red Hat Enterprise Linux Server (v. 7)"
        self.curdir = os.path.join(os.getcwd(), os.path.dirname(__file__))
        if self.host:
            self.snmpq = snmp.SNMPQueryTool(self.host)
        else:
            self.snmpq = None
        self.soup = None
        self.cve = None

        initdb = False
        if not os.path.exists(os.path.join(self.curdir, 'cache.db')):
            initdb = True

        self.conn = sqlite3.connect(os.path.join(self.curdir, 'cache.db'), check_same_thread=False)

        if initdb:
            self._init_db()

    def _init_db(self):
        cur = self.conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS cache (id INTEGER PRIMARY KEY AUTOINCREMENT, " \
                    + "timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP, platform TEXT NOT NULL, " \
                    + "rhelver INTEGER NOT NULL, cve TEXT NOT NULL, result TEXT NOT NULL, " \
                    + "o_ver TEXT DEFAULT NULL)")
        cur.execute("CREATE INDEX IF NOT EXISTS cve_idx ON cache (cve)")
        self.conn.commit()
        cur.close()

    def get_cve_info(self, cve):
        # Fix formatting
        cve = cve.strip()
        cve = cve.replace(',','')
        cve = cve.upper()
        self.cve = cve
        del(cve) # for refactoring

        if not self.cve_r.match(self.cve):
            # Check the CVE is in the correct format
            return {'cve': "{0} -- This is not a CVE reference.".format(self.cve), 'verinfo': None}

        cached_cve = self._cache_retrieve()
        if cached_cve['cve'] is not None:
            if self.host:
                if cached_cve['originalver']:
                    return {'cve': cached_cve['cve'], 'verinfo': self._get_installed_package(cached_cve['originalver'])}
            # Likely a statement, so no verinfo despite wanting us to check a host
            return {'cve': cached_cve['cve'], 'verinfo': None}

        cveurl = self.cve_base_url + self.cve # + ".html"  # Not sure if we need .html anymore? They rewrite it anyway.
        try:
            html = urllib2.urlopen(cveurl).read()
        except urllib2.HTTPError:
            # 404 or general screwup, don't cache in case it turns up later
            return {'cve': "{0} -- !!FIX!! Not found on Red Hat's website. " \
                                  + "Might be Windows only or bad CVE reference, see {1}".format(self.cve, self.mitre_url + self.cve), 'verinfo': None}
        except urllib2.URLError:
            return {'cve': "There was a problem with the URL.", 'verinfo': None}

        soup = BeautifulSoup(html)

        # Not DRY at all, just hacking in 7 support. Need to rewrite this
        # entire tool tbh.
        if self.rhel_version == "7":
            if soup.find(text=self.rhsa7_r):
                return self.scrape_rhsa(soup, self.rhsa7_r)
            elif soup.find(text=self.rhsa6_r):
                result = "Related to, or fix only available for, RHEL6."
                statement = self.get_statement(soup)
                if statement:
                    result = result + " Red Hat Statement: " + statement
                    self._cache_store(result)
                    return {'cve': self.cve + " -- " + result, 'verinfo': None}
            elif soup.find(text=self.rhsa5_r):
                result = "Related to, or fix only available for, RHEL5."
                statement = self.get_statement(soup)
                if statement:
                    result = result + " Red Hat Statement: " + statement
                self._cache_store(result)
                return {'cve': self.cve + " -- " + result, 'verinfo': None}
            elif soup.find(text=self.rhsax_r):
                result = "Affected <=RHEL4. Packages from RHEL6 will not be affected by this issue."
                self._cache_store(result)
                return {'cve': self.cve + " -- " + result, 'verinfo': None}
        elif self.rhel_version == "6":
            if soup.find(text=self.rhsa6_r):
                return self.scrape_rhsa(soup, self.rhsa6_r)
            elif soup.find(text=self.rhsa5_r):
                result = "Related to, or fix only available for, RHEL5."
                statement = self.get_statement(soup)
                if statement:
                    result = result + " Red Hat Statement: " + statement
                self._cache_store(result)
                return {'cve': self.cve + " -- " + result, 'verinfo': None}
            elif soup.find(text=self.rhsax_r):
                result = "Affected <=RHEL4. Packages from RHEL6 will not be affected by this issue."
                self._cache_store(result)
                return {'cve': self.cve + " -- " + result, 'verinfo': None}
        else:
            if soup.find(text=self.rhsa5_r):
                return self.scrape_rhsa(soup, self.rhsa5_r)

        # If we get here, then there isn't a RHSA available.

        statement = self.get_statement(soup)
        if statement:
            # If we're here, Red Hat haven't released an updated package, but they
            # have made a statement about the issue, usually pointing out why they
            # haven't fixed it. We need to grab this for our report...
            result = "Red Hat Statement: \"{0}\" - {1}".format(statement, cveurl)
            self._cache_store(result)
            return {'cve': self.cve + " -- " + result, 'verinfo': None}

        elif soup.find(text="CVE not found"):
            # They changed their website! This is needed to pick up the lack of a CVE now,
            # since they don't 404 on a missing CVE, they redirect to a page that returns 200 OK. Boo.
            result = "!!FIX!! Not found on Red Hat's website. Might be Windows only or bad CVE reference, see {0}".format(self.mitre_url + self.cve)
            return {'cve': self.cve + " -- " + result, 'verinfo': None}

        else:
            result = "!!FIX!! No RHSA for version {0}, no statement either. See {1}".format(self.rhel_version, cveurl)
            #_add_cve(cve, result)
            return {'cve': self.cve + " -- " + result, 'verinfo': None}

    def get_statement(self, soup):
        if soup.find(text="Statement"):
            return ' '.join([text for text in soup.find(text="Statement").findNext('p').findAll(text=True)])
        else:
            return None

    def scrape_rhsa(self, soup, rx):
        # If we've found the above, we have an RHSA (in theory!)
        # Get the link to the RHSA page
        rhsa = soup.find(text=rx).findNext('a')['href']

        # Open that page, read it in, hand it off to BS
        rhsa_soup = BeautifulSoup(urllib2.urlopen(rhsa).read())

        if rhsa_soup.find(text=self.sc_r):
            return {"cve": "{0} -- !!FIX!! This CVE is related to Red Hat Software Collections. If you are not using RHSC you might be fine. Please check manually: {1}".format(self.cve, rhsa), "verinfo": None}

        # Get the package version where the issue is fixed (SRPMS link)
        if self.rhel_version == "5":
            pkghdr = self.pkghdr5
        elif self.rhel_version == "6":
            pkghdr = self.pkghdr6
        elif self.rhel_version == "7":
            pkghdr = self.pkghdr7
        else:
           raise ValueError("RHEL version should be '5', '6' or '7' only.")
        o_ver = rhsa_soup.find('a', attrs={"name": pkghdr}).findNext(text="SRPMS:").findNext('td').contents[0]

        # Change the 'src' in the package name to our platform name
        # This is being very lazy, but it works - the versions are the same
        # for i386 and x86_64, so we can get away with this for now.
        ver = o_ver.replace(".src.", '.{0}.'.format(self.platform))

        # Construct our result text
        result = "Resolved in version {0}: {1}".format(ver, rhsa)

        # Get currently installed package on our SNMP queried host, if any.
        instver = None
        if self.host:
            instver = self._get_installed_package(o_ver)

        # Store the information in the cache to speed up future lookups
        if self.cve == None:
            raise ValueError("scrape_rhsa() called without current CVE")
        self._cache_store(result, o_ver)

        # Return our dictionary containing the CVE result and the SNMP info (if any)
        return {'cve': "{0} -- {1}".format(self.cve, result), 'verinfo': instver}

    def _get_installed_package(self, package):
        return "" # workaround
        #p = package.split('src')[0][:-1]
        #return self.snmpq.get_installed_package(p)

    def _cache_retrieve(self):
        cur = self.conn.cursor()
        cur.execute("""SELECT cve,result FROM cache where cve=? AND platform=? AND rhelver=? LIMIT 1""", \
                                                (self.cve, self.platform, self.rhel_version))
        result = cur.fetchone()
        cur.execute("""SELECT o_ver FROM cache where cve=? AND platform=? AND rhelver=? LIMIT 1""",
                                                (self.cve, self.platform, self.rhel_version))
        o_ver = cur.fetchone()
        if o_ver:
            o_ver = o_ver[0]
        cur.close()
        if result is not None:
            result = ' -- '.join([t for t in result if t is not None])

        return {'cve': result, 'originalver': o_ver}

    def _cache_store(self, result, o_ver=None):
        cur = self.conn.cursor()
        if o_ver:
            # We'll store the version that the issue is fixed in separately so we can do
            # a lookup on it easily later when this information is retrieved from the cache
            cur.execute("""INSERT INTO cache(cve, result, platform, rhelver, o_ver) VALUES (?, ?, ?, ?, ?)""", \
                           (self.cve, result, self.platform, int(self.rhel_version), o_ver))
        else:
            cur.execute("""INSERT INTO cache(cve, result, platform, rhelver, o_ver) VALUES (?, ?, ?, ?, NULL)""", \
                           (self.cve, result, self.platform, int(self.rhel_version)))
        self.conn.commit()
        cur.close()

if __name__ == '__main__':
    # If we're run directly from the command line, expect CVEs to
    # come in on stdin. Read 'em and check 'em.

    rawdata = ""

    if sys.stdin.isatty():
        #print("No input detected. You need to pipe a whitespace separated list of CVEs in!")
        #print("e.g. `./rhsa.py < cvelist.txt`, or your preferred method.")
        #sys.exit(1)
        rawdata = "CVE-2014-9427 CVE-2014-8142"
    else:
        rawdata = sys.stdin.read()

    cves = rawdata.split()

    checker = CVEChecker(host='localhost', rhel_version="6")

    for cve in cves:
        info = checker.get_cve_info(cve)
        if info['verinfo'] is not None:
            print("{0} -- Currently installed package: {1}".format(info['cve'], info['verinfo']))
        else:
            print(info['cve'])
