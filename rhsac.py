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
#
# vim:ts=4:sw=4:sts=4:ai:si:nu

import sys, re, urllib2, sqlite3, os, snmp
from time import sleep
from BeautifulSoup import BeautifulSoup

class CVEChecker:
    def __init__(self):
        self.CVE_BASE_URL = "https://www.redhat.com/security/data/cve/"
        self.RHEL_VERSION = "5"
        self.rhsa_r = re.compile(".*Red Hat Enterprise Linux version "+self.RHEL_VERSION+".*")
        self.curdir = os.path.join(os.getcwd(), os.path.dirname(__file__))

        initdb = False
        if not os.path.exists(os.path.join(self.curdir, 'cache.db')):
            initdb = True

        self.conn = sqlite3.connect(os.path.join(self.curdir, 'cache.db'), check_same_thread = False)

        if initdb:
            self._init_db()

    def _init_db(self):
        cur = self.conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS cache (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP, platform TEXT NOT NULL, cve TEXT NOT NULL, result TEXT NOT NULL)")
        cur.execute("CREATE INDEX IF NOT EXISTS cve_idx ON cache (cve)")
        self.conn.commit()
        cur.close()

    def get_cve_info(self, cve, platform="x86_64", host=None):
        if platform not in ['x86_64','i386']:
            return { 'cve': "Platform must be 'x86_64' or 'i386'.", 'verinfo': None }

        if host:
            snmpq = snmp.SNMPQueryTool(host)
            snmpq.get_installed_packages()

        cve = cve.strip()

        cached_cve = self._cache_retrieve(cve, platform)
        if cached_cve is not None:
            if host is None:
                # Not performing an SNMP query
                return {'cve': cached_cve, 'verinfo': None }
            if host is not None:
                # XXX: Do what? We can't cache the snmp results (in theory) so re-run?
                pass

        cveurl = self.CVE_BASE_URL + cve + ".html" # Not sure if we need .html anymore? They rewrite it anyway.
        try:
            html = urllib2.urlopen(cveurl).read()
        except urllib2.HTTPError:
            # 404 or general screwup, don't cache in case it turns up later
            return { 'cve': cve + " -- !!FIX!! Not found on Red Hat's website. " \
                                  +"Google it, might be Windows only or bad CVE reference.", 'verinfo': None }
        except urllib2.URLError:
            return { 'cve': "There was a problem with the URL.", 'verinfo': None }

        soup = BeautifulSoup(html)

        if soup.find(text=self.rhsa_r) is not None:
            # If we've found the above, we have an RHSA (in theory!)
            # Get the link to the RHSA page
            rhsa = soup.find(text=self.rhsa_r).findNext('a')['href']
            # Open that page, read it in, hand it off to BS
            rhsa_soup = BeautifulSoup(urllib2.urlopen(rhsa).read())
            # Get the package version where the issue is fixed (SRPMS link)
            ver = rhsa_soup.find('a',attrs={"name": "Red Hat Enterprise Linux (v. "+self.RHEL_VERSION+" server)"}).findNext(text="SRPMS:").findNext('td').contents[0]
            # Change the 'src' in the package name to our platform name
            # This is being very lazy, but it works - the versions are the same
            # for i386 and x86_64, so we can get away with this for now.
            ver = ver.replace(".src.", '.'+platform+'.')
            # Construct our result text
            result = "Resolved in version "+ver+": " + rhsa
            # TODO: SNMP check should probably come here.
            
            # Store the information in the cache to speed up future lookups
            self._cache_store(cve, result, platform)
            # Return our dictionary containing the CVE result and the SNMP info (if any)
            return { 'cve': cve + " -- " + result, 'verinfo': None }
        elif soup.find(text="Statement"):
            # If we're here, Red Hat haven't released an updated package, but they
            # have made a statement about the issue, usually pointing out why they
            # haven't fixed it. We need to grab this for our report...
            statement = ' '.join([text for text in soup.find(text="Statement").findNext('p').findAll(text=True)])
            result = "Red Hat Statement: \""+ statement + "\" - " + cveurl
            self._cache_store(cve, result, platform)
            return { 'cve': cve + " -- " + result, 'verinfo': None }
        elif soup.find(text="CVE not found"):
            # They changed their website! This is needed to pick up the lack of a CVE now,
            # since they don't 404 on a missing CVE, they redirect to a page that returns 200 OK. Boo.
            result = "!!FIX!! Not found on Red Hat's website. Google it, might be Windows only or bad CVE reference."
            return { 'cve': cve + " -- " + result, 'verinfo': None }
        else:
            result = "!!FIX!! No RHSA for version "+RHEL_VERSION+", no statement either. See: " + cveurl
            #_add_cve(cve, result, platform)
            return { 'cve': cve + " -- " + result, 'verinfo': None }

    def _cache_retrieve(self, cve, platform):
        cur = self.conn.cursor()
        cur.execute("""SELECT cve,result FROM cache where cve=? AND platform=? LIMIT 1""", (cve, platform))
        result = cur.fetchone()
        cur.close()
        if result is not None:
            result = ' -- '.join([t for t in result if t is not None])
        return result

    def _cache_store(self, cve, result, platform):
        cur = self.conn.cursor()
        cur.execute("""INSERT INTO cache(cve, result, platform) VALUES (?, ?, ?)""", (cve, result, platform))
        self.conn.commit()
        cur.close()

if __name__ == '__main__':
    # If we're run directly from the command line, expect CVEs to
    # come in on stdin. Read 'em and check 'em.

    rawdata = ""

    if sys.stdin.isatty():
        print "No input detected. You need to pipe a whitespace separated list of CVEs in!"
        print "e.g. `./rhsa.py < cvelist.txt`, or your preferred method."
        sys.exit(1)
    else:
        rawdata = sys.stdin.read()

    cves = rawdata.split()

    checker = CVEChecker()

    for cve in cves:
        print checker.get_cve_info(cve)['cve']
