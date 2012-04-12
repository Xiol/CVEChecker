#!/usr/bin/env python
# netsnmp requires net-snmp-python on CentOS / RHEL
import os
import cPickle
import time
import netsnmp
import difflib

PKG_STORE = "hosts"


class SNMPQueryTool:
    def __init__(self, host, mib="HOST-RESOURCES-MIB::hrSWInstalledName",
                 force_refresh=False):
        self.host = host
        self.snmp_mib = mib
        self.instpkgs = None
        self.force_refresh = force_refresh  # Don't use cache
        self.debug = False

        if not os.path.exists(PKG_STORE):
            os.mkdir(PKG_STORE, 0755)

        self._retr_pkgs()

    def get_packages(self):
        """ Get a full list of installed packages on host."""
        self._debug("SNMP: Performing SNMP query...")
        try:
            self.instpkgs = list(netsnmp.snmpwalk(
                                    netsnmp.Varbind(self.snmp_mib), Version=1,
                                    DestHost=self.host, Community='public'))

            if self.instpkgs == []:
                self.instpkgs = None
        except:
            self.instpkgs = None
            return

        self._store_pkgs()

    def _store_pkgs(self):
        # Need to store state over requests to avoid polling SNMP too much
        # This feels dirty.
        if self.instpkgs:
            with open(os.path.join(PKG_STORE, self.host), 'w') as f:
                cPickle.dump(self.instpkgs, f, 2)

    def _retr_pkgs(self):
        pkgf = os.path.join(PKG_STORE, self.host)

        if not os.path.exists(pkgf):
            return

        # If our cached package list is older than 10 minutes, remove it
        if (time.time() - os.path.getmtime(pkgf)) > 600 or self.force_refresh:
            self._debug("SNMP: Old SNMP results found, unlinking.")
            os.unlink(pkgf)
            return
        else:
            with open(pkgf, 'r') as f:
                self._debug("SNMP: Loading cached SNMP results.")
                self.instpkgs = cPickle.load(f)
                self._debug("SNMP: Load complete.")
            return

    def get_installed_package(self, package):
        if self.instpkgs is None:
            self.get_packages()

        if self.instpkgs is None:
            # If it's still none, SNMP failed.
            return "SNMP query problem."

        # Use difflib.SequenceMatcher() to figure out the package name.
        # Why all this BS? Well, RPM package names aren't consistent, and
        # the rpm python tools will only work against installed packages
        # on THIS system, which won't do. This is going to be slow.

        # First we need to narrow down the possible candidates.
        pkg_start = package.split('-')[0]
        potentials = []
        for p in self.instpkgs:
            if p.find(pkg_start) == 0:
                potentials.append(p)

        # Then we'll use a SequenceMatcher to check those potentials,
        # assuming we have some...
        if potentials == []:
            self._debug("No potentials found.")
            return None

        sm = difflib.SequenceMatcher()
        sm.set_seq2(package)
        hr = {'package': None, 'ratio': 0}
        for p in potentials:
            sm.set_seq1(p)
            r = sm.quick_ratio()
            if r > hr['ratio']:
                hr['ratio'] = r
                hr['package'] = p

        self._debug("Match found, package: {0}, ratio: {0}".format(hr['ratio'], hr['package']))

        if hr['package']:
            return hr['package']
        else:
            return None

    def _debug(self, msg):
        if self.debug:
            print msg

if __name__ == "__main__":
    q = SNMPQueryTool('localhost')
    q.get_installed_package(raw_input("Package to query: "))
