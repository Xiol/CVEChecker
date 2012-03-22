#!/usr/bin/env python
# netsnmp requires net-snmp-python on CentOS / RHEL
import sys, os, re, cPickle, time, netsnmp, difflib

PKG_STORE = "hosts"

class SNMPQueryTool:
    def __init__(self, host, mib="HOST-RESOURCES-MIB::hrSWInstalledName",
                 force_refresh=False):
        self.host = host
        self.snmp_mib = mib
        self.instpkgs = None
        self.force_refresh = force_refresh # Don't use cache
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
        # Uses difflib to perform a fuzzy match to return the installed package
        # 'package' should be a full RPM package name including version
        # Returns the best match, which will be at index 0
        if self.instpkgs is None:
            self.get_packages()

        if self.instpkgs is None:
            # If it's still none, SNMP failed.
            return "SNMP query problem."

        pkg = difflib.get_close_matches(package, self.instpkgs)[0]

        if pkg:
            return pkg
        else:
            return None

    def _debug(self, msg):
        if self.debug:
            print msg

if __name__ == "__main__":
    q = SNMPQueryTool('localhost')
    q.get_installed_package(raw_input("Package to query: "))
