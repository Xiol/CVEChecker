#!/usr/bin/env python
import sys
import os
import re
import cPickle
import time
import netsnmp  # requires 'net-snmp-python' on CentOS

PKG_STORE = "hosts"

class SNMPQueryTool:
    def __init__(self, host, mib="HOST-RESOURCES-MIB::hrSWInstalledName",
                 force_refresh=False):
        self.host = host
        self.snmp_mib = mib
        self.instpkgs = None
        self.force_refresh = force_refresh # Don't use cache

        if not os.path.exists(PKG_STORE):
            os.mkdir(PKG_STORE, 0755)

        self._retr_pkgs()

    def get_installed_packages(self):
        """ Get a full list of installed packages on host."""
        self.instpkgs = list(netsnmp.snmpwalk(
                                netsnmp.Varbind(self.snmp_mib), Version=1,
                                DestHost=self.host, Community='public'))
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
            print "old file detected, unlinking"
            os.unlink(pkgf)
            return
        else:
            with open(pkgf, 'r') as f:
                print "loading cached results"
                self.instpkgs = cPickle.load(f)
            return

    def get_installed_version(self, package):
        """ Returns the full package name including version number for the
        package requested. 'package' should be the package name without 
        a version number."""

        if self.instpkgs == None:
            self.get_installed_packages()

        p = None

        # Loop over the list of installed packages and find the one
        # we're looking once. Once found, stop searching and return it
        for p in (pkg for pkg in self.instpkgs if pkg.find(package) == 0):
            break

        return p

if __name__ == "__main__":
    q = SNMPQueryTool('localhost')
    q.get_installed_version(raw_input("Package to query: "))
