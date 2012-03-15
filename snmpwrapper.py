#!/usr/bin/env python
import sys
import os
import re
import netsnmp  # requires 'net-snmp-python' on CentOS

# var = netsnmp.Varbind(SNMP_MIB)
# res = netsnmp.snmpwalk(var, Version=1, DestHost='localhost', Community='public')

class SNMPQueryTool:
    def __init__(self, host, mib="HOST-RESOURCES-MIB::hrSWInstalledName"):
        self.host = host
        self.snmp_mib = mib
        self.instpkgs = None

    def _get_installed_packages(self):
        """ Get a full list of installed packages on host."""
        self.instpkgs = list(netsnmp.snmpwalk(
                                netsnmp.Varbind(self.snmp_mib), Version=1,
                                DestHost=self.host, Community='public'))

    def get_installed_version(self, package):
        """ Returns the full package name including version number for the
        package requested. 'package' should be the package name without 
        a version number."""

        if self.instpkgs == None:
            self._get_installed_packages()

        p = None

        # Loop over the list of installed packages and find the one
        # we're looking once. Once found, stop searching and return it
        for p in (pkg for pkg in self.instpkgs if pkg.find(package) == 0):
            break
        
        return p


if __name__ == "__main__":
    q = SNMPQueryTool('localhost')
    print q.get_installed_version('glibc')

    #    print "What you doin', bruv?"
    #    sys.exit(1)
