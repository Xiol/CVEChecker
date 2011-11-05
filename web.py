#!/usr/bin/env python
# Web frontend for CVE -> RHSA report generator. 
# 
# Requires CherryPy, Mako, Python <= 2.7

import rhsa 
import cherrypy
import os
from mako.template import Template
from mako.lookup import TemplateLookup

tlu = TemplateLookup(directories=['templates'])

curdir = os.path.join(os.getcwd(), os.path.dirname(__file__))

cherrypy.config.update({
    'tools.staticdir.root': curdir 
})

class RHSAGenWeb:
    @cherrypy.expose
    def index(self):
        return tlu.get_template("index.html").render(rhelver=rhsa.RHEL_VERSION)

    @cherrypy.expose
    def repgen(self, cves=None):
        if cves == None or cves == "":
            return "You didn't give me a list of CVEs :("

        rhsalist = []

        cves = cves.split()

        for cve in cves:
            rhsalist.append(rhsa.get_cve_info(cve))

        return tlu.get_template("repgen.html").render(rhsalist=rhsalist)

if __name__ == "__main__":
    cherrypy.quickstart(RHSAGenWeb(), "/", "web.conf")
