#!/usr/bin/env python
# Web frontend for CVE -> RHSA report generator. 
# 
# Requires CherryPy, Mako, Scrubber, Python <= 2.7

import rhsa 
import cherrypy
import os
from mako.template import Template
from mako.lookup import TemplateLookup
from scrubber import Scrubber

tlu = TemplateLookup(directories=['templates'])
scrubber = Scrubber(autolink=True)
curdir = os.path.join(os.getcwd(), os.path.dirname(__file__))

cherrypy.config.update({
    'tools.staticdir.root': curdir,
    'server.environment': 'production'
})

class RHSAGenWeb:
    @cherrypy.expose
    def index(self):
        return tlu.get_template("index.html").render(rhelver=rhsa.RHEL_VERSION)

    @cherrypy.expose
    def repgen(self, cves=None):
        scrubber.scrub(cves)

        if cves == None or cves == "":
            return "You didn't give me a list of CVEs :("

        rhsalist = []

        cves = cves.split()

        for cve in cves:
            rhsalist.append(scrubber.scrub(rhsa.get_cve_info(cve)))

        return tlu.get_template("repgen.html").render(rhsalist=rhsalist)
    
    @cherrypy.expose
    def default(self):
        return "404"

if __name__ == "__main__":
    cherrypy.quickstart(RHSAGenWeb(), "/", "web.conf")
