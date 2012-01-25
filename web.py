#!/usr/bin/env python -OO
# Web frontend for CVE -> RHSA report generator. 
# 
# Requires CherryPy, Mako, Scrubber, Python <= 2.7

import rhsa 
import cherrypy
import os
import re
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

fixemph = re.compile('!!FIX!!')

class RHSAGenWeb:
    @cherrypy.expose
    def index(self):
        return tlu.get_template("index.html").render(rhelver=rhsa.RHEL_VERSION)

    @cherrypy.expose
    def repgen(self, cves=None, platform="x86_64"):
        scrubber.scrub(cves)

        if cves == None or cves == "":
            return "You didn't give me a list of CVEs :("

        if platform == None or platform == "":
            return "Somehow you managed to not give me a platform. :("

        rhsalist = []

        cves = cves.split()

        for cve in cves:
            item = scrubber.scrub(rhsa.get_cve_info(cve, platform))
            item = fixemph.sub('<b class="emph">!!FIX!!</b>', item)
            rhsalist.append(item)

        return tlu.get_template("repgen.html").render(rhsalist=rhsalist)
    
    @cherrypy.expose
    def default(self):
        return "404"

if __name__ == "__main__":
    cherrypy.quickstart(RHSAGenWeb(), "/", "web.conf")
