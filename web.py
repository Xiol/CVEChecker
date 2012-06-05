#!/usr/bin/env python -OO
# This Source Code Form is subject to the terms of the Mozilla
# Public License, v. 2.0. If a copy of the MPL was not distributed
# with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Web frontend for CVE -> RHSA report generator.
#
# Requires CherryPy, Mako, Scrubber, Python <= 2.7

import rhsac
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
        return tlu.get_template("index.html").render(rhelver="5")

    @cherrypy.expose
    def repgen(self, cves=None, platform="x86_64", host=None):
        scrubber.scrub(cves)

        if cves == None or cves == "":
            return "You didn't give me a list of CVEs :("

        if platform == None or platform == "":
            return "Somehow you managed to not give me a platform. :("

        if host == "":
            host = None

        checker = rhsac.CVEChecker()

        rhsalist = []

        cves = cves.split()

        for cve in cves:
            item = checker.get_cve_info(cve, platform, host)
            item['cve'] = scrubber.scrub(item['cve'])
            item['cve'] = fixemph.sub('<b class="emph">!!FIX!!</b>', item['cve'])
            rhsalist.append(item)

        return tlu.get_template("repgen.html").render(rhsalist=rhsalist)

    @cherrypy.expose
    def default(self):
        return "404"

if __name__ == "__main__":
    cherrypy.quickstart(RHSAGenWeb(), "/beta", "web.conf")
