FROM gliderlabs/alpine:3.2
RUN apk update && apk upgrade
RUN apk add py-pip ca-certificates
RUN pip install cherrypy beautifulsoup scrubber mako
RUN addgroup -g 998 cve
RUN adduser -h /cve -S -u 998 -G cve cvechecker
USER cvechecker
COPY start.sh cvechecker.py rhsac.py snmp.py web.py web.conf /cve/
COPY templates/ /cve/templates/
COPY static/ /cve/static/
WORKDIR /cve
VOLUME /cve/cache.db
EXPOSE 8080
CMD /usr/bin/python /cve/web.py
