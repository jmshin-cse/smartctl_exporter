ARG ARCH="amd64"
ARG OS="linux"
FROM alpine:3.23
LABEL maintainer="The Prometheus Authors <prometheus-developers@googlegroups.com>"

# smartmontools (7.5 from alpine 3.23 apk) + tools needed for drivedb fetch
RUN apk add --no-cache smartmontools wget ca-certificates

# Fetch latest drivedb.h from upstream with 3-URL fallback chain.
# If all URLs fail (offline build, etc.), the alpine package's bundled
# drivedb is used instead — build still succeeds.
ARG DRIVEDB_BUST=stable
RUN echo "=== Fetching latest drivedb.h (DRIVEDB_BUST=${DRIVEDB_BUST}) ===" \
 && BEFORE=$(stat -c '%s' /usr/share/smartmontools/drivedb.h 2>/dev/null || echo 0) \
 && ( wget -q --tries=2 --timeout=20 -O /tmp/drivedb-latest.h \
        'https://www.smartmontools.org/export/HEAD/trunk/smartmontools/drivedb.h' \
   || wget -q --tries=2 --timeout=20 -O /tmp/drivedb-latest.h \
        'https://raw.githubusercontent.com/smartmontools/smartmontools/master/smartmontools/drivedb.h' \
   || wget -q --tries=2 --timeout=20 -O /tmp/drivedb-latest.h \
        'https://svn.smartmontools.org/svn/trunk/smartmontools/drivedb.h' ) \
 && [ -s /tmp/drivedb-latest.h ] \
 && cp /tmp/drivedb-latest.h /usr/share/smartmontools/drivedb.h \
 && AFTER=$(stat -c '%s' /usr/share/smartmontools/drivedb.h) \
 && echo "drivedb.h: ${BEFORE}B -> ${AFTER}B (latest from upstream)" \
 || echo "WARN: drivedb fetch failed (all URLs); keeping alpine package's bundled drivedb"

ARG ARCH="amd64"
ARG OS="linux"
COPY .build/${OS}-${ARCH}/smartctl_exporter /bin/smartctl_exporter

EXPOSE      9633
USER        nobody
ENTRYPOINT  [ "/bin/smartctl_exporter" ]
