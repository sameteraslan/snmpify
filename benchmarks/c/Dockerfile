# net-snmp's C library and the benchmark client built against it.
#   docker build -t snmpify-bench-netsnmp benchmarks/c
#   docker run --rm --network host snmpify-bench-netsnmp /usr/bin/time -f "RSS_KB %M" \
#     bench_netsnmp walk 127.0.0.1 16100 1
FROM ubuntu:26.04@sha256:d66b366dac61b575bee2aef07e9c26e8070096fbe84a3d4d3eb0da069b5d76db
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gcc libc6-dev libsnmp-dev time \
 && rm -rf /var/lib/apt/lists/*
COPY bench_netsnmp.c /src/
RUN gcc -O2 -o /usr/local/bin/bench_netsnmp /src/bench_netsnmp.c $(net-snmp-config --libs)
ENV MIBS=""
