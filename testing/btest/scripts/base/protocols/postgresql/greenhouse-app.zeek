# @TEST-DOC: Read a pcap created from the greenhouse testing app of the Loki fundamentals: https://github.com/grafana/loki-fundamentals
#
# @TEST-REQUIRES: ${SCRIPTS}/have-spicy
# @TEST-EXEC: zeek -b -C -r ${TRACES}/postgresql/greenhouse-app.pcap %INPUT
#
# @TEST-EXEC: test ! -f analyzer.log
# @TEST-EXEC: btest-diff-cut -m uid id.orig_h id.orig_p id.resp_h id.resp_p history service conn.log
# @TEST-EXEC: btest-diff-cut -m postgresql.log

@load base/protocols/conn
@load base/protocols/postgresql
