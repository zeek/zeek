# @TEST-DOC: Test that misc/dump events works.
#
# @TEST-REQUIRES: ${SCRIPTS}/have-spicy
# @TEST-EXEC: zeek -b -r ${TRACES}/postgresql/psql-select-now.pcap %INPUT >>output
# @TEST-EXEC: zeek -b -r ${TRACES}/postgresql/psql-insert-fail-drop-fail.pcap %INPUT >>output
#
# @TEST-EXEC: btest-diff output

@load base/protocols/postgresql/spicy-events.zeek
@load misc/dump-events

redef DumpEvents::dump_all_events = T;
redef DumpEvents::include=/^(PostgreSQL|analyzer_)/;

event zeek_init() {
	Analyzer::register_for_port(Analyzer::ANALYZER_POSTGRESQL, 5432/tcp);
}
