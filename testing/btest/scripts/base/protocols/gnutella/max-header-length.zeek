# @TEST-DOC: Ensure the Gnutella analyzer cannot exceed a max line length
#
# @TEST-EXEC: zeek -b -r $TRACES/gnutella/max-header.pcapng %INPUT
# @TEST-EXEC: btest-diff weird.log
# @TEST-EXEC: btest-diff-cut -m history conn.log

@load base/protocols/conn
@load base/frameworks/notice/weird

# Make sure this is never exceeded
redef Gnutella::max_line_length = 100;
# But this gets exceeded!
redef Gnutella::max_header_length = 200;

event zeek_init() {
	Analyzer::register_for_port(Analyzer::ANALYZER_GNUTELLA, 6346/tcp);
}
