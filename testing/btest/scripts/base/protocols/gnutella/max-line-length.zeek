# @TEST-DOC: Ensure the Gnutella analyzer cannot exceed a max line length
#
# @TEST-EXEC: zeek -b -r $TRACES/gnutella/max-line.pcapng %INPUT
# @TEST-EXEC: btest-diff weird.log
# @TEST-EXEC: btest-diff-cut -m history conn.log

@load base/protocols/conn
@load base/frameworks/notice/weird

# This will trigger before the end of the line and stop buffer growth
redef Gnutella::max_line_length = 100;
# This is the same, but the line length should break first
redef Gnutella::max_header_length = 100;

event zeek_init() {
	Analyzer::register_for_port(Analyzer::ANALYZER_GNUTELLA, 6346/tcp);
}
