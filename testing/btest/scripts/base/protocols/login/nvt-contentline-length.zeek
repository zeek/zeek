# @TEST-DOC: Ensures exceeding max line length triggers a weird in lines
#
# @TEST-EXEC: zcat <$TRACES/contentline/telnet-long-line-no-eol.pcapng.gz | zeek -b -r - %INPUT
# @TEST-EXEC: mv weird.log weird-long.log
# @TEST-EXEC: mv conn.log conn-long.log
# @TEST-EXEC: btest-diff-cut -m weird-long.log
# @TEST-EXEC: btest-diff-cut -m uid service history conn-long.log
#
# Regression test for a \n causing -1 element access when the limit is hit:
# @TEST-EXEC: zcat <$TRACES/contentline/nvt-line-limit-crlf-heap-buffer-overflow.pcap.gz | zeek -b -r - %INPUT
# @TEST-EXEC: mv conn.log conn-buffer-overflow.log
# @TEST-EXEC: mv weird.log weird-buffer-overflow.log
# @TEST-EXEC: btest-diff-cut -m weird-buffer-overflow.log
# @TEST-EXEC: btest-diff-cut -m uid service history conn-buffer-overflow.log

@load base/protocols/conn
@load base/protocols/ftp
@load base/frameworks/notice/weird

event zeek_init() {
	Analyzer::register_for_port(Analyzer::ANALYZER_TELNET, 23/tcp);
}
