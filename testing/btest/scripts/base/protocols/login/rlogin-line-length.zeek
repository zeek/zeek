# @TEST-DOC: Ensures exceeding max line length triggers a weird in rlogin usernames
#
# @TEST-EXEC: zcat <$TRACES/contentline/rlogin-long-client-user-no-nul.pcapng.gz | zeek -b -r - %INPUT
# @TEST-EXEC: btest-diff-cut -m weird.log
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log

@load base/protocols/conn
@load base/frameworks/notice/weird

event zeek_init() {
	Analyzer::register_for_port(Analyzer::ANALYZER_RLOGIN, 513/tcp);
}
