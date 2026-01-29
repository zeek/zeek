# @TEST-DOC: Disallow mixing different enum types.
#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

type color: enum { Red, White, Blue, };
type city: enum { Rome, Paris};

global e1 = Red;
global e2 = Rome;

event zeek_init()
	{
	print e1 == e2;
	}

global analyzers = set(Analyzer::ANALYZER_HTTP);
global packet_analyzers = set(PacketAnalyzer::ANALYZER_VXLAN);

event zeek_init()
	{
	for ( tag in analyzers )
		print tag;

	for ( tag in packet_analyzers )
		print tag;
	}
