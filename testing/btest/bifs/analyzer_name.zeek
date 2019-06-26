#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = Analyzer::ANALYZER_PIA_TCP;
	print Analyzer::name(a);
	}
