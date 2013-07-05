#
# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	local a = Analyzer::ANALYZER_PIA_TCP;
	print Analyzer::name(a);
	}
