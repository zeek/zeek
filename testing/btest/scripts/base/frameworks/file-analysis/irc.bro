# @TEST-EXEC: bro -r $TRACES/irc-dcc-send.trace $SCRIPTS/file-analysis-test.bro %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff thefile

redef test_file_analysis_source = "IRC_DATA";

redef test_get_file_name = function(f: fa_file): string
	{
	return "thefile";
	};
