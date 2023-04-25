# @TEST-EXEC: zeek -b -r $TRACES/irc-dcc-send.trace $SCRIPTS/file-analysis-test.zeek %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff --binary thefile

@load base/protocols/irc

redef test_file_analysis_source = "IRC_DATA";

function myfile(f: fa_file): string
	{
	return "thefile";
	}

redef test_get_file_name = myfile;
