# @TEST-EXEC: zeek -r $TRACES/irc-dcc-send.trace $SCRIPTS/file-analysis-test.zeek %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff thefile

redef test_file_analysis_source = "IRC_DATA";

global first: bool = T;

function myfile(f: fa_file): string
	{
	if ( first )
		{
		first = F;
		return "thefile";
		}
	else
		return "";
	}

redef test_get_file_name = myfile;
