# @TEST-EXEC: zeek -r $TRACES/smtp.trace $SCRIPTS/file-analysis-test.zeek %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff thefile0
# @TEST-EXEC: btest-diff thefile1
# @TEST-EXEC: btest-diff thefile2

redef test_file_analysis_source = "SMTP";

global mycnt: count = 0;

redef test_get_file_name = function(f: fa_file): string
	{
	local rval: string = fmt("thefile%d", mycnt);
	++mycnt;
	return rval;
	};
