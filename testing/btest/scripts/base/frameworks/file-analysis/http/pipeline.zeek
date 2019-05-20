# @TEST-EXEC: zeek -r $TRACES/http/pipelined-requests.trace $SCRIPTS/file-analysis-test.zeek %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff 1-file
# @TEST-EXEC: btest-diff 2-file
# @TEST-EXEC: btest-diff 3-file
# @TEST-EXEC: btest-diff 4-file
# @TEST-EXEC: btest-diff 5-file

redef test_file_analysis_source = "HTTP";

global c = 0;

redef test_get_file_name = function(f: fa_file): string
	{
	return fmt("%d-file", ++c);
	};
