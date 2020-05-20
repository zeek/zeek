# @TEST-EXEC: zeek -r $TRACES/http/multipart.trace $SCRIPTS/file-analysis-test.zeek %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff 1-file
# @TEST-EXEC: btest-diff 2-file
# @TEST-EXEC: btest-diff 3-file
# @TEST-EXEC: btest-diff 4-file

redef test_file_analysis_source = "HTTP";

global cnt: count = 0;

redef test_get_file_name = function(f: fa_file): string
	{
	++cnt;
	return fmt("%d-file", cnt);
	};
