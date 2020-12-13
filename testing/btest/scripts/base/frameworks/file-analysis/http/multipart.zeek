# @TEST-EXEC: zeek -b -r $TRACES/http/multipart.trace $SCRIPTS/file-analysis-test.zeek %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff --binary 1-file
# @TEST-EXEC: btest-diff --binary 2-file
# @TEST-EXEC: btest-diff --binary 3-file
# @TEST-EXEC: btest-diff --binary 4-file

@load base/protocols/http

redef test_file_analysis_source = "HTTP";

global cnt: count = 0;

redef test_get_file_name = function(f: fa_file): string
	{
	++cnt;
	return fmt("%d-file", cnt);
	};
