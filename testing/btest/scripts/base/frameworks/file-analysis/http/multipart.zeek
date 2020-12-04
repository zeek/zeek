# @TEST-EXEC: zeek -b -r $TRACES/http/multipart.trace $SCRIPTS/file-analysis-test.zeek %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: env -u TEST_DIFF_CANONIFIER btest-diff 1-file
# @TEST-EXEC: env -u TEST_DIFF_CANONIFIER btest-diff 2-file
# @TEST-EXEC: env -u TEST_DIFF_CANONIFIER btest-diff 3-file
# @TEST-EXEC: env -u TEST_DIFF_CANONIFIER btest-diff 4-file

@load base/protocols/http

redef test_file_analysis_source = "HTTP";

global cnt: count = 0;

redef test_get_file_name = function(f: fa_file): string
	{
	++cnt;
	return fmt("%d-file", cnt);
	};
