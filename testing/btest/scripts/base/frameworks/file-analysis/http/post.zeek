# @TEST-EXEC: zeek -b -r $TRACES/http/post.trace $SCRIPTS/file-analysis-test.zeek %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff --binary 1-file
# @TEST-EXEC: btest-diff --binary 2-file

@load base/protocols/http

redef test_file_analysis_source = "HTTP";

global c = 0;

redef test_get_file_name = function(f: fa_file): string
	{
	return fmt("%d-file", ++c);
	};
