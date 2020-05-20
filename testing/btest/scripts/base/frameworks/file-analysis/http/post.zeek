# @TEST-EXEC: zeek -r $TRACES/http/post.trace $SCRIPTS/file-analysis-test.zeek %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff 1-file
# @TEST-EXEC: btest-diff 2-file

redef test_file_analysis_source = "HTTP";

global c = 0;

redef test_get_file_name = function(f: fa_file): string
	{
	return fmt("%d-file", ++c);
	};
