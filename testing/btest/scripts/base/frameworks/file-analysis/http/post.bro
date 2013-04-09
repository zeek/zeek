# @TEST-EXEC: bro -r $TRACES/http/post.trace $SCRIPTS/file-analysis-test.bro %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff v5HLI7MxPQh-file
# @TEST-EXEC: btest-diff PZS1XGHkIf1-file

redef test_file_analysis_source = "HTTP";

redef test_get_file_name = function(f: fa_file): string
	{
	return fmt("%s-file", f$id);
	};
