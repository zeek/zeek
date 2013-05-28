# @TEST-EXEC: bro -r $TRACES/http/get.trace $SCRIPTS/file-analysis-test.bro %INPUT >get.out
# @TEST-EXEC: bro -r $TRACES/http/get-gzip.trace $SCRIPTS/file-analysis-test.bro %INPUT >get-gzip.out
# @TEST-EXEC: btest-diff get.out
# @TEST-EXEC: btest-diff get-gzip.out
# @TEST-EXEC: btest-diff Cx92a0ym5R8-file
# @TEST-EXEC: btest-diff kg59rqyYxN-file

redef test_file_analysis_source = "HTTP";

redef test_get_file_name = function(f: fa_file): string
	{
	return fmt("%s-file", f$id);
	};
