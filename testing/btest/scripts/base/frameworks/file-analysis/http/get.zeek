# @TEST-EXEC: zeek -r $TRACES/http/get.trace $SCRIPTS/file-analysis-test.zeek %INPUT c=1 >get.out
# @TEST-EXEC: zeek -r $TRACES/http/get-gzip.trace $SCRIPTS/file-analysis-test.zeek %INPUT c=2 >get-gzip.out
# @TEST-EXEC: btest-diff get.out
# @TEST-EXEC: btest-diff get-gzip.out
# @TEST-EXEC: btest-diff 1-file
# @TEST-EXEC: btest-diff 2-file

redef test_file_analysis_source = "HTTP";

global c = 0 &redef;

redef test_get_file_name = function(f: fa_file): string
	{
	return fmt("%d-file", c);
	};
