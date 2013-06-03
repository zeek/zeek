# @TEST-EXEC: bro -r $TRACES/http/multipart.trace $SCRIPTS/file-analysis-test.bro %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff TJdltRTxco1-file
# @TEST-EXEC: btest-diff QJO04kPdawk-file
# @TEST-EXEC: btest-diff dDH5dHdsRH4-file
# @TEST-EXEC: btest-diff TaUJcEIboHh-file

redef test_file_analysis_source = "HTTP";

redef test_get_file_name = function(f: fa_file): string
	{
	return fmt("%s-file", f$id);
	};
