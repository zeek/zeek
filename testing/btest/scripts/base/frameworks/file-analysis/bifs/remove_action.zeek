# @TEST-EXEC: zeek -r $TRACES/http/get.trace $SCRIPTS/file-analysis-test.zeek %INPUT >get.out
# @TEST-EXEC: btest-diff get.out

redef test_file_analysis_source = "HTTP";

redef test_get_file_name = function(f: fa_file): string
	{
	return fmt("%s-file", f$id);
	};

event file_new(f: fa_file) &priority=-10
	{
	for ( tag in test_file_analyzers )
		Files::remove_analyzer(f, tag);
	local filename = test_get_file_name(f);
	Files::remove_analyzer(f, Files::ANALYZER_EXTRACT,
	                       [$extract_filename=filename]);
	}
