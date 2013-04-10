# @TEST-EXEC: bro -r $TRACES/http/get.trace $SCRIPTS/file-analysis-test.bro %INPUT >get.out
# @TEST-EXEC: btest-diff get.out

redef test_file_analysis_source = "HTTP";

redef test_get_file_name = function(f: fa_file): string
	{
	return fmt("%s-file", f$id);
	};

event file_new(f: fa_file) &priority=-10
	{
	for ( act in test_file_actions )
		FileAnalysis::remove_action(f, act);
	local filename = test_get_file_name(f);
	FileAnalysis::remove_action(f, [$act=FileAnalysis::ACTION_EXTRACT,
	                                $extract_filename=filename]);
	}
