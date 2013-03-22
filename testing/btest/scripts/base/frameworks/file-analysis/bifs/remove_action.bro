# @TEST-EXEC: bro -r $TRACES/http/get.trace $SCRIPTS/file-analysis-test.bro %INPUT >get.out
# @TEST-EXEC: btest-diff get.out

redef test_file_analysis_source = "HTTP";

redef test_get_file_name = function(info: FileAnalysis::Info): string
	{
	return fmt("%s-file", info$file_id);
	};

hook FileAnalysis::policy(trig: FileAnalysis::Trigger, info: FileAnalysis::Info)
	{
	if ( trig != FileAnalysis::TRIGGER_TYPE ) return;
	for ( act in test_file_actions )
		FileAnalysis::remove_action(info$file_id, act);
	local filename = test_get_file_name(info);
	FileAnalysis::remove_action(info$file_id,
	                             [$act=FileAnalysis::ACTION_EXTRACT,
	                              $extract_filename=filename]);
	}
