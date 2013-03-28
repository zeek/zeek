# Needs perftools support.
#
# @TEST-REQUIRES: bro  --help 2>&1 | grep -q mem-leaks
#
# @TEST-GROUP: leaks
#
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local bro -m -r $TRACES/http/get.trace $SCRIPTS/file-analysis-test.bro %INPUT

redef test_file_analysis_source = "HTTP";

redef test_get_file_name = function(info: FileAnalysis::Info): string
	{
	return fmt("%s-file", info$file_id);
	};
