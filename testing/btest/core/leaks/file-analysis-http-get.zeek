# Needs perftools support.
#
# @TEST-REQUIRES: zeek  --help 2>&1 | grep -q mem-leaks
#
# @TEST-GROUP: leaks
#
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run zeek zeek -m -r $TRACES/http/get.trace $SCRIPTS/file-analysis-test.zeek %INPUT
# @TEST-EXEC: btest-bg-wait 60

redef test_file_analysis_source = "HTTP";

redef test_get_file_name = function(f: fa_file): string
	{
	return fmt("%s-file", f$id);
	};
