# @TEST-EXEC: bro -r $TRACES/http/pipelined-requests.trace $SCRIPTS/file-analysis-test.bro %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff aFQKI8SPOL2-file
# @TEST-EXEC: btest-diff CCU3vUEr06l-file
# @TEST-EXEC: btest-diff HCzA0dVwDPj-file
# @TEST-EXEC: btest-diff a1Zu1fteVEf-file
# @TEST-EXEC: btest-diff xXlF7wFdsR-file

redef test_file_analysis_source = "HTTP";

redef test_get_file_name = function(f: fa_file): string
	{
	return fmt("%s-file", f$id);
	};
