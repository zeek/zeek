# @TEST-EXEC: zeek -r $TRACES/ftp/retr.trace $SCRIPTS/file-analysis-test.zeek %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff thefile

redef test_file_analysis_source = "FTP_DATA";

redef test_get_file_name = function(f: fa_file): string
	{
	return "thefile";
	};
