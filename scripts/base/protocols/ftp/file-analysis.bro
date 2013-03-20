@load ./main
@load base/utils/conn-ids
@load base/frameworks/file-analysis/main

redef FileAnalysis::handle_callbacks += {
	[ANALYZER_FTP_DATA] = function(c: connection, is_orig: bool): string
		{
		if ( is_orig ) return "";
		return fmt("%s %s %s", ANALYZER_FTP_DATA, c$start_time,
		           id_string(c$id));
		},
};
