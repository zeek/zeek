@load ./dcc-send.bro
@load base/utils/conn-ids
@load base/frameworks/file-analysis/main

redef FileAnalysis::handle_callbacks += {
	[ANALYZER_IRC_DATA] = function(c: connection, is_orig: bool): string
		{
		if ( is_orig ) return "";
		return fmt("%s %s %s", ANALYZER_IRC_DATA, c$start_time,
		           id_string(c$id));
		},
};
