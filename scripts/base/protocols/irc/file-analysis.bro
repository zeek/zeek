@load ./dcc-send.bro
@load base/utils/conn-ids
@load base/frameworks/file-analysis/main

redef FileAnalysis::service_handle_callbacks += {
	["irc-dcc-data"] = function(c: connection, is_orig: bool): string
		{
		if ( is_orig ) return "";
		return fmt("%s irc-dcc-data: %s", c$start_time, id_string(c$id));
		},
};
