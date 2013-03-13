@load ./main
@load base/utils/conn-ids
@load base/frameworks/file-analysis/main

redef FileAnalysis::service_handle_callbacks += {
	["ftp-data"] = function(c: connection, is_orig: bool): string
		{
		return fmt("%s ftp-data: %s", c$start_time, id_string(c$id));
		},
};
