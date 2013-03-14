@load ./main
@load ./utils
@load base/utils/conn-ids
@load base/frameworks/file-analysis/main

module HTTP;

function get_file_handle(c: connection, is_orig: bool): string
	{
	if ( ! c?$http ) return "";

	if ( c$http$range_request )
		return fmt("%s http(%s): %s: %s", c$start_time, is_orig,
		           c$id$orig_h, build_url(c$http));

	return fmt("%s http(%s, %s): %s", c$start_time, is_orig,
	           c$http$trans_depth, id_string(c$id));
	}

redef FileAnalysis::handle_callbacks += {
	[ANALYZER_HTTP] = get_file_handle,
};
