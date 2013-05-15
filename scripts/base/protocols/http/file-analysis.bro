@load ./main
@load ./utils
@load base/utils/conn-ids
@load base/frameworks/file-analysis/main

module HTTP;

export {
	## Default file handle provider for HTTP.
	global get_file_handle: function(c: connection, is_orig: bool): string;
}

function get_file_handle(c: connection, is_orig: bool): string
	{
	if ( ! c?$http ) return "";

	if ( c$http$range_request )
		return cat(ANALYZER_HTTP, " ", is_orig, " ", c$id$orig_h, " ",
		           build_url(c$http));

	return cat(ANALYZER_HTTP, " ", c$start_time, " ", is_orig, " ",
	           c$http$trans_depth, " ", id_string(c$id));
	}

module GLOBAL;

event get_file_handle(tag: AnalyzerTag, c: connection, is_orig: bool)
	{
	if ( tag != ANALYZER_HTTP ) return;
	set_file_handle(HTTP::get_file_handle(c, is_orig));
	}
