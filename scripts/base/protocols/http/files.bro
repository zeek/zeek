@load ./main
@load ./entities
@load ./utils
@load base/frameworks/files

module HTTP;

export {
	## Default file handle provider for HTTP.
	global get_file_handle: function(c: connection, is_orig: bool): string;
}

function get_file_handle(c: connection, is_orig: bool): string
	{
	if ( ! c?$http ) 
		return "";

	local mime_depth = is_orig ? c$http$orig_mime_depth : c$http$resp_mime_depth;
	if ( c$http$range_request )
		{
		return cat(Analyzer::ANALYZER_HTTP, is_orig, c$id$orig_h, mime_depth, build_url(c$http));
		}
	else
		{
		return cat(Analyzer::ANALYZER_HTTP, c$start_time, is_orig, 
		           c$http$trans_depth, mime_depth, id_string(c$id));
		}
	}

event bro_init() &priority=5
	{
	Files::register_protocol(Analyzer::ANALYZER_HTTP, HTTP::get_file_handle);
	}
