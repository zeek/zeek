@load ./main
@load ./entities
@load ./utils
@load base/utils/conn-ids
@load base/frameworks/files

module HTTP;

export {
	## Default file handle provider for HTTP.
	global get_file_handle: function(c: connection, is_orig: bool): string;

	## Default file describer for HTTP.
	global describe_file: function(f: fa_file): string;
}

function get_file_handle(c: connection, is_orig: bool): string
	{
	if ( ! c?$http )
		return "";

	if ( c$http$range_request && ! is_orig )
		{
		# Any multipart responses from the server are pieces of same file
		# that correspond to range requests, so don't use mime depth to
		# identify the file.
		return cat(Analyzer::ANALYZER_HTTP, is_orig, c$id$orig_h, build_url(c$http));
		}
	else
		{
		local mime_depth = is_orig ? c$http$orig_mime_depth : c$http$resp_mime_depth;
		return cat(Analyzer::ANALYZER_HTTP, c$start_time, is_orig,
		           c$http$trans_depth, mime_depth, id_string(c$id));
		}
	}

function describe_file(f: fa_file): string
	{
	# This shouldn't be needed, but just in case...
	if ( f$source != "HTTP" )
		return "";

	for ( cid in f$conns )
		{
		if ( f$conns[cid]?$http )
			return build_url_http(f$conns[cid]$http);
		}
	return "";
	}

event bro_init() &priority=5
	{
	Files::register_protocol(Analyzer::ANALYZER_HTTP,
	                         [$get_file_handle = HTTP::get_file_handle,
	                          $describe        = HTTP::describe_file]);
	}
