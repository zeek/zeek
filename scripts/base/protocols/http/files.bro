@load ./main
@load ./entities
@load ./utils
@load base/frameworks/files

module HTTP;

export {
	redef record Info += {
		## An ordered vector of file unique IDs seen sent by the originator (client).
		orig_fuids:    vector of string &log &default=string_vec();

		## An ordered vector of file unique IDs seen sent by the responder (server).
		resp_fuids:    vector of string &log &default=string_vec();
	};

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

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool) &priority=5
	{
	if ( c?$http )
		{
		if ( f$is_orig )
			c$http$orig_fuids[|c$http$orig_fuids|] = f$id;
		else
			c$http$resp_fuids[|c$http$resp_fuids|] = f$id;
		}
	}
