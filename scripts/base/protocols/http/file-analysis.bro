@load ./main
@load ./utils
@load base/utils/conn-ids
@load base/frameworks/files

module HTTP;

export {
	redef record Info += {
		## The sniffed mime type of the data being sent by the client.
		client_mime_type: string &log &optional;

		## The sniffed mime type of the data being returned by the server.
		mime_type:        string &log &optional;
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
		return cat(ANALYZER_HTTP, is_orig, c$id$orig_h, mime_depth, build_url(c$http));
		}
	else
		{
		return cat(ANALYZER_HTTP, c$start_time, is_orig, 
		           c$http$trans_depth, mime_depth, id_string(c$id));
		}
	}

event bro_init() &priority=5
	{
	Files::register_protocol(ANALYZER_HTTP, HTTP::get_file_handle);
	}

event file_over_new_connection(f: fa_file, c: connection) &priority=5
	{
	if ( c?$http )
		{
		#if (!f?$mime_type)
		#	print f;
#
		#if ( f$is_orig )
		#	c$http$client_mime_type = f$mime_type;
		#else
		#	c$http$mime_type = f$mime_type;

		if ( c$http?$filename )
			f$info$filename = c$http$filename;
		}
	}