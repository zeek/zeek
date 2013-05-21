@load ./main
@load ./utils
@load base/utils/conn-ids
@load base/frameworks/file-analysis/main

module HTTP;

export {
	redef record HTTP::Info += {
		## Number of MIME entities in the HTTP request message body so far.
		request_mime_level: count &default=0;
		## Number of MIME entities in the HTTP response message body so far.
		response_mime_level: count &default=0;
	};

	## Default file handle provider for HTTP.
	global get_file_handle: function(c: connection, is_orig: bool): string;
}

event http_begin_entity(c: connection, is_orig: bool) &priority=5
	{
	if ( ! c?$http ) return;

	if ( is_orig )
		++c$http$request_mime_level;
	else
		++c$http$response_mime_level;
	}

function get_file_handle(c: connection, is_orig: bool): string
	{
	if ( ! c?$http ) return "";

	local mime_level: count =
	        is_orig ? c$http$request_mime_level : c$http$response_mime_level;
	local mime_level_str: string = mime_level > 1 ? cat(mime_level) : "";

	if ( c$http$range_request )
		return cat(ANALYZER_HTTP, " ", is_orig, " ", c$id$orig_h, " ",
		           build_url(c$http));

	return cat(ANALYZER_HTTP, " ", c$start_time, " ", is_orig, " ",
	           c$http$trans_depth, mime_level_str, " ", id_string(c$id));
	}

module GLOBAL;

event get_file_handle(tag: AnalyzerTag, c: connection, is_orig: bool)
	&priority=5
	{
	if ( tag != ANALYZER_HTTP ) return;
	set_file_handle(HTTP::get_file_handle(c, is_orig));
	}
