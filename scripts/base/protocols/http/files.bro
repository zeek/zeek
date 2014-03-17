@load ./main
@load ./entities
@load ./utils
@load base/utils/conn-ids
@load base/frameworks/files

module HTTP;

export {
	## Default file describer for HTTP.
	global describe_file: function(f: fa_file): string;
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
