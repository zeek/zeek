##! Utilities specific for FTP processing.

@load ./info
@load base/utils/addrs
@load base/utils/paths

module FTP;

export {
	## Creates a URL from an :bro:type:`FTP::Info` record.
	##
	## rec: An :bro:type:`FTP::Info` record.
	##
	## Returns: A URL, not prefixed by ``"ftp://"``.
	global build_url: function(rec: Info): string;

	## Creates a URL from an :bro:type:`FTP::Info` record.
	##
	## rec: An :bro:type:`FTP::Info` record.
	##
	## Returns: A URL prefixed with ``"ftp://"``.
	global build_url_ftp: function(rec: Info): string;

	## Create an extremely shortened representation of a log line.
	global describe: function(rec: Info): string;
}

function build_url(rec: Info): string
	{
	if ( !rec?$arg )
		return "";

	local comp_path = build_path_compressed(rec$cwd, rec$arg);
	if ( comp_path[0] != "/" )
		comp_path = cat("/", comp_path);

	return fmt("%s%s", addr_to_uri(rec$id$resp_h), comp_path);
	}

function build_url_ftp(rec: Info): string
	{
	return fmt("ftp://%s", build_url(rec));
	}

function describe(rec: Info): string
	{
	return build_url_ftp(rec);
	}
