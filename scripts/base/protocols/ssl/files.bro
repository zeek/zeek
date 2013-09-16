@load ./main
@load base/utils/conn-ids
@load base/frameworks/files

module SSL;

export {
	redef record Info += {
		## An ordered vector of file unique IDs which contains
		## all the certificates sent over the connection
		fuids: vector of string &log &default=string_vec();
	};

	## Default file handle provider for SSL.
	global get_file_handle: function(c: connection, is_orig: bool): string;

	## Default file describer for SSL.
	global describe_file: function(f: fa_file): string;
}

function get_file_handle(c: connection, is_orig: bool): string
	{
	return cat(Analyzer::ANALYZER_SMTP, c$start_time);
	}

function describe_file(f: fa_file): string
	{
	# This shouldn't be needed, but just in case...
	if ( f$source != "SSL" )
		return "";

	return "";
	}

event bro_init() &priority=5
	{
	Files::register_protocol(Analyzer::ANALYZER_SSL, 
	                         [$get_file_handle = SSL::get_file_handle,
	                          $describe        = SSL::describe_file]);
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool) &priority=5
	{
	if ( c?$ssl )
		c$ssl$fuids[|c$ssl$fuids|] = f$id;

	Files::add_analyzer(f, Files::ANALYZER_X509);
	}
