@load ./info
@load ./main
@load ./utils
@load base/utils/conn-ids
@load base/frameworks/files

module FTP;

export {
	redef record Info += {
		## File unique ID.
		fuid: string &optional &log;
	};

	## Default file handle provider for FTP.
	global get_file_handle: function(c: connection, is_orig: bool): string;

	## Describe the file being transferred.
	global describe_file: function(f: fa_file): string;
}

function get_file_handle(c: connection, is_orig: bool): string
	{
	if ( [c$id$resp_h, c$id$resp_p] !in ftp_data_expected ) 
		return "";

	return cat(Analyzer::ANALYZER_FTP_DATA, c$start_time, c$id, is_orig);
	}

function describe_file(f: fa_file): string
	{
	# This shouldn't be needed, but just in case...
	if ( f$source != "FTP" )
		return "";

	for ( cid in f$conns )
		{
		if ( f$conns[cid]?$ftp )
			return FTP::describe(f$conns[cid]$ftp);
		}
	return "";
	}

event bro_init() &priority=5
	{
	Files::register_protocol(Analyzer::ANALYZER_FTP_DATA,
	                         [$get_file_handle = FTP::get_file_handle,
	                          $describe        = FTP::describe_file]);
	}


event file_over_new_connection(f: fa_file, c: connection, is_orig: bool) &priority=5
	{
	if ( [c$id$resp_h, c$id$resp_p] !in ftp_data_expected ) 
		return;

	local ftp = ftp_data_expected[c$id$resp_h, c$id$resp_p];
	ftp$fuid = f$id;
	if ( f?$mime_type )
		ftp$mime_type = f$mime_type;
	}
