@load ./main
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
}

function get_file_handle(c: connection, is_orig: bool): string
	{
	if ( [c$id$resp_h, c$id$resp_p] !in ftp_data_expected ) 
		return "";

	return cat(Analyzer::ANALYZER_FTP_DATA, c$start_time, c$id, is_orig);
	}

event bro_init() &priority=5
	{
	Files::register_protocol(Analyzer::ANALYZER_FTP_DATA, FTP::get_file_handle);
	}


event file_over_new_connection(f: fa_file, c: connection) &priority=5
	{
	if ( [c$id$resp_h, c$id$resp_p] !in ftp_data_expected ) 
		return;

	local ftp = ftp_data_expected[c$id$resp_h, c$id$resp_p];
	ftp$fuid = f$id;
	if ( f?$mime_type )
		ftp$mime_type = f$mime_type;
	}