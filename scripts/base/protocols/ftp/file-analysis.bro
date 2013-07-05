@load ./main
@load base/utils/conn-ids
@load base/frameworks/files

module FTP;

export {
	## Default file handle provider for FTP.
	global get_file_handle: function(c: connection, is_orig: bool): string;
}

function get_file_handle(c: connection, is_orig: bool): string
	{
	if ( [c$id$resp_h, c$id$resp_p] !in ftp_data_expected ) 
		return "";

	return cat(ANALYZER_FTP_DATA, c$start_time, c$id, is_orig);
	}

event bro_init() &priority=5
	{
	Files::register_protocol(ANALYZER_FTP_DATA, FTP::get_file_handle);
	}
