@load ./main
@load base/utils/conn-ids
@load base/frameworks/file-analysis/main

module FTP;

export {
	## Default file handle provider for FTP.
	global get_file_handle: function(c: connection, is_orig: bool): string;
}

function get_handle_string(c: connection): string
	{
	return fmt("%s %s %s", ANALYZER_FTP_DATA, c$start_time, id_string(c$id));
	}

function get_file_handle(c: connection, is_orig: bool): string
	{
	if ( [c$id$resp_h, c$id$resp_p] !in ftp_data_expected ) return "";

	local info: FTP::Info = ftp_data_expected[c$id$resp_h, c$id$resp_p];

	if ( info$passive )
		# FTP client initiates data channel.
		if ( is_orig )
			# Don't care about FTP client data.
			return "";
		else
			# Do care about FTP server data.
			return get_handle_string(c);
	else
		# FTP server initiates dta channel.
		if ( is_orig )
			# Do care about FTP server data.
			return get_handle_string(c);
		else
			# Don't care about FTP client data.
			return "";
	}

module GLOBAL;

event get_file_handle(tag: AnalyzerTag, c: connection, is_orig: bool)
	{
	if ( tag != ANALYZER_FTP_DATA ) return;
	set_file_handle(FTP::get_file_handle(c, is_orig));
	}
