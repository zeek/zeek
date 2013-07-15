@load ./main
@load base/utils/conn-ids
@load base/frameworks/files

module TFTP;

export {
	redef record Info += {
		## File unique ID.
		fuid: string &optional &log;
	};

	## Default file handle provider for TFTP.
	global get_file_handle: function(c: connection, is_orig: bool): string;
}

function get_file_handle(c: connection, is_orig: bool): string
	{
	#if ( [c$id$resp_h, c$id$resp_p] !in tftp_data_expected ) 
	#	return "";

	return cat(Analyzer::ANALYZER_TFTP, c$start_time, c$id, is_orig);
	}

event bro_init() &priority=5
	{
	Files::register_protocol(Analyzer::ANALYZER_TFTP, FTP::get_file_handle);
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool) &priority=5
	{
	#if ( [c$id$resp_h, c$id$resp_p] !in tftp_data_expected ) 
	#	return;

	#local tftp = tftp_data_expected[c$id$resp_h, c$id$resp_p];
	#tftp$fuid = f$id;
	#if ( f?$mime_type )
	#	tftp$mime_type = f$mime_type;
	}
