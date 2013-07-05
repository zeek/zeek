@load ./main
@load ./entities
@load base/utils/conn-ids
@load base/frameworks/files

module SMTP;

export {
	## Default file handle provider for SMTP.
	global get_file_handle: function(c: connection, is_orig: bool): string;
}

function get_file_handle(c: connection, is_orig: bool): string
	{
	return cat(ANALYZER_SMTP, c$start_time, c$smtp$trans_depth,
	           c$smtp_state$mime_depth);
	}

event bro_init() &priority=5
	{
	Files::register_protocol(ANALYZER_SMTP, SMTP::get_file_handle);
	}
