@load ./main
@load ./entities
@load base/utils/conn-ids
@load base/frameworks/file-analysis/main

module SMTP;

export {
	## Default file handle provider for SMTP.
	global get_file_handle: function(c: connection, is_orig: bool): string;
}

function get_file_handle(c: connection, is_orig: bool): string
	{
	if ( ! c?$smtp ) return "";
	return cat(ANALYZER_SMTP, " ", c$start_time, " ", c$smtp$trans_depth, " ",
	           c$smtp_state$mime_level);
	}

module GLOBAL;

event get_file_handle(tag: AnalyzerTag, c: connection, is_orig: bool)
	{
	if ( tag != ANALYZER_SMTP ) return;
	set_file_handle(SMTP::get_file_handle(c, is_orig));
	}
