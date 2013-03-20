@load ./main
@load ./entities
@load base/utils/conn-ids
@load base/frameworks/file-analysis/main

module SMTP;

function get_file_handle(c: connection, is_orig: bool): string
	{
	if ( ! c?$smtp ) return "";

	return fmt("%s %s %s %s", ANALYZER_SMTP, c$start_time, c$smtp$trans_depth,
	           c$smtp_state$mime_level);
	}

redef FileAnalysis::handle_callbacks += {
	[ANALYZER_SMTP] = get_file_handle,
};
