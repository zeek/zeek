@load ./main
@load ./entities
@load base/utils/conn-ids
@load base/frameworks/file-analysis/main

module SMTP;

export {
	## Determines whether the default :bro:see:`get_file_handle` handler
	## is used to return file handles to the file analysis framework.
	## Redefine to true in order to provide a custom handler which overrides
	## the default for SMTP.
	const disable_default_file_handle_provider: bool = F &redef;

	## Default file handle provider for SMTP.
	function get_file_handle(c: connection, is_orig: bool): string
		{
		if ( ! c?$smtp ) return "";

		return cat(ANALYZER_SMTP, " ", c$start_time, " ",
		           c$smtp$trans_depth, " ", c$smtp_state$mime_level);
		}
}

module GLOBAL;

event get_file_handle(tag: AnalyzerTag, c: connection, is_orig: bool)
	{
	if ( tag != ANALYZER_SMTP ) return;
	if ( SMTP::disable_default_file_handle_provider ) return;
	return_file_handle(SMTP::get_file_handle(c, is_orig));
	}
