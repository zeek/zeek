@load ./main
@load base/utils/conn-ids
@load base/frameworks/file-analysis/main

module FTP;

export {
	## Determines whether the default :bro:see:`get_file_handle` handler
	## is used to return file handles to the file analysis framework.
	## Redefine to true in order to provide a custom handler which overrides
	## the default for FTP.
	const disable_default_file_handle_provider: bool = F &redef;

	## Default file handle provider for FTP.
	function get_file_handle(c: connection, is_orig: bool): string
		{
		if ( is_orig ) return "";
		return fmt("%s %s %s", ANALYZER_FTP_DATA, c$start_time,
		           id_string(c$id));
		}
}

module GLOBAL;

event get_file_handle(tag: AnalyzerTag, c: connection, is_orig: bool)
	{
	if ( tag != ANALYZER_FTP_DATA ) return;
	if ( FTP::disable_default_file_handle_provider ) return;
	return_file_handle(FTP::get_file_handle(c, is_orig));
	}
