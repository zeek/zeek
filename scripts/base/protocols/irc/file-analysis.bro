@load ./dcc-send.bro
@load base/utils/conn-ids
@load base/frameworks/file-analysis/main

module IRC;

export {
	## Determines whether the default :bro:see:`get_file_handle` handler
	## is used to return file handles to the file analysis framework.
	## Redefine to true in order to provide a custom handler which overrides
	## the default for IRC.
	const disable_default_file_handle_provider: bool = F &redef;

	## Default file handle provider for IRC.
	function get_file_handle(c: connection, is_orig: bool): string
		{
		if ( is_orig ) return "";
		return fmt("%s %s %s", ANALYZER_IRC_DATA, c$start_time,
		           id_string(c$id));
		}
}

module GLOBAL;

event get_file_handle(tag: AnalyzerTag, c: connection, is_orig: bool)
	{
	if ( tag != ANALYZER_IRC_DATA ) return;
	if ( IRC::disable_default_file_handle_provider ) return;
	return_file_handle(IRC::get_file_handle(c, is_orig));
	}
