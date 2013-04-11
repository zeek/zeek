@load ./dcc-send.bro
@load base/utils/conn-ids
@load base/frameworks/file-analysis/main

module IRC;

export {
	## Default file handle provider for IRC.
	global get_file_handle: function(c: connection, is_orig: bool): string;
}

function get_file_handle(c: connection, is_orig: bool): string
	{
	if ( is_orig ) return "";
	return fmt("%s %s %s", ANALYZER_IRC_DATA, c$start_time, id_string(c$id));
	}

module GLOBAL;

event get_file_handle(tag: AnalyzerTag, c: connection, is_orig: bool)
	{
	if ( tag != ANALYZER_IRC_DATA ) return;
	set_file_handle(IRC::get_file_handle(c, is_orig));
	}
