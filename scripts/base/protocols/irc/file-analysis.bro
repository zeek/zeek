@load ./dcc-send
@load base/utils/conn-ids
@load base/frameworks/files

module IRC;

export {
	## Default file handle provider for IRC.
	global get_file_handle: function(c: connection, is_orig: bool): string;
}

function get_file_handle(c: connection, is_orig: bool): string
	{
	if ( [c$id$resp_h, c$id$resp_p] !in dcc_expected_transfers ) 
		return "";

	return cat(ANALYZER_IRC_DATA, c$start_time, c$id, is_orig);
	}

event bro_init() &priority=5
	{
	Files::register_protocol(ANALYZER_IRC_DATA, IRC::get_file_handle);
	}
