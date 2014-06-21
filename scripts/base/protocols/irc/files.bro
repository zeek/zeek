@load ./dcc-send
@load base/utils/conn-ids
@load base/frameworks/files

module IRC;

export {
	redef record Info += {
		## File unique ID.
		fuid: string &log &optional;
	};

	## Default file handle provider for IRC.
	global get_file_handle: function(c: connection, is_orig: bool): string;
}

function get_file_handle(c: connection, is_orig: bool): string
	{
	return cat(Analyzer::ANALYZER_IRC_DATA, c$start_time, c$id, is_orig);
	}

event bro_init() &priority=5
	{
	Files::register_protocol(Analyzer::ANALYZER_IRC_DATA,
	                         [$get_file_handle = IRC::get_file_handle]);
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool) &priority=5
	{
	if ( [c$id$resp_h, c$id$resp_p] !in dcc_expected_transfers ) 
		return;

	local irc = dcc_expected_transfers[c$id$resp_h, c$id$resp_p];
	irc$fuid = f$id;
	if ( irc?$dcc_file_name )
		f$info$filename = irc$dcc_file_name;
	if ( f?$mime_type )
		irc$dcc_mime_type = f$mime_type;
	}
