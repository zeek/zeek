@load ./main
@load ./entities
@load base/utils/conn-ids
@load base/frameworks/files

module SMTP;

export {
	redef record Info += {
		## An ordered vector of file unique IDs seen attached to
		## the message.
		fuids: vector of string &log &default=string_vec();
	};

	## Default file handle provider for SMTP.
	global get_file_handle: function(c: connection, is_orig: bool): string;

	## Default file describer for SMTP.
	global describe_file: function(f: fa_file): string;
}

function get_file_handle(c: connection, is_orig: bool): string
	{
	return cat(Analyzer::ANALYZER_SMTP, c$start_time, c$smtp$trans_depth,
	           c$smtp_state$mime_depth);
	}

function describe_file(f: fa_file): string
	{
	# This shouldn't be needed, but just in case...
	if ( f$source != "SMTP" )
		return "";

	for ( cid in f$conns )
		{
		local c = f$conns[cid];
		return SMTP::describe(c$smtp);
		}
	return "";
	}

event bro_init() &priority=5
	{
	Files::register_protocol(Analyzer::ANALYZER_SMTP, 
	                         [$get_file_handle = SMTP::get_file_handle,
	                          $describe        = SMTP::describe_file]);
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool) &priority=5
	{
	if ( c?$smtp )
		c$smtp$fuids[|c$smtp$fuids|] = f$id;
	}
