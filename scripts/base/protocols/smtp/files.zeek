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

		## Tracks the fuid of the mail message if
		## :zeek:see:`SMTP::enable_mail_data_file_analysis` is set.
		mail_fuid: string &optional;
	};

	## Default file handle provider for SMTP.
	global get_file_handle: function(c: connection, is_orig: bool): string;

	## Default file describer for SMTP.
	global describe_file: function(f: fa_file): string;
}

event smtp_mail_data_file(f: fa_file, c: connection)
	{
	c$smtp$mail_fuid = f$id;
	}

function get_file_handle(c: connection, is_orig: bool): string
	{
	# Adding mail_fuid here if set to ensure the top-level mail message
	# and the first MIME attachment do not get the same fuid allocated.
	return cat(Analyzer::ANALYZER_SMTP, c$start_time, c$smtp$trans_depth,
	           c$smtp?$mail_fuid ? c$smtp$mail_fuid : "", c$smtp_state$mime_depth);
	}

function describe_file(f: fa_file): string
	{
	# This shouldn't be needed, but just in case...
	if ( f$source != "SMTP" )
		return "";

	for ( _, c in f$conns )
		{
		return SMTP::describe(c$smtp);
		}
	return "";
	}

event zeek_init() &priority=5
	{
	Files::register_protocol(Analyzer::ANALYZER_SMTP,
	                         [$get_file_handle = SMTP::get_file_handle,
	                          $describe        = SMTP::describe_file]);
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool) &priority=5
	{
	if ( c?$smtp && !c$smtp$tls )
		{
		c$smtp$fuids += f$id;

		# If the file doesn't yet have a parent and the top-level
		# mail is being sent to file analysis, use its id as parent.
		if ( ! f?$parent_id && c$smtp?$mail_fuid )
			f$parent_id = c$smtp$mail_fuid;
		}
	}
