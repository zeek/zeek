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

		## Tracks the fuid of the top-level RFC822 mail message if
		## :zeek:see:`SMTP::enable_rfc822_msg_file_analysis` is set.
		rfc822_msg_fuid: string &optional;
	};

	## Default file handle provider for SMTP.
	global get_file_handle: function(c: connection, is_orig: bool): string;

	## Default file describer for SMTP.
	global describe_file: function(f: fa_file): string;
}

function get_file_handle(c: connection, is_orig: bool): string
	{
	# Adding rfc822_msg_fuid here if set to ensure the top-level mail
	# message and the first MIME attachment do not get the same fuid allocated
	# when :zeek:see:`SMTP::enable_rfc822_msg_file_analysis` is set.
	return cat(Analyzer::ANALYZER_SMTP, c$start_time, c$smtp$trans_depth,
	           c$smtp?$rfc822_msg_fuid ? c$smtp$rfc822_msg_fuid : "",
	           c$smtp_state$mime_depth);
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
	                         Files::ProtoRegistration($get_file_handle = SMTP::get_file_handle,
	                                                  $describe        = SMTP::describe_file));
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool) &priority=5
	{
	if ( c?$smtp && !c$smtp$tls )
		{
		c$smtp$fuids += f$id;

		# If top-level messages are passed to the file analysis
		# framework, the first file within a SMTP transaction is
		# always the top-level RFC822 message. Keep track of it.
		#
		# This allows users to implement a low priority file_over_new_connection()
		# event and check for f$id == c$smtp$rfc822_msg_fuid to attach analyzers
		# to the RFC822 message specifically.
		if ( SMTP::enable_rfc822_msg_file_analysis )
			{
			if ( ! c$smtp?$rfc822_msg_fuid )
				c$smtp$rfc822_msg_fuid = f$id;
			else
				{
				# This is a file representing part of the RFC822
				# message (e.g. the body or a MIME part). If it
				# does not yet have a parent, attach the RFC822
				# fuid as the parent.
				if ( ! f?$parent_id )
					f$parent_id = c$smtp$rfc822_msg_fuid;
				}
			}
		}
	}
