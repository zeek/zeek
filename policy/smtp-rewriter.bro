# $Id: smtp-rewriter.bro 4758 2007-08-10 06:49:23Z vern $

@load smtp
@load mime 	# need mime for content hash

module SMTP;

redef rewriting_smtp_trace = T;

# We want this event handler to execute *after* the one in smtp.bro.
event smtp_request(c: connection, is_orig: bool, command: string, arg: string)
	{
	if ( ! rewriting_trace() )
		return;

	local session = smtp_sessions[c$id];

	if ( command != ">" )
		{
		if ( command == "." )
			{
			# A hack before we have MIME rewriter.
			# rewrite_smtp_data(c, is_orig, fmt("X-number-of-lines: %d",
			# 			session$num_lines_in_body));
			rewrite_smtp_data(c, is_orig, fmt("X-number-of-bytes: %d",
						session$num_bytes_in_body));

			# Write empty line to avoid MIME analyzer complaints.
			rewrite_smtp_data(c, is_orig, "");
			rewrite_smtp_data(c, is_orig, fmt("%s", session$content_hash));
			}

		if ( command in smtp_legal_cmds )
			{
			# Avoid the situation in which we mistake
			# mail contents for SMTP commands.
			rewrite_smtp_request(c, is_orig, command, arg);
			rewrite_push_packet(c, is_orig);
			}
		}
	}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string,
			msg: string, cont_resp: bool)
	{
	if ( ! rewriting_trace() )
		return;

	rewrite_smtp_reply(c, is_orig, code, msg, cont_resp);
	}

function starts_with_leading_whitespace(s: string): bool
	{
	return /^[ \t]/ in s;
	}

function rewrite_smtp_header_line(c: connection, is_orig: bool,
				session: smtp_session_info, line: string)
	{
	if ( starts_with_leading_whitespace(line) )
		{ # a continuing header
		if ( session$keep_current_header )
			rewrite_smtp_data(c, is_orig, line);
		}
	else
		{
		session$keep_current_header = F;

		local pair = split1(line, /:/);
		if ( length(pair) < 2 )
			{
			session$keep_current_header = T;
			rewrite_smtp_data(c, is_orig, line);
			}
		else
			{
			local field_name = to_upper(pair[1]);

			# Currently, the MIME analyzer is sensitive to
			# CONTENT-TYPE and CONTENT_TRANSFER_ENCODING,
			# so we want to remove these when anonymizing,
			# because we can't ensure their integrity when
			# rewriting message bodies.
			#
			# To be conservative, however, we strip out *all*
			# CONTENT-* headers.
			if ( /^CONTENT-/ !in field_name )
				{
				session$keep_current_header = T;
				rewrite_smtp_data(c, is_orig, line);
				}
			}
		}
	}
