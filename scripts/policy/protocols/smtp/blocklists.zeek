##! Watch for various SPAM blocklist URLs in SMTP error messages.

@load base/protocols/smtp
@load base/frameworks/notice

module SMTP;

export {
	redef enum Notice::Type += {
		## An SMTP server sent a reply mentioning an SMTP block list.
		Blocklist_Error_Message,
		## The originator's address is seen in the block list error message.
		## This is useful to detect local hosts sending SPAM with a high
		## positive rate.
		Blocklist_Blocked_Host,
	};

	# This matches content in SMTP error messages that indicate some
	# block list doesn't like the connection/mail.
	option blocklist_error_messages =
		  /spamhaus\.org\//
		| /sophos\.com\/security\//
		| /spamcop\.net\/bl/
		| /cbl\.abuseat\.org\//
		| /sorbs\.net\//
		| /bsn\.borderware\.com\//
		| /mail-abuse\.com\//
		| /b\.barracudacentral\.com\//
		| /psbl\.surriel\.com\//
		| /antispam\.imp\.ch\//
		| /dyndns\.com\/.*spam/
		| /rbl\.knology\.net\//
		| /intercept\.datapacket\.net\//
		| /uceprotect\.net\//
		| /hostkarma\.junkemailfilter\.com\//;

}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string,
                 msg: string, cont_resp: bool) &priority=3
	{
	if ( code >= 400 && code != 421 )
		{
		# Raise a notice when an SMTP error about a block list is discovered.
		if ( blocklist_error_messages in msg )
			{
			local note = Blocklist_Error_Message;
			local message = fmt("%s received an error message mentioning an SMTP block list", c$id$orig_h);

			# Determine if the originator's IP address is in the message.
			local ips = extract_ip_addresses(msg);
			local text_ip = "";
			if ( |ips| > 0 && to_addr(ips[0]) == c$id$orig_h )
				{
				note = Blocklist_Blocked_Host;
				message = fmt("%s is on an SMTP block list", c$id$orig_h);
				}

			NOTICE([$note=note, $conn=c, $msg=message, $sub=msg,
			        $identifier=cat(c$id$orig_h)]);
			}
		}
	}
