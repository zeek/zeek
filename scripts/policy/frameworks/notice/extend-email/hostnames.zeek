##! Loading this script extends the :zeek:enum:`Notice::ACTION_EMAIL` action
##! by appending to the email the hostnames associated with
##! :zeek:type:`Notice::Info`'s *src* and *dst* fields as determined by a
##! DNS lookup.

@load base/frameworks/notice/main

module Notice;

# We have to store references to the notices here because the when statement
# clones the frame which doesn't give us access to modify values outside
# of it's execution scope. (we get a clone of the notice instead of a
# reference to the original notice)
global tmp_notice_storage: table[string] of Notice::Info &create_expire=max_email_delay+10secs;

# Run after e-mail address is set, but before e-mail is sent.
hook notice(n: Notice::Info) &priority=-1
	{
	if ( ! n?$src && ! n?$dst )
		return;

	# This should only be done for notices that are being sent to email.
	if ( |n$email_dest| == 0 )
		return;

	# I'm not recovering gracefully from the when statements because I want
	# the notice framework to detect that something has exceeded the maximum
	# allowed email delay and tell the user.
	local uid = unique_id("");
	tmp_notice_storage[uid] = n;

	local output = "";
	if ( n?$src )
		{
		add n$email_delay_tokens["hostnames-src"];
		when [n, uid, output] ( local src_name = lookup_addr(n$src) )
			{
			output = string_cat("orig/src hostname: ", src_name, "\n");
			tmp_notice_storage[uid]$email_body_sections += output;
			delete tmp_notice_storage[uid]$email_delay_tokens["hostnames-src"];
			}
		}
	if ( n?$dst )
		{
		add n$email_delay_tokens["hostnames-dst"];
		when [n, uid, output] ( local dst_name = lookup_addr(n$dst) )
			{
			output = string_cat("resp/dst hostname: ", dst_name, "\n");
			tmp_notice_storage[uid]$email_body_sections += output;
			delete tmp_notice_storage[uid]$email_delay_tokens["hostnames-dst"];
			}
		}
	}
