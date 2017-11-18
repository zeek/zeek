##! Loading this script extends the :bro:enum:`Notice::ACTION_EMAIL` action
##! by appending to the email the hostnames associated with
##! :bro:type:`Notice::Info`'s *src* and *dst* fields as determined by a
##! DNS lookup.

@load ../main

module Notice;

hook notice(n: Notice::Info) &priority=10
	{
	if ( ! n?$src && ! n?$dst )
		return;

	# This should only be done for notices that are being sent to email.
	if ( ACTION_EMAIL !in n$actions )
		return;

	local uid = unique_id("");

	local output = "";
	if ( n?$src )
		{
		add n$email_delay_tokens["hostnames-src"];
		local src_name = async lookup_addr(n$src);
		output = string_cat("orig/src hostname: ", src_name, "\n");
		n$email_body_sections[|n$email_body_sections|] = output;
		}
	if ( n?$dst )
		{
		add n$email_delay_tokens["hostnames-dst"];
		local dst_name = async lookup_addr(n$dst);
		output = string_cat("resp/dst hostname: ", dst_name, "\n");
		n$email_body_sections[|n$email_body_sections|] = output;
		}
	}
