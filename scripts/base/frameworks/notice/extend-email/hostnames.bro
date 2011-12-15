@load ../main

module Notice;

event Notice::notice(n: Notice::Info) &priority=10
	{
	if ( ! n?$src && ! n?$dst )
		return;
	
	# This should only be done for notices that are being sent to email.
	if ( ACTION_EMAIL !in n$actions )
		return;
	
	# I'm not recovering gracefully from the when statements because I want 
	# the notice framework to detect that something has exceeded the maximum
	# allowed email delay and tell the user.
	
	local output = "";
	if ( n?$src )
		{
		add n$email_delay_tokens["hostnames-src"];
		when ( local src_name = lookup_addr(n$src) )
			{
			output = string_cat("orig_h/src hostname: ", src_name, "\n");
			n$email_body_sections[|n$email_body_sections|] = output;
			delete n$email_delay_tokens["hostnames-src"];
			}
		timeout max_email_delay+5secs { }
		}
	if ( n?$dst )
		{
		add n$email_delay_tokens["hostnames-dst"];
		when ( local dst_name = lookup_addr(n$dst) )
			{
			output = string_cat("resp_h/dst hostname: ", dst_name, "\n");
			n$email_body_sections[|n$email_body_sections|] = output;
			delete n$email_delay_tokens["hostnames-dst"];
			}
		timeout max_email_delay+5secs { }
		}
	}
