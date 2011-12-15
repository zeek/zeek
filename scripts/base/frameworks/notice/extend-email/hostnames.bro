@load ../main

module Notice;

function lookup_addr_wrapper(n: Info, a: addr): string
	{
	return when ( local name = lookup_addr(a) )
		{
		return name;
		}
	}

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
		when ( local src_name = lookup_addr_wrapper(n, n$src) )
			{
			output = string_cat("orig/src hostname: ", src_name, "\n");
			n$email_body_sections[|n$email_body_sections|] = output;
			delete n$email_delay_tokens["hostnames-src"];
			}
		}
	if ( n?$dst )
		{
		add n$email_delay_tokens["hostnames-dst"];
		when ( local dst_name = lookup_addr_wrapper(n, n$dst) )
			{
			output = string_cat("resp/dst hostname: ", dst_name, "\n");
			n$email_body_sections[|n$email_body_sections|] = output;
			delete n$email_delay_tokens["hostnames-dst"];
			}
		}
	}
