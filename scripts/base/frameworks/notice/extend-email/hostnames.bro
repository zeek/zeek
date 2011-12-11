@load ../main

module Notice;

# This probably doesn't actually work due to the async lookup_addr.
event Notice::notice(n: Notice::Info) &priority=10
	{
	if ( ! n?$src && ! n?$dst )
		return;
	
	# This should only be done for notices that are being sent to email.
	if ( ACTION_EMAIL !in n$actions )
		return;
		
	local output = "";
	if ( n?$src )
		{
		when ( local src_name = lookup_addr(n$src) )
			{
			output = string_cat("orig_h/src hostname: ", src_name, "\n");
			n$email_body_sections[|n$email_body_sections|] = output;
			}
		}
	if ( n?$dst )
		{
		when ( local dst_name = lookup_addr(n$dst) )
			{
			output = string_cat("resp_h/dst hostname: ", dst_name, "\n");
			n$email_body_sections[|n$email_body_sections|] = output;
			}
		}
	}
