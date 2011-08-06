
module Notice;

# This probably doesn't actually work due to the async lookup_addr.
event Notice::notice(n: Notice::Info) &priority=10
	{
	if ( ! n?$src && ! n?$dst )
		return;
	
	local output = "";
	if ( n?$src )
		{
		when ( local src_name = lookup_addr(n$src) )
			{
			output = cat(output, "orig_h/src: ", src_name, "\n");
			}
		timeout 5secs
			{
			output = cat(output, "orig_h/src: <timeout>\n");
			}
		}
	if ( n?$dst )
		{
		when ( local dst_name = lookup_addr(n$dst) )
			{
			output = cat(output, "resp_h/dst: ", dst_name, "\n");
			}
		timeout 5secs
			{
			output = cat(output, "resp_h/dst: <timeout>\n");
			}
		}
	
	if ( output != "" )
		n$email_body_sections[|n$email_body_sections|] = output;
	}