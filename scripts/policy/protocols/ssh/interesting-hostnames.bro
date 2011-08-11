@load base/frameworks/notice/main

module SSH;

export {
	redef enum Notice::Type += {
		## Generated if a login originates from a host matched by the 
		## :bro:id:`interesting_hostnames` regular expression.
		Login_From_Interesting_Hostname,
		## Generated if a login goes to a host matched by the 
		## :bro:id:`interesting_hostnames` regular expression.
		Login_To_Interesting_Hostname,
	};
	
	## Strange/bad host names to see successful SSH logins from or to.
	const interesting_hostnames =
			/^d?ns[0-9]*\./ |
			/^smtp[0-9]*\./ |
			/^mail[0-9]*\./ |
			/^pop[0-9]*\./  |
			/^imap[0-9]*\./ |
			/^www[0-9]*\./  |
			/^ftp[0-9]*\./  &redef;
}

event SSH::heuristic_successful_login(c: connection)
	{
	# Check to see if this login came from an interesting hostname.
	when ( local orig_hostname = lookup_addr(c$id$orig_h) )
		{
		if ( interesting_hostnames in orig_hostname )
			{
			NOTICE([$note=Login_From_Interesting_Hostname,
			        $conn=c,
			        $msg=fmt("Interesting login from hostname: %s", orig_hostname),
			        $sub=orig_hostname]);
			}
		}
	# Check to see if this login went to an interesting hostname.
	when ( local resp_hostname = lookup_addr(c$id$orig_h) )
		{
		if ( interesting_hostnames in resp_hostname )
			{
			NOTICE([$note=Login_To_Interesting_Hostname,
			        $conn=c,
			        $msg=fmt("Interesting login to hostname: %s", resp_hostname),
			        $sub=resp_hostname]);
			}
		}
	}

