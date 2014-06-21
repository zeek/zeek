##! This script will generate a notice if an apparent SSH login originates 
##! or heads to a host with a reverse hostname that looks suspicious.  By 
##! default, the regular expression to match "interesting" hostnames includes 
##! names that are typically used for infrastructure hosts like nameservers, 
##! mail servers, web servers and ftp servers.

@load base/frameworks/notice

module SSH;

export {
	redef enum Notice::Type += {
		## Generated if a login originates or responds with a host where
		## the reverse hostname lookup resolves to a name matched by the
		## :bro:id:`SSH::interesting_hostnames` regular expression.
		Interesting_Hostname_Login,
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
	for ( host in set(c$id$orig_h, c$id$resp_h) )
		{
		when ( local hostname = lookup_addr(host) )
			{
			if ( interesting_hostnames in hostname )
				{
				NOTICE([$note=Interesting_Hostname_Login,
				        $msg=fmt("Possible SSH login involving a %s %s with an interesting hostname.",
				                 Site::is_local_addr(host) ? "local" : "remote",
				                 host == c$id$orig_h ? "client" : "server"),
				        $sub=hostname, $conn=c]);
				}
			}
		}
	}

