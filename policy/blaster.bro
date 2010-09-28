# $Id: blaster.bro 5952 2008-07-13 19:45:15Z vern $
#
# Identifies W32.Blaster-infected hosts by observing their scanning
# activity.

@load notice
@load site

# Which hosts have scanned which addresses via 135/tcp.
global w32b_scanned: table[addr] of set[addr] &write_expire = 5min;
global w32b_reported: set[addr] &persistent;

const W32B_port = 135/tcp;
const W32B_MIN_ATTEMPTS = 50 &redef;

redef enum Notice += {
	W32B_SourceLocal,
	W32B_SourceRemote,
};

event connection_attempt(c: connection)
	{
	if ( c$id$resp_p != W32B_port )
		return;

	local ip = c$id$orig_h;

	if ( ip in w32b_reported )
		return;

	if ( ip in w32b_scanned )
		{
		add (w32b_scanned[ip])[c$id$resp_h];

		if ( length(w32b_scanned[ip]) >= W32B_MIN_ATTEMPTS )
			{
			if ( is_local_addr(ip) )
				NOTICE([$note=W32B_SourceLocal, $conn=c,
					$msg=fmt("W32.Blaster local source: %s",
							ip)]);
			else
				NOTICE([$note=W32B_SourceRemote, $conn=c,
					$msg=fmt("W32.Blaster remote source: %s",
							ip)]);

			add w32b_reported[ip];
			}
		}

	else
		w32b_scanned[ip] = set(ip) &mergeable;
	}
