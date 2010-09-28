# $Id$

@load site
@load notice

# Ugly: we need the following from conn.bro, but we can't soundly load
# it because it in turn loads us.
global full_id_string: function(c: connection): string;

module TerminateConnection;

export {
	redef enum Notice += {
		TerminatingConnection,	# connection will be terminated
		TerminatingConnectionIgnored,	# connection terminated disabled
	};

	# Whether we're allowed (and/or are capable) to terminate connections
	# using "rst".
	const activate_terminate_connection = F &redef;

	# Terminate the given connection.
	global terminate_connection: function(c: connection);

}

function terminate_connection(c: connection)
	{
	local id = c$id;

	if ( activate_terminate_connection )
		{
		local local_init = is_local_addr(id$orig_h);

		local term_cmd = fmt("rst %s -n 32 -d 20 %s %d %d %s %d %d",
					local_init ? "-R" : "",
					id$orig_h, id$orig_p, get_orig_seq(id),
					id$resp_h, id$resp_p, get_resp_seq(id));

		if ( reading_live_traffic() )
			system(term_cmd);
		else
			NOTICE([$note=TerminatingConnection, $conn=c,
				$msg=term_cmd, $sub="first termination command"]);

		term_cmd = fmt("rst %s -r 2 -n 4 -s 512 -d 20 %s %d %d %s %d %d",
				local_init ? "-R" : "",
				id$orig_h, id$orig_p, get_orig_seq(id),
				id$resp_h, id$resp_p, get_resp_seq(id));

		if ( reading_live_traffic() )
			system(term_cmd);
		else
			NOTICE([$note=TerminatingConnection, $conn=c,
				$msg=term_cmd, $sub="second termination command"]);

		NOTICE([$note=TerminatingConnection, $conn=c,
			$msg=fmt("terminating %s", full_id_string(c))]);
		}

	else
		NOTICE([$note=TerminatingConnectionIgnored, $conn=c,
			$msg=fmt("ignoring request to terminate %s",
					full_id_string(c))]);
	}
