# $Id: rsh.bro 4758 2007-08-10 06:49:23Z vern $

@load conn
@load login

module RSH;

export {
	redef enum Notice += {
	# RSH client username and server username differ.
		DifferentRSH_Usernames,

		# Attempt to authenticate via RSH failed.
		FailedRSH_Authentication,

		# RSH session appears to be interactive - multiple lines of
		# user commands.
		InteractiveRSH,

		SensitiveRSH_Input,
		SensitiveRSH_Output,
	};

	const failure_msgs =
		  /^Permission denied/
		| /Login failed/
	&redef;
}

redef capture_filters += { ["rsh"] = "tcp port 514" };

global rsh_ports = { 514/tcp } &redef;
redef dpd_config += { [ANALYZER_RSH] = [$ports = rsh_ports] };

type rsh_session_info: record {
        client_user: string;
        server_user: string;
	initial_cmd: string;
        output_line: count;     # number of lines seen
};

global rsh_sessions: table[conn_id] of rsh_session_info;

function new_rsh_session(c: connection, client_user: string,
			 server_user: string, line: string)
	{
	if ( c$id in rsh_sessions )
		delete rsh_sessions[c$id];

	local s: rsh_session_info;
	s$client_user = client_user;
	s$server_user = server_user;
	s$initial_cmd = line;
        s$output_line = 0;

	rsh_sessions[c$id] = s;
	}

event rsh_request(c: connection, client_user: string, server_user: string,
		  line: string, new_session: bool)
	{
	local id = c$id;

	local BS_line = edit(line, Login::BS);
      	local DEL_line = edit(line, Login::DEL);

	if ( new_session )
		{
		new_rsh_session(c, client_user, server_user, line);

		if ( client_user != server_user )
			NOTICE([$note=DifferentRSH_Usernames, $conn=c,
				$msg=fmt("differing client/server usernames (%s/%s)",
					client_user, server_user),
				$sub=client_user, $user=server_user]);
		}

	local s = rsh_sessions[c$id];
	if ( s$output_line > 0 )
		NOTICE([$note=InteractiveRSH, $conn=c,
			$msg="interactive RSH session, input following output",
			$sub=s$client_user, $user=s$server_user]);

	if ( Login::input_trouble in line ||
	     Login::input_trouble in BS_line ||
	     Login::input_trouble in DEL_line ||
	     line == Login::full_input_trouble )
		NOTICE([$note=SensitiveRSH_Input, $conn=c,
			$msg=line, $sub=s$client_user, $user=s$server_user]);
	}

event rsh_reply(c: connection, client_user: string, server_user: string,
		line: string)
	{
	local s = rsh_sessions[c$id];

        if ( line != "" && ++s$output_line == 1 && failure_msgs in line )
		NOTICE([$note=FailedRSH_Authentication, $conn=c,
			$msg=line, $sub=s$client_user, $user=s$server_user]);

	if ( Login::output_trouble in line ||
	     line == Login::full_output_trouble )
		NOTICE([$note=SensitiveRSH_Output, $conn=c,
			$msg=line, $sub=s$client_user, $user=s$server_user]);
	}
