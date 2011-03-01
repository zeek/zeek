# $Id: tm-ftp.bro,v 1.1.2.1 2006/01/04 03:55:48 sommer Exp $
#
# For sensitive FTP connections, request the data connection from the TM.
# When we get it, we store the reassembled payload and run the file-analyzer
# (the latter is automatically done by ftp.bro).

@load time-machine
@load tm-contents
@load ftp

module TimeMachineFTP;

global data_conns: table[count] of conn_id;

event ftp_sensitive_file(c: connection, session: FTP::ftp_session_info,
				filename: string)
	{
	if ( is_external_connection(c) )
		return;

	if ( session$id !in data_conns )
		# Should not happen, as transfer parameters need to be
		# negotiated first.  We let ftp.bro deal with this, though.
		return;

	local id = data_conns[session$id];
	TimeMachine::save_contents(fmt("ftp.%s", session$id), c, T, "tm-ftp");
	}

event ftp_connection_expected(c: connection, orig_h: addr, resp_h: addr,
				resp_p: port, session: FTP::ftp_session_info)
	{
	data_conns[session$id] =
		[$orig_h=orig_h, $orig_p=0/tcp, $resp_h=resp_h, $resp_p=resp_p];
	}

event connection_state_remove(c: connection)
		&priority = 5 # to be called before FTP's handler
	{
	if ( c$id in FTP::ftp_sessions )
		delete data_conns[FTP::ftp_sessions[c$id]$id];
	}
