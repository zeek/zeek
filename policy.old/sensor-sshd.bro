# $Id: sensor-sshd.bro 4758 2007-08-10 06:49:23Z vern $
#
# sshd sensor input, i.e., events received from instrumented SSH servers
# that communicate with Bro via the Broccoli library.

# We leverage the login analyzer:
@load login
@load remote

# To prevent requesting sshd events from any peering Bro that connects,
# here is a list of our sshds. List the IP addresses of the hosts your
# sshds are running on here:
#
redef Remote::destinations += {
	["sshd1"] = [$host = 127.0.0.1, $events = /sensor_sshd.*/, $connect=F, $ssl=F]
};

# A big log file for all kinds of notes:
#
global sshd_log: file = open_log_file("sshd");

# A record gathering everything we need to know per connection
# from an ssh client to the sshd:
#
type sshd_conn: record {

	# Connection record we create for connections to sshd
	conn: connection;

	# A table indexed by channel numbers, yielding files.
	# For each channel that contains a shell session this
	# table contains a file to which the session content is
	# logged.
	sessions: table[count] of file;
};

# To avoid reporting IP/port quadruples repeatedly, connections in
# sshd are identified through a globally unique identifier for the
# sshd server (a string) plus an numerical identifier for each
# connection to that sshd.
#
global sshd_conns: table[string, count] of sshd_conn;


function sshd_conn_new(src_ip: addr, src_p: port,
		       dst_ip: addr, dst_p: port,
		       ts: time): sshd_conn
	{
	local id: conn_id;
	id$orig_h = src_ip;
	id$orig_p = src_p;
	id$resp_h = dst_ip;
	id$resp_p = dst_p;

	local orig: endpoint;
	local resp: endpoint;
	orig$size = resp$size = 0;
	orig$state = resp$state = 0;

	local c: connection;
	c$id = id;
	c$orig = orig;
	c$resp = resp;
	c$start_time = ts;
	c$duration = 0 sec;

	# We mark this connection so the login analyzer can
	# understand that it is a login session.
	add c$service["ssh-login"];

	c$addl = "";
	c$hot = 0;

	local sc: sshd_conn;
	sc$conn	= c;

	return sc;
	}


event sensor_sshd_listen(ts: time, sid: string,
			 server_ip: addr, server_p: port)
	{
	print sshd_log, fmt("[%D][%s:%s] sshd listening at %s:%d",
			    ts, get_event_peer()$host, sid, server_ip, server_p);
	}


event sensor_sshd_restart(ts: time, sid: string)
	{
	print sshd_log, fmt("[%D][%s:%s] sshd %s restarted",
			    ts, get_event_peer()$host, sid, sid);
	}


event sensor_sshd_exit(ts: time, sid: string)
	{
	print sshd_log, fmt("[%D][%s:%s] sshd %s exiting",
			    ts, get_event_peer()$host, sid, sid);
	}


event sensor_sshd_conn_new(ts: time, sid: string, cid: count,
			   src_ip: addr, src_p: port,
			   dst_ip: addr, dst_p: port)
	{
	local sc = sshd_conn_new(src_ip, src_p, dst_ip, dst_p, ts);
	sshd_conns[sid, cid] = sc;
	print sshd_log, fmt("[%D][%s:%s:%d] conn attempt from %s:%d to %s:%d",
			    ts, get_event_peer()$host, sid, cid, src_ip, sc$conn$id$orig_p,
			    dst_ip, sc$conn$id$resp_p);

	Login::new_login_session(sc$conn, get_event_peer()$id, 0);
	}


event sensor_sshd_conn_end(ts: time, sid: string, cid: count)
	{
	local pid = get_event_peer()$id;
	local sc = sshd_conns[sid, cid];

	print sshd_log, fmt("[%D][%s:%s:%d] conn terminated",
		            ts, get_event_peer()$host, sid, cid);

	Login::remove_login_session(sc$conn, pid);
	delete sshd_conns[sid, cid];
	}


event sensor_sshd_auth_ok(ts: time, sid: string, cid: count,
			  user: string, uid: int, gid: int)
	{
	local pid = get_event_peer()$id;
	local sc = sshd_conns[sid, cid];
	print sshd_log, fmt("[%D][%s:%s:%d] auth ok: %s (%d/%d)",
			    ts, get_event_peer()$host, sid, cid, user, uid, gid);

	Login::ext_set_login_state(sc$conn$id, pid, LOGIN_STATE_LOGGED_IN);
	event authentication_accepted(user, sc$conn);
	}


event sensor_sshd_auth_failed(ts: time, sid: string, cid: count, user: string)
	{
	local sc = sshd_conns[sid, cid];
	print sshd_log, fmt("[%D][%s:%s:%d] auth reject: user %s from %s:%d",
			    ts, get_event_peer()$host, sid, cid, user,
			    sc$conn$id$orig_h, sc$conn$id$orig_p);

	event authentication_rejected(user, sc$conn);
	}


event sensor_sshd_auth_timeout(ts: time, sid: string, cid: count)
	{
	local sc = sshd_conns[sid, cid];
	print sshd_log, fmt("[%D][%s:%s:%d] auth timeout", ts,
			    sid, get_event_peer()$host, cid);
	}


event sensor_sshd_auth_password_attempt(ts: time, sid: string, cid: count,
				        user: string, password: string,
					valid: bool)
	{
	local sc = sshd_conns[sid, cid];

	if ( ! valid )
		{
		print sshd_log, fmt("[%D][%s:%s:%d] password bad: user %s, password '%s'",
				    ts, get_event_peer()$host, sid, cid, user, password);
		event login_failure(sc$conn, user, "", password, "");
		}
	else
		{
		print sshd_log, fmt("[%D][%s:%s:%d] password ok: user %s, password '%s'",
				    ts, get_event_peer()$host, sid, cid, user, password);
		event login_success(sc$conn, user, "", password, "");
		}
	}


event sensor_sshd_channel_new_session(ts: time, sid: string, cid: count,
					chan_id: count, stype: string)
	{
	local sc = sshd_conns[sid, cid];

	print sshd_log, fmt("[%D][%s:%s:%d:%d] new session: type %s",
			    ts, get_event_peer()$host, sid, cid, chan_id, stype);

	if ( stype == "shell" )
		{
		local filename =
			fmt("sshd-%s-%s-%d-%d.log",
				get_event_peer()$host, sid, cid, chan_id);
		sc$sessions[chan_id] = open(filename);
		}
	}


event sensor_sshd_channel_new_forward(ts: time, sid: string,
				      cid: count, chan_id: count,
				      src_ip: addr, src_p: port,
				      dst_ip: addr, dst_p: port,
				      s2h: bool)
	{
	if ( s2h )
		print sshd_log, fmt("[%D][%s:%s:%d:%d] new port channel: %s:%d -> c -> s -> %s:%d",
				    ts, get_event_peer()$host, sid, cid,
				    chan_id, src_ip, src_p, dst_ip, dst_p);
	else
		print sshd_log, fmt("[%D][%s:%s:%d:%d] new port channel: %s:%d <- c <- s <- %s:%d",
				    ts, get_event_peer()$host, sid, cid,
				    chan_id, dst_ip, dst_p, src_ip, src_p);
	}


event sensor_sshd_data_rx(ts: time, sid: string, cid: count, chan_id: count,
			line: string)
	{
	local sc = sshd_conns[sid, cid];

	if ( chan_id in sc$sessions )
		{
		print sc$sessions[chan_id],
			fmt("[%D][%s:%s:%d:%d] rx: %s", ts,
				get_event_peer()$host, sid, cid, chan_id, line);
		event login_output_line(sc$conn, line);
		}
	}


event sensor_sshd_data_tx(ts: time, sid: string, cid: count,
				chan_id: count, line: string)
	{
	local sc: sshd_conn = sshd_conns[sid, cid];

	if ( chan_id in sc$sessions )
		{
		print sc$sessions[chan_id],
			fmt("[%D][%s:%s:%d:%d] tx: %s", ts,
				get_event_peer()$host, sid, cid, chan_id, line);
		event login_input_line(sc$conn, line);
		}
	}


event sensor_sshd_exec(ts: time, sid: string, cid: count,
			chan_id: count, command: string)
	{
	print sshd_log,
		fmt("[%D][%s:%s:%d:%d] exec: '%s'", ts, get_event_peer()$host,
			sid, cid, chan_id, command);
	}


event sensor_sshd_channel_exit(ts: time, sid: string, cid: count,
				chan_id: count, status: int)
	{
	print sshd_log,
		fmt("[%D][%s:%s:%d:%d] channel exit, code %d", ts,
			get_event_peer()$host, sid, cid, chan_id, status);
	}


event sensor_sshd_channel_cleanup(ts: time, sid: string, cid: count,
					chan_id: count)
	{
	local sc: sshd_conn = sshd_conns[sid, cid];

	print sshd_log, fmt("[%D][%s:%s:%d:%d] channel cleanup",
			    ts, get_event_peer()$host, sid, cid, chan_id);

	if ( chan_id in sc$sessions )
		delete sc$sessions[chan_id];
	}
