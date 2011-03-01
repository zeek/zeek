# $Id:$

@load http
@load app-summary

redef capture_filters = {
	["http"] = "tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 8888 or tcp port 3128",
};

module HTTP_req_per_session;

export {
	global log = open_log_file("http-rps-summary") &redef;
	const http_session_idle_timeout = 1 sec &redef;
}

type http_session: record {
	# standard stuff
	connection_id: conn_id;		# of the first conn
	conn_start: time;
	func: string;
	start: time;
	num_req: count;
	req_size: count;
	num_resp: count;
	resp_size: count;

	# for timeout
	unfinished_req: count;
	unfinished_resp: count;
	last_time: time;
};

global expire_http_session: function(
	tbl: table[addr] of http_session, index: addr): interval;

global http_ssn_table: table[addr] of http_session
	&read_expire = http_session_idle_timeout
	&expire_func = expire_http_session;

function new_http_session(c: connection): http_session
	{
	local t = [
		$connection_id = c$id,
		$conn_start = c$start_time,
		$func = "unknown",
		$start = network_time(),
		$num_req = 0, $req_size = 0,
		$num_resp = 0, $resp_size = 0,
		$unfinished_req = 0, $unfinished_resp = 0,
		$last_time = network_time()];

	return t;
	}

function lookup_http_session(c: connection, is_orig: bool): http_session
	{
	local id = c$id;
	local index = id$orig_h;

	if ( index !in http_ssn_table )
		{
		if ( ! is_orig )
			print fmt("%.6f HTTP session not found for a resposne",
				network_time(), conn_id_string(id));

		http_ssn_table[index] = new_http_session(c);
		}

	return http_ssn_table[index];
	}

function end_http_session(t: http_session)
	{
	print_app_summary(log, t$connection_id, t$conn_start, t$func, t$start,
		t$num_req, t$req_size,
		t$num_resp, t$resp_size,
		fmt("duration %.6f", t$last_time - t$start));
	}

function check_expiration(t: http_session): bool
	{
	print fmt("%.6f check expiration http_session %s: %.6f %d,%d %d,%d",
		network_time(), conn_id_string(t$connection_id),
		t$last_time,
		t$num_req, t$num_resp,
		t$unfinished_req, t$unfinished_resp);

	if ( network_time() - t$last_time < http_session_idle_timeout
	     || ( t$unfinished_req + t$unfinished_resp > 0 &&
	          network_time() - t$last_time < 15 min &&
		  ! done_with_network ) )
		{
		print fmt("do not expire");
		return F;
		}

	end_http_session(t);
	return T;
	}

function expire_http_session(tbl: table[addr] of http_session,
		index: addr): interval
	{
	local t = tbl[index];
	if ( ! check_expiration(t) )
		{
		print fmt("... no, wait one more second: %d, %d",
			t$unfinished_req, t$unfinished_resp);
		return 1 sec;
		}
	return 0 sec;
	}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
	{
	local t = lookup_http_session(c, T);
	if ( check_expiration(t) )
		{
		delete http_ssn_table[c$id$orig_h];
		t = lookup_http_session(c, T);
		}
	t$func = method;
	++t$num_req;
	++t$unfinished_req;
	t$last_time = network_time();
	}

event http_reply(c: connection, version: string, code: count, reason: string)
	{
	# print fmt("http reply");
	local t = lookup_http_session(c, F);
	++t$num_resp;
	++t$unfinished_resp;
	t$last_time = network_time();
	}

function http_request_done(c: connection, stat: http_message_stat)
	{
	# print fmt("http request done");
	local t = lookup_http_session(c, T);
	t$req_size = t$req_size + stat$body_length;
	if ( t$unfinished_req > 0 )
		--t$unfinished_req;
	t$last_time = network_time();
	}

function http_reply_done(c: connection, stat: http_message_stat)
	{
	local t = lookup_http_session(c, F);
	t$resp_size = t$resp_size + stat$body_length;
	if ( t$unfinished_resp > 0 )
		--t$unfinished_resp;
	t$last_time = network_time();
	}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
	{
	if ( is_orig )
		http_request_done(c, stat);
	else
		http_reply_done(c, stat);
	}

event bro_done()
	{
	for ( index in http_ssn_table )
		{
		end_http_session(http_ssn_table[index]);
		}
	}
