@load http
@load app-summary

redef capture_filters = {
	["http"] = "tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 8888 or tcp port 3128",
	["ipp"] = "tcp port 631",
};

module HTTP_summary;

global log = open_log_file("http-summary") &redef;

type http_transaction: record {
	# standard stuff
	connection_id: conn_id;
	conn_start: time;
	func: string;
	start: time;
	num_req: count;
	req_size: count;
	num_resp: count;
	resp_size: count;

	# for tracking the state
	req_done: bool;
	resp_done: bool;
	done: bool;

	# http-specific stuff
	code: count;
	req_content_type: string;
	resp_content_type: string;
	conditional_get: string;
	user_agent: string;
	cache_control: string;
	last_modified: string;
	etag: string;
};

type http_trans_group: record {
	trans: table[count] of http_transaction;
	first_req: count;
	last_req: count;
};

global http_trans_table: table[conn_id] of http_trans_group;

function lookup_http_trans_group(id: conn_id, create: bool): http_trans_group
	{
	if ( id !in http_trans_table )
		{
		if ( create )
			{
			local trans: table[count] of http_transaction;
			http_trans_table[id] = [
				$trans = trans, $first_req = 1, $last_req = 0];
			}
		else
			print fmt("HTTP trans_group not found: %s", conn_id_string(id));
		}

	return http_trans_table[id];
	}

function new_http_transaction(c: connection, func: string): http_transaction
	{
	# print fmt("new http trans: %.6f %s", network_time(), func);
	local g = lookup_http_trans_group(c$id, T);

	local t = [
		$connection_id = c$id,
		$conn_start = c$start_time,
		$func = func,
		$start = network_time(),
		$num_req = 0, $req_size = 0,
		$num_resp = 0, $resp_size = 0,
		$req_done = F, $resp_done = F, $done = F,
		$code = 0,
		$req_content_type = "none",
		$resp_content_type = "none",
		$conditional_get = "no",
		$user_agent = "none",
		$cache_control = "none",
		$last_modified = "none",
		$etag = "none"];

	++g$last_req;
	g$trans[g$last_req] = t;

	return t;
	}

function lookup_http_transaction(id: conn_id, is_orig: bool): http_transaction
	{
	local g = lookup_http_trans_group(id, F);
	local index = is_orig ? g$last_req : g$first_req;

	if ( index !in g$trans )
		{
		print fmt("HTTP transaction not found: %s : %d-%d",
			conn_id_string(id), g$first_req, g$last_req);
		}

	return g$trans[index];
	}

function end_http_transaction(t: http_transaction)
	{
	if ( t$req_done && t$resp_done )
		{
		if ( t$done )
			return;
		t$done = T;
		print_app_summary(log, t$connection_id, t$conn_start, t$func, t$start,
			t$num_req, t$req_size,
			t$num_resp, t$resp_size,
			fmt("code %d content_type_^ %s content_type_v %s conditional_get %s user_agent %s cache_control %s last_modified %s etag %s",
				t$code,
				t$req_content_type, t$resp_content_type,
				t$conditional_get,
				subst_string(t$user_agent, " ", "_"),
				subst_string(t$cache_control, " ", ""),
				t$last_modified == "none" ? "none" : "present",
				t$etag == "none" ? "none" : "present"
				));
		}
	}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
	{
	# print fmt("http request");
	local t = new_http_transaction(c, method);
	++t$num_req;
	t$req_done = F;
	}

event http_reply(c: connection, version: string, code: count, reason: string)
	{
	# print fmt("http reply");
	local id = c$id;
	local g = lookup_http_trans_group(id, T);
	local t: http_transaction;
	if ( g$first_req in g$trans )
		t = g$trans[g$first_req];
	else
		t = new_http_transaction(c, "none");

	++t$num_resp;
	t$code = code;
	t$resp_done = F;
	}

function http_request_done(c: connection, stat: http_message_stat)
	{
	# print fmt("http request done");
	local t = lookup_http_transaction(c$id, T);
	t$req_size = t$req_size + stat$body_length;
	t$req_done = T;
	end_http_transaction(t);
	}

function http_reply_done(c: connection, stat: http_message_stat)
	{
	# print fmt("http reply done");
	local t = lookup_http_transaction(c$id, F);
	t$resp_size = t$resp_size + stat$body_length;
	if ( t$code >= 200 )
		{
		t$resp_done = T;
		end_http_transaction(t);
		local g = lookup_http_trans_group(t$connection_id, F);
		++g$first_req;
		}
	}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
	{
	if ( is_orig )
		http_request_done(c, stat);
	else
		http_reply_done(c, stat);
	}

event http_content_type(c: connection, is_orig: bool, ty: string, subty: string)
	{
	local t = lookup_http_transaction(c$id, is_orig);
	local type_str = fmt("%s/%s", ty, subty);
	if ( is_orig )
		t$req_content_type = type_str;
	else
		t$resp_content_type = type_str;
	}

function http_conditional_get(c: connection, is_orig: bool, h: mime_header_rec)
	{
	local t = lookup_http_transaction(c$id, is_orig);
	t$conditional_get = h$name;
	}

function http_user_agent(c: connection, is_orig: bool, h: mime_header_rec)
	{
	local t = lookup_http_transaction(c$id, is_orig);
	t$user_agent = h$value;
	}

function http_cache_control(c: connection, is_orig: bool, h: mime_header_rec)
	{
	local t = lookup_http_transaction(c$id, is_orig);
	t$cache_control = h$value;
	}

function http_last_modified(c: connection, is_orig: bool, h: mime_header_rec)
	{
	local t = lookup_http_transaction(c$id, is_orig);
	t$last_modified = h$value;
	}

function http_etag(c: connection, is_orig: bool, h: mime_header_rec)
	{
	local t = lookup_http_transaction(c$id, is_orig);
	t$etag = h$value;
	}

# type mime_header_rec: record {
#	name: string;
#	value: string;
# };
# type mime_header_list: table[count] of mime_header_rec;

const conditional_get_headers = {
	"IF-MODIFIED-SINCE",
	"IF-UNMODIFIED-SINCE",
	"IF-MATCH",
	"IF-NONE-MATCH",
	"IF-RANGE",
};

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
	{
	if ( ! is_orig )
		return;

	for ( i in hlist )
		{
		local h = hlist[i];
		if ( h$name in conditional_get_headers )
			http_conditional_get(c, is_orig, h);
		if ( h$name == "USER-AGENT" )
			http_user_agent(c, is_orig, h);
		if ( h$name == "CACHE-CONTROL" )
			http_cache_control(c, is_orig, h);
		if ( h$name == "LAST-MODIFIED" )
			http_last_modified(c, is_orig, h);
		if ( h$name == "ETAG" )
			http_etag(c, is_orig, h);
		}
	}

function end_http_trans_group(g: http_trans_group, index: count)
	{
	if ( index !in g$trans )
		return;
	local t = g$trans[index];

	t$req_done = T;
	t$resp_done = T;
	end_http_transaction(t);

	delete g$trans[index];
	end_http_trans_group(g, index + 1);
	}

event connection_state_remove(c: connection)
	{
	local id = c$id;
	if ( id in http_trans_table )
		{
		end_http_trans_group(http_trans_table[id], 1);
		delete http_trans_table[id];
		}
	}
