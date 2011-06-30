@load conn-util
@load app-summary
@load dns-info

module DNS_common_summary;


export {

	global dns_summary_log = open_log_file("dns-common-summary") &redef;

	const server_ports = {
		53/udp, 53/tcp, 137/udp,
	} &redef;
}

redef capture_filters += {
	["dns"] = "port 53",
	["netbios-ns"] = "udp port 137",
};

const dns_op_name = {
	[0] = "QUERY",
	[1] = "IQUERY",
	[2] = "STATUS",
	[5] = "NB_REGISTER",
	[6] = "NB_RELEASE",
	[7] = "NB_WACK",
	[8] = "NB_REFRESH",
} &default = function(op: count): string
	{
	return fmt("op-%d", op);
	};

function dns_qtype(qtype: int, server_port: port): string
	{
	if ( qtype < 0 )
		return "none";

	if ( server_port == 137/udp )
		{
		if ( qtype == 32 )
			return "NB";
		if ( qtype == 33 )
			return "NBSTAT";
		}

	return query_types[int_to_count(qtype)];
	}

function dns_rcode(rcode: int): string
	{
	return ( rcode < 0 ) ? "none" :
		base_error[int_to_count(rcode)];
	}

const netbios_host_type = {
	["00"] = "workstation",
	["03"] = "messenger",
	["1b"] = "domain_master_browser",
	["20"] = "server",
	["1c"] = "domain_group",
	["1d"] = "master_browser_group",
	["1e"] = "group",
} &default = function(t: string): string { return t; };

const dns_transaction_timeout = 30 sec &redef;

type dns_transaction: record {
	connection_id: conn_id;
	conn_start: time;
	func: string;
	start: time;
	num_req: count;
	req_size: count;
	num_resp: count;
	resp_size: count;

	num_q: count;
	qtype: string;
	query: string;
	host_type: string;
	rcode: string;
	resp_time: time;	# of the first resp
};

# Use only the client addr and transaction id for index, because
# Netbios/NS clients sometimes send to broadcast address
type dns_trans_index: record {
	client: addr;
	client_port: port;
	id: count;
	server: addr;
	server_port: port;
};
global dns_trans_table: table[dns_trans_index] of dns_transaction;

function fmt_list(x: string): string
	{
	if ( strstr(x, ",") > 0 )
		return cat("[", x, "]");
	else
		return x;
	}

event expire_DNS_transaction(ind: dns_trans_index)
	{
	if ( ind !in dns_trans_table )
		return;

	local t = dns_trans_table[ind];
	if ( ind$server_port in server_ports )
		{
		print_app_summary(dns_summary_log,
			t$connection_id,
			t$conn_start,
			t$func, t$start,
			t$num_req, t$req_size,
			t$num_resp, t$resp_size,
			fmt("qtype %s return %s query '%s' host_type %s latency %.6f",
				fmt_list(t$qtype), fmt_list(t$rcode),
				fmt_list(gsub(t$query, / /, "_")),
				fmt_list(t$host_type),
				t$resp_time >= t$start ? t$resp_time - t$start : -1 sec));
		}
	delete dns_trans_table[ind];
	}

function lookup_dns_transaction(c: connection, msg: dns_msg, is_orig: bool): dns_transaction
	{
	local id = c$id;
	local client: addr;
	local server: addr;
	local client_port: port;
	local server_port: port;

	if ( ( ! msg$QR && is_orig ) || ( msg$QR && ! is_orig ) )
		{
		client = id$orig_h;
		client_port = id$orig_p;
		server = id$resp_h;
		server_port = id$resp_p;
		}
	else
		{
		client = id$resp_h;
		client_port = id$resp_p;
		server = id$orig_h;
		server_port = id$orig_p;
		}

	# print fmt("%.6f client %s server %s", network_time(), client, server);

	# Netbios queries are sometimes sent to broadcast addresses,
	# so we ignore the server part
	if ( server_port == 137/udp )
		server = 0.0.0.0;

	local ind = [$client = client, $client_port = client_port,
			$id = msg$id,
			$server = server, $server_port = server_port];

	if ( ind !in dns_trans_table )
		{
		local t = [
			$connection_id = id,
			$conn_start = c$start_time,
			$func = dns_op_name[msg$opcode],
			$start = network_time(),
			$num_req = 0, $req_size = 0,
			$num_resp = 0, $resp_size = 0,
			$num_q = 0,
			$qtype = "none",
			$query = "none", $host_type = "none",
			$rcode = "none",
			$resp_time = network_time() - 1 sec];
		dns_trans_table[ind] = t;
		}

	schedule dns_transaction_timeout {
		expire_DNS_transaction(ind)
		};

	return dns_trans_table[ind];
	}

event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
	{
	local t = lookup_dns_transaction(c, msg, is_orig);
	if ( ! msg$QR )
		{
		++t$num_req;
		t$req_size = t$req_size + len;
		}
	else
		{
		local rcode = dns_rcode(msg$rcode);
		if ( t$rcode == "none" )
			t$rcode = rcode;
		else if ( t$rcode != rcode )
			t$rcode = cat(t$rcode, ",", rcode);
		++t$num_resp;
		t$resp_size = t$resp_size + len;
		if ( t$num_resp == 1 )
			t$resp_time = network_time();
		}
	}

function append_query(t: dns_transaction, query: string, host_type: string, qtype: string)
	{
	++t$num_q;
	if ( t$num_q == 1 )
		{
		t$qtype = qtype;
		t$query = query;
		t$host_type = host_type;
		}
	else
		{
		if ( qtype != t$qtype )
			t$qtype = cat(t$qtype, ",", qtype);
		if ( query != t$query )
			t$query = cat(t$query, ",", query);
		if ( host_type != t$host_type )
			t$host_type = cat(t$host_type, ",", host_type);
		}
	}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	local host_type = "n/a";
	if ( c$id$resp_p == 137/udp )
		{
		query = decode_netbios_name(query);
		local last_byte = sub_bytes(query, byte_len(query) - 2, 2);
		host_type = netbios_host_type[last_byte];
		}

	# print log, fmt("conn %s start %.6f op %d qtype 0x%x name [%s]",
	#	conn_id_string(c$id), network_time(),
	#	msg$opcode, qtype, query);

	local t = lookup_dns_transaction(c, msg, T);
	append_query(t, query, host_type, dns_qtype(qtype, c$id$resp_p));
	}
