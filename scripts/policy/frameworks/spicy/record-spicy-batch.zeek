##! Saves all input traffic in Spicy's batch format.

module SpicyBatch;

export {
    const filename = "batch.dat" &redef;
}

redef tcp_content_deliver_all_orig=T;
redef tcp_content_deliver_all_resp=T;
redef udp_content_deliver_all_orig=T;
redef udp_content_deliver_all_resp=T;

global output: file;
global conns: set[conn_id];
global num_conns = 0;

function id(c: connection) : string
	{
	local cid = c$id;
	local proto = "???";

	if ( is_tcp_port(cid$orig_p) )
		proto = "tcp";
	else if ( is_udp_port(cid$orig_p) )
		proto = "udp";
	else if ( is_icmp_port(cid$orig_p) )
		proto = "icmp";

	return fmt("%s-%d-%s-%d-%s", cid$orig_h, cid$orig_p, cid$resp_h, cid$resp_p, proto);
	}

function begin(c: connection, type_: string)
	{
	add conns[c$id];
	++num_conns;
	print fmt("tracking %s", c$id);

	local id_ = id(c);
	print output, fmt("@begin-conn %s %s %s-orig %s%%orig %s-resp %s%%resp\n", id_, type_, id_, c$id$resp_p, id_, c$id$resp_p);
	}

event zeek_init()
	{
	output = open(filename);
	enable_raw_output(output);
	print output, "!spicy-batch v2\n";
	}

event new_connection_contents(c: connection)
	{
	begin(c, "stream");
	}

event tcp_contents(c: connection, is_orig: bool, seq: count, contents: string)
	{
	print output, fmt("@data %s-%s %d\n", id(c), (is_orig ? "orig" : "resp"), |contents|);
	print output, contents;
	print output, "\n";
	}

event content_gap(c: connection, is_orig: bool, seq: count, length: count)
	{
	print output, fmt("@gap %s-%s %d\n", id(c), (is_orig ? "orig" : "resp"), length);
	}

event udp_contents(c: connection, is_orig: bool, contents: string)
	{
	if ( c$id !in conns )
		begin(c, "block");

	print output, fmt("@data %s-%s %d\n", id(c), (is_orig ? "orig" : "resp"), |contents|);
	print output, contents;
	print output, "\n";
	}

event connection_state_remove(c: connection)
	{
	if ( c$id !in conns )
		return;

	print output, fmt("@end-conn %s\n", id(c));
	}

event zeek_done()
	{
	close(output);
	print fmt("recorded %d session%s total", num_conns, (num_conns > 1 ? "s" : ""));
	print fmt("output in %s", filename);
	}
