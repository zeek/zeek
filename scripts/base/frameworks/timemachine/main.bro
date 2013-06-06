
@load base/frameworks/control

module TimeMachine;

export {
	const tm_host = 0.0.0.0 &redef;
	const tm_port = 47757/tcp &redef;

	type Query: record {
		## Query result
		to_file: string &optional;
		feed:    string &optional;
		tag:     string &optional;

		## Query specification
		host1: addr;
		port1: port &optional;
		host2: addr &optional;
		port2: port &optional;

		## Flags
		mem_only: bool &default=T;
		subscribe: bool &default=F;
		start: time &optional;
		end: time &optional;
	};

	## 
	global dump_host: function(filename: string, host: addr);

	## 
	global dump_conn: function(c: connection);

	global perform_query: function(q: Query);
}

# This commanad is used internally to send commands to timemachine.
global TimeMachine::command: event(cmd: string);
const feed_id = unique_id("feed-") &redef;

event bro_init() &priority=5
	{
	if ( tm_host != 0.0.0.0 )
		{
		Communication::nodes["timemachine"] = [$host=tm_host, $p=tm_port, $connect=T, $retry=1min, 
		                                        $events=/TimeMachine::.*/];
		}
	}


function build_query(q: Query): string
	{
	local query_result = "";
	local query_spec = "";
	local query_flags = "";

	# Set the query_result
	if ( q?$to_file )
		query_result = fmt("to_file \"%s\"", q$to_file);
	else if ( q?$feed || q?$tag )
		{
		if ( q?$feed )
			query_result = fmt("feed %s", feed_id);
		if ( q?$tag )
			query_result = cat(" tag", q$tag);
		}
	else
		{
		Reporter::error("invalid TimeMachine query - lacking an adequate query result.");
		return "<invalid query>";
		}

	# Set the query_spec
	if ( !q?$port1 && !q?$port2 )
		{
		if ( !q?$host2 )
			query_spec = fmt("index ip \"%s\"", q$host1);
		else
			query_spec = fmt("index connection2 \"%s %s\"", 
			                 q$host1, q$host2);
		}
	else if ( q?$host2 )
		{
		if ( q?$port1 && q?$port2 )
			query_spec = fmt("index connection4 \"%s %s:%d %s:%d\"", 
			                 get_port_transport_proto(q$port1),
			                 q$host1, port_to_count(q$port1),
			                 q$host2, port_to_count(q$port2));
		else if ( q?$port2 )
			query_spec = fmt("index connection3 \"%s %s %s:%d\"", 
			                 get_port_transport_proto(q$port2),
			                 q$host1, q$host2, port_to_count(q$port2));
		}
	else
		{
		Reporter::error("invalid TimeMachine query - lacking an adequate query specification.");
		return "<invalid query>";
		}

	# Set any applicable flags
	if ( q$mem_only )
		query_flags = cat(query_flags, " ", "mem_only");
	# Start, end, and subscribe currently only work for connection4 index lookups
	if ( /connection4/ in query_spec )
		{
		if ( q$subscribe )
			query_flags = cat(query_flags, " ", "subscribe");
		if ( q?$start )
			query_flags = cat(query_flags, " start ", fmt("%.6f", time_to_double(q$start)));
		if ( q?$end )
			query_flags = cat(query_flags, " end ", fmt("%.6f", time_to_double(q$end)));
		}

	return cat("query ", query_result, " ", query_spec, " ", query_flags);
	}

function perform_query(q: Query)
	{
	local query = build_query(q);
	#print query;
	event TimeMachine::command(query);
	}

	
function dump_conn(c: connection)
	{
	perform_query([$to_file=fmt("crap/%s-%s:%d-%s:%d.pcap", c$uid, c$id$orig_h, port_to_count(c$id$orig_p), c$id$resp_h, port_to_count(c$id$resp_p)),
	               $host1=c$id$orig_h, $port1=c$id$orig_p,
	               $host2=c$id$resp_h, $port2=c$id$resp_p,
	               $subscribe=T]);
	}
