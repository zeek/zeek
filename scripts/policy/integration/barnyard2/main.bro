##! This script lets Barnyard2 integrate with Bro.  It receives alerts from
##! Barnyard2 and logs them.  In the future it will do more correlation
##! and derive new notices from the alerts.

@load ./types

module Barnyard2;

export {
	redef enum Log::ID += { LOG };
	
	type Info: record {
		ts:                 time      &log;
		pid:                PacketID  &log;
		alert:              AlertData &log;
	};
	
	## This can convert a Barnyard :bro:type:`Barnyard2::PacketID` value to
	## a :bro:type:`conn_id` value in the case that you might need to index 
	## into an existing data structure elsewhere within Bro.
	global pid2cid: function(p: PacketID): conn_id;
}

event bro_init() &priority=5
	{
	Log::create_stream(Barnyard2::LOG, [$columns=Info]);
	}


function pid2cid(p: PacketID): conn_id
	{
	return [$orig_h=p$src_ip, $orig_p=p$src_p, $resp_h=p$dst_ip, $resp_p=p$dst_p];
	}

event barnyard_alert(id: PacketID, alert: AlertData, msg: string, data: string)
	{
	Log::write(Barnyard2::LOG, [$ts=network_time(), $pid=id, $alert=alert]);
	
	#local proto_connection_string: string;
	#if ( id$src_p == 0/tcp )
	#	proto_connection_string = fmt("{PROTO:255} %s -> %s", id$src_ip, id$dst_ip);
	#else
	#	proto_connection_string = fmt("{%s} %s:%d -> %s:%d", 
	#	                              to_upper(fmt("%s", get_port_transport_proto(id$dst_p))),
	#	                              id$src_ip, id$src_p, id$dst_ip, id$dst_p);
    #
	#local snort_alike_msg = fmt("%.6f [**] [%d:%d:%d] %s [**] [Classification: %s] [Priority: %d] %s", 
	#                            sad$ts,
	#                            sad$generator_id,
	#                            sad$signature_id,
	#                            sad$signature_revision,
	#                            msg, 
	#                            sad$classification, 
	#                            sad$priority_id, 
	#                            proto_connection_string);
	}
