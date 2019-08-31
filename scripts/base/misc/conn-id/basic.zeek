## A connection's identifying 4-tuple of endpoints and ports.
##
## .. note:: It's actually a 5-tuple: the transport-layer protocol is stored as
##    part of the port values, `orig_p` and `resp_p`, and can be extracted from
##    them with :zeek:id:`get_port_transport_proto`.

type conn_id: record {
	orig_h: addr;	##< The originator's IP address.
	orig_p: port;	##< The originator's port number.
	resp_h: addr;	##< The responder's IP address.
	resp_p: port;	##< The responder's port number.
} &log;

@load base/init-bare.zeek