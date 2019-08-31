## A connection's identifying 5-tuple of endpoints, ports and transport-layer
## protocol, accopmanied by the VLAN ID
type conn_id: record {
	orig_h: addr;	##< The originator's IP address.
	orig_p: port;	##< The originator's port number.
	resp_h: addr;	##< The responder's IP address.
	resp_p: port;	##< The responder's port number.
	vlan_id: int &optional;	##< VLAN ID.
} &log;

@load base/init-bare.zeek