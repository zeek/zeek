##! This script adapts Zeek's connection tuples to include 802.1Q VLAN and
##! Q-in-Q tags, when available. Zeek normally ignores VLAN tags in its flow
##! lookups; this change makes it factor them in and also makes those VLAN tags
##! part of the conn_id record.

redef record conn_id += {
	## The outer VLAN for this connection, if applicable.
	vlan: int      &log &optional;

	## The inner VLAN for this connection, if applicable.
	inner_vlan: int      &log &optional;
};

redef ConnTuple::builder = ConnTuple::CONNTUPLE_VLAN;
