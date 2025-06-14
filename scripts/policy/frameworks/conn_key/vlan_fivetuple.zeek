##! This script adapts Zeek's connection key to include 802.1Q VLAN and
##! Q-in-Q tags, when available. Zeek normally ignores VLAN tags for connection
##! lookups; this change makes it factor them in and also makes those VLAN tags
##! part of the :zeek:see:`conn_id` record.

redef record conn_id += {
	## The outer VLAN for this connection, if applicable.
	vlan: int      &log &optional;

	## The inner VLAN for this connection, if applicable.
	inner_vlan: int      &log &optional;
};

redef ConnKey::factory = ConnKey::CONNKEY_VLAN_FIVETUPLE;
