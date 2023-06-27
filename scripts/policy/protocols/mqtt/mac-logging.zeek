##! This script adds link-layer address (MAC) information to the mqtt logs

@load base/protocols/mqtt

module MQTT;

redef record ConnectInfo += {
	## Link-layer address of the originator, if available.
	orig_l2_addr: string	&log &optional;
	## Link-layer address of the responder, if available.
	resp_l2_addr: string	&log &optional;
};

redef record SubscribeInfo += {
	## Link-layer address of the originator, if available.
	orig_l2_addr: string	&log &optional;
	## Link-layer address of the responder, if available.
	resp_l2_addr: string	&log &optional;
};

redef record PublishInfo += {
	## Link-layer address of the originator, if available.
	orig_l2_addr: string	&log &optional;
	## Link-layer address of the responder, if available.
	resp_l2_addr: string	&log &optional;
};

# Add the link-layer addresses to the MQTT::Info structures.
event mqtt_connect(c: connection, msg: MQTT::ConnectMsg)
	{
	if ( c$orig?$l2_addr )
		c$mqtt$orig_l2_addr = c$orig$l2_addr;

	if ( c$resp?$l2_addr )
		c$mqtt$resp_l2_addr = c$resp$l2_addr;
	}

event mqtt_publish(c: connection, is_orig: bool, msg_id: count, msg: MQTT::PublishMsg)
	{
	if ( c$orig?$l2_addr )
		c$mqtt_state$publish[msg_id]$orig_l2_addr = c$orig$l2_addr;

	if ( c$resp?$l2_addr )
		c$mqtt_state$publish[msg_id]$resp_l2_addr = c$resp$l2_addr;
	}

event mqtt_subscribe(c: connection, msg_id: count, topics: string_vec, requested_qos: index_vec)
	{
	if ( c$orig?$l2_addr )
		c$mqtt_state$subscribe[msg_id]$orig_l2_addr = c$orig$l2_addr;

	if ( c$resp?$l2_addr )
		c$mqtt_state$subscribe[msg_id]$resp_l2_addr = c$resp$l2_addr;
	}

event mqtt_unsubscribe(c: connection, msg_id: count, topics: string_vec)
	{
	if ( c$orig?$l2_addr )
		c$mqtt_state$subscribe[msg_id]$orig_l2_addr = c$orig$l2_addr;

	if ( c$resp?$l2_addr )
		c$mqtt_state$subscribe[msg_id]$resp_l2_addr = c$resp$l2_addr;
	}
