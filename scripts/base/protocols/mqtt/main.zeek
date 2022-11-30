##! Implements base functionality for MQTT (v3.1.1) analysis.
##! Generates the mqtt.log file.

module MQTT;

@load base/protocols/mqtt/consts

export {
	redef enum Log::ID += {
		CONNECT_LOG,
		SUBSCRIBE_LOG,
		PUBLISH_LOG,
	};

	global log_policy_connect: Log::PolicyHook;
	global log_policy_subscribe: Log::PolicyHook;
	global log_policy_publish: Log::PolicyHook;

	type MQTT::SubUnsub: enum {
		MQTT::SUBSCRIBE,
		MQTT::UNSUBSCRIBE,
	} &redef;

	type ConnectInfo: record {
		## Timestamp for when the event happened
		ts:             time    &log;
		## Unique ID for the connection
		uid:            string  &log;
		## The connection's 4-tuple of endpoint addresses/ports
		id:             conn_id &log;

		## Indicates the protocol name
		proto_name:     string  &log &optional;
		## The version of the protocol in use
		proto_version:  string  &log &optional;
		## Unique identifier for the client
		client_id:      string  &log &optional;
		## Status message from the server in response to the connect request
		connect_status: string  &log &optional;

		## Topic to publish a "last will and testament" message to
		will_topic:     string  &log &optional;
		## Payload to publish as a "last will and testament"
		will_payload:   string  &log &optional;
	};

	type SubscribeInfo: record {
		## Timestamp for when the subscribe or unsubscribe request started
		ts:                time     &log;
		## UID for the connection
		uid:               string   &log;
		## ID fields for the connection
		id:                conn_id  &log;

		## Indicates if a subscribe or unsubscribe action is taking place
		action:            SubUnsub &log;
		## The topics (or topic patterns) being subscribed to
		topics:             string_vec   &log;
		## QoS levels requested for messages from subscribed topics
		qos_levels:         index_vec    &log &optional;
		## QoS level the server granted
		granted_qos_level: count    &log &optional;
		## Indicates if the request was acked by the server
		ack:               bool     &log &default=F;
	};

	type PublishInfo: record {
		## Timestamp for when the publish message started
		ts:          time    &log;
		## UID for the connection
		uid:         string  &log;
		## ID fields for the connection
		id:          conn_id &log;

		## Indicates if the message was published by the client of
		## this connection or published to the client.
		from_client: bool    &log;
		## Indicates if the message was to be retained by the server
		retain:      bool    &log;
		## QoS level set for the message
		qos:         string  &log;
		## Status of the published message. This will be set to "incomplete_qos"
		## if the full back and forth for the requested level of QoS was not seen.
		## Otherwise if it's successful the field will be "ok".
		status:      string  &log &default="incomplete_qos";

		## Topic the message was published to
		topic:       string  &log;
		## Payload of the message
		payload:     string  &log;

		## The actual length of the payload in the case the *payload*
		## field's contents were truncated according to
		## :zeek:see:`MQTT::max_payload_size`.
		payload_len: count   &log;

		## Track if the message was acked
		ack:         bool    &default=F;
		## Indicates if the server sent the RECEIVED qos message
		rec:         bool    &default=F;
		## Indicates if the client sent the RELEASE qos message
		rel:         bool    &default=F;
		## Indicates if the server sent the COMPLETE qos message
		comp:        bool    &default=F;
		## Internally used for comparing numeric qos level
		qos_level:   count   &default=0;
	};

	## Event that can be handled to access the MQTT record as it is sent on
	## to the logging framework.
	global MQTT::log_mqtt: event(rec: ConnectInfo);

	## The expiration function for published messages that haven't been logged
	## yet simply causes the message to be logged.
	global publish_expire: function(tbl: table[count] of PublishInfo, idx: count): interval;

	## The expiration function for subscription messages that haven't been logged
	## yet simply causes the message to be logged.
	global subscribe_expire: function(tbl: table[count] of SubscribeInfo, idx: count): interval;

	## Data structure to track pub/sub messaging state of a given connection.
	type State: record {
		## Published messages that haven't been logged yet.
		publish: table[count] of PublishInfo &optional &write_expire=5secs &expire_func=publish_expire;
		## Subscription/unsubscription messages that haven't been ACK'd or
		## logged yet.
		subscribe: table[count] of SubscribeInfo &optional &write_expire=5secs &expire_func=subscribe_expire;
	};
}

function publish_expire(tbl: table[count] of PublishInfo, idx: count): interval
	{
	Log::write(PUBLISH_LOG, tbl[idx]);
	return 0sec;
	}

function subscribe_expire(tbl: table[count] of SubscribeInfo, idx: count): interval
	{
	Log::write(SUBSCRIBE_LOG, tbl[idx]);
	return 0sec;
	}

redef record connection += {
	mqtt: ConnectInfo &optional;
	mqtt_state: State &optional;
};

const ports = { 1883/tcp };
redef likely_server_ports += { ports };

event zeek_init() &priority=5
	{
	Log::create_stream(MQTT::CONNECT_LOG, [$columns=ConnectInfo, $ev=log_mqtt, $path="mqtt_connect", $policy=log_policy_connect]);
	Log::create_stream(MQTT::SUBSCRIBE_LOG, [$columns=SubscribeInfo, $path="mqtt_subscribe", $policy=log_policy_subscribe]);
	Log::create_stream(MQTT::PUBLISH_LOG, [$columns=PublishInfo, $path="mqtt_publish", $policy=log_policy_publish]);

	Analyzer::register_for_ports(Analyzer::ANALYZER_MQTT, ports);
	}

function set_session(c: connection): ConnectInfo
	{
	if ( ! c?$mqtt )
		c$mqtt = ConnectInfo($ts  = network_time(),
		                     $uid = c$uid,
		                     $id  = c$id);

	if ( ! c?$mqtt_state )
		{
		c$mqtt_state = State();
		c$mqtt_state$publish = table();
		c$mqtt_state$subscribe = table();
		}

	return c$mqtt;
	}

event mqtt_connect(c: connection, msg: MQTT::ConnectMsg) &priority=5
	{
	local info = set_session(c);

	info$proto_name = msg$protocol_name;
	info$proto_version = versions[msg$protocol_version];
	info$client_id = msg$client_id;
	if ( msg?$will_topic )
		info$will_topic = msg$will_topic;
	if ( msg?$will_msg )
		info$will_payload = msg$will_msg;
	}

event mqtt_connack(c: connection, msg: MQTT::ConnectAckMsg) &priority=5
	{
	local info = set_session(c);

	info$connect_status = return_codes[msg$return_code];

	Log::write(CONNECT_LOG, info);
	}

event mqtt_publish(c: connection, is_orig: bool, msg_id: count, msg: MQTT::PublishMsg) &priority=5
	{
	set_session(c);

	local pi = PublishInfo($ts=network_time(),
	                       $uid=c$uid,
	                       $id=c$id,
	                       $from_client=is_orig,
	                       $retain=msg$retain,
	                       $qos=qos_levels[msg$qos],
	                       $qos_level=msg$qos,
	                       $topic=msg$topic,
	                       $payload=msg$payload,
	                       $payload_len=msg$payload_len);
	if ( pi$qos_level == 0 )
		pi$status="ok";

	c$mqtt_state$publish[msg_id] = pi;
	}

event mqtt_publish(c: connection, is_orig: bool, msg_id: count, msg: MQTT::PublishMsg) &priority=-5
	{
	local pi = c$mqtt_state$publish[msg_id];

	if ( pi$qos_level == 0 )
		{
		Log::write(PUBLISH_LOG, pi);
		delete c$mqtt_state$publish[msg_id];
		}
	}

event mqtt_puback(c: connection, is_orig: bool, msg_id: count) &priority=5
	{
	set_session(c);

	if ( msg_id in c$mqtt_state$publish )
		{
		local pi = c$mqtt_state$publish[msg_id];
		pi$ack = T;
		if ( pi$qos_level == 1 )
			pi$status = "ok";
		}
	}

event mqtt_puback(c: connection, is_orig: bool, msg_id: count) &priority=-5
	{
	if ( msg_id in c$mqtt_state$publish )
		{
		local pi = c$mqtt_state$publish[msg_id];

		if ( pi$status == "ok" )
			{
			Log::write(PUBLISH_LOG, pi);
			delete c$mqtt_state$publish[msg_id];
			}
		}
	}

event mqtt_pubrec(c: connection, is_orig: bool, msg_id: count) &priority=5
	{
	set_session(c);

	if ( msg_id in c$mqtt_state$publish )
		{
		local pi = c$mqtt_state$publish[msg_id];
		pi$rec = T;
		}
	}

event mqtt_pubrel(c: connection, is_orig: bool, msg_id: count) &priority=5
	{
	set_session(c);

	if ( msg_id in c$mqtt_state$publish )
		{
		local pi = c$mqtt_state$publish[msg_id];
		pi$rel = T;
		}
	}

event mqtt_pubcomp(c: connection, is_orig: bool, msg_id: count) &priority=5
	{
	local info = set_session(c);
	if ( msg_id !in c$mqtt_state$publish )
		return;

	local pi = c$mqtt_state$publish[msg_id];
	pi$comp = T;

	if ( pi$qos_level == 2 && pi$rec && pi$rel && pi$comp )
		pi$status = "ok";
	}

event mqtt_pubcomp(c: connection, is_orig: bool, msg_id: count) &priority=-5
	{
	if ( msg_id !in c$mqtt_state$publish )
		return;

	local pi = c$mqtt_state$publish[msg_id];
	if ( pi$status == "ok" )
		{
		Log::write(PUBLISH_LOG, pi);
		delete c$mqtt_state$publish[msg_id];
		}
	}


event mqtt_subscribe(c: connection, msg_id: count, topics: string_vec, requested_qos: index_vec) &priority=5
	{
	local info = set_session(c);

	local si = SubscribeInfo($ts  = network_time(),
	                         $uid = c$uid,
	                         $id  = c$id,
	                         $action = MQTT::SUBSCRIBE,
	                         $topics = topics,
	                         $qos_levels = requested_qos);

	c$mqtt_state$subscribe[msg_id] = si;
	}

event mqtt_suback(c: connection, msg_id: count, granted_qos: count) &priority=5
	{
	set_session(c);

	if ( msg_id !in c$mqtt_state$subscribe )
		return;

	local x = c$mqtt_state$subscribe[msg_id];
	x$granted_qos_level = granted_qos;
	x$ack = T;

	Log::write(MQTT::SUBSCRIBE_LOG, x);
	delete c$mqtt_state$subscribe[msg_id];
	}

event mqtt_unsubscribe(c: connection, msg_id: count, topics: string_vec) &priority=5
	{
	set_session(c);

	local si = SubscribeInfo($ts  = network_time(),
	                         $uid = c$uid,
	                         $id  = c$id,
	                         $action = MQTT::UNSUBSCRIBE,
	                         $topics = topics);

	c$mqtt_state$subscribe[msg_id] = si;
	}

event mqtt_unsuback(c: connection, msg_id: count) &priority=-5
	{
	set_session(c);

	if ( msg_id !in c$mqtt_state$subscribe )
		return;

	local x = c$mqtt_state$subscribe[msg_id];
	x$ack = T;

	Log::write(MQTT::SUBSCRIBE_LOG, x);
	delete c$mqtt_state$subscribe[msg_id];
	}

#event mqtt_pingreq(c: connection) &priority=5
#	{
#	}
#
#event mqtt_pingresp(c: connection) &priority=5
#	{
#	}

#event mqtt_disconnect(c: connection) &priority=-5
#	{
#	Log::write(MQTT::CONNECT_LOG, info);
#	}

