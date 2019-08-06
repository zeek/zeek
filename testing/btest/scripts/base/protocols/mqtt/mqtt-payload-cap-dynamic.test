# @TEST-EXEC: zeek -b -r $TRACES/mqtt.pcap %INPUT > out
# @TEST-EXEC: btest-diff out

@load policy/protocols/mqtt
@load base/frameworks/config

event mqtt_publish(c: connection, is_orig: bool, msg_id: count, msg: MQTT::PublishMsg)
	{
	print "mqtt_publish", msg$payload, |msg$payload|, msg$payload_len;

	if ( MQTT::max_payload_size > 8 )
		Config::set_value("MQTT::max_payload_size", 8);
	else
		Config::set_value("MQTT::max_payload_size", MQTT::max_payload_size - 3);
	}
