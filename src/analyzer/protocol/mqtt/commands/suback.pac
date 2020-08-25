refine casetype Command += {
	MQTT_SUBACK -> suback : MQTT_suback;
};

type MQTT_suback = record {
	msg_id      : uint16;
	granted_QoS : uint8;
} &let {
	proc: bool = $context.flow.proc_mqtt_suback(this);
};

refine flow MQTT_Flow += {
	function proc_mqtt_suback(msg: MQTT_suback): bool
		%{
		if ( mqtt_suback )
			{
			zeek::BifEvent::enqueue_mqtt_suback(connection()->zeek_analyzer(),
			                              connection()->zeek_analyzer()->Conn(),
			                              ${msg.msg_id},
			                              ${msg.granted_QoS});
			}

		return true;
		%}
};
