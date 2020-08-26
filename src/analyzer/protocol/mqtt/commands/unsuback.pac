refine casetype Command += {
	MQTT_UNSUBACK -> unsuback : MQTT_unsuback;
};

type MQTT_unsuback = record {
	msg_id : uint16;
} &let {
	proc: bool = $context.flow.proc_mqtt_unsuback(this);
};

refine flow MQTT_Flow += {
	function proc_mqtt_unsuback(msg: MQTT_unsuback): bool
		%{
		if ( mqtt_unsuback )
			{
			zeek::BifEvent::enqueue_mqtt_unsuback(connection()->zeek_analyzer(),
			                                connection()->zeek_analyzer()->Conn(),
			                                ${msg.msg_id});
			}

		return true;
		%}
};
