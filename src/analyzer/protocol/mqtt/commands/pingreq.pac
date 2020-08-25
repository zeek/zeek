refine casetype Command += {
	MQTT_PINGREQ -> pingreq : MQTT_pingreq;
};

type MQTT_pingreq = empty &let {
	proc: bool = $context.flow.proc_mqtt_pingreq(this);
};

refine flow MQTT_Flow += {
	function proc_mqtt_pingreq(msg: MQTT_pingreq): bool
		%{
		if ( mqtt_pingreq )
			{
			zeek::BifEvent::enqueue_mqtt_pingreq(connection()->zeek_analyzer(),
			                               connection()->zeek_analyzer()->Conn());
			}

		return true;
		%}
};
