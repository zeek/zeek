refine casetype Command += {
	MQTT_PINGRESP -> pingresp : MQTT_pingresp;
};

type MQTT_pingresp = empty &let {
	proc: bool = $context.flow.proc_mqtt_pingresp(this);
};

refine flow MQTT_Flow += {
	function proc_mqtt_pingresp(msg: MQTT_pingresp): bool
		%{
		if ( mqtt_pingresp )
			{
			zeek::BifEvent::enqueue_mqtt_pingresp(connection()->zeek_analyzer(),
			                                connection()->zeek_analyzer()->Conn());
			}

		return true;
		%}
};
