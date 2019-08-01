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
			BifEvent::generate_mqtt_pingresp(connection()->bro_analyzer(),
			                                 connection()->bro_analyzer()->Conn());
			}

		return true;
		%}
};
