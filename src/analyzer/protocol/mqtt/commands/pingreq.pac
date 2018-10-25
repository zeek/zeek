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
			BifEvent::generate_mqtt_pingreq(connection()->bro_analyzer(), 
			                                connection()->bro_analyzer()->Conn());
			}

		return true;
		%}
};
