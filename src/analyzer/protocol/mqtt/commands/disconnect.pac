refine casetype Command += {
	MQTT_DISCONNECT -> disconnect : MQTT_disconnect;
};

type MQTT_disconnect = empty &let {
	proc: bool = $context.flow.proc_mqtt_disconnect(this);
};

refine flow MQTT_Flow += {
	function proc_mqtt_disconnect(msg: MQTT_disconnect): bool
		%{
		if ( mqtt_disconnect )
			{
			BifEvent::generate_mqtt_disconnect(connection()->bro_analyzer(),
			                                   connection()->bro_analyzer()->Conn());
			}

		return true;
		%}
};
