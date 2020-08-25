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
			zeek::BifEvent::enqueue_mqtt_disconnect(connection()->zeek_analyzer(),
			                                  connection()->zeek_analyzer()->Conn());
			}

		return true;
		%}
};
