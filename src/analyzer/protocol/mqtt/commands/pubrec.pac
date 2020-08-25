refine casetype Command += {
	MQTT_PUBREC  -> pubrec  : MQTT_pubrec(pdu);
};

type MQTT_pubrec(pdu: MQTT_PDU) = record {
	msg_id : uint16;
} &let {
	proc: bool = $context.flow.proc_mqtt_pubrec(this, pdu.is_orig);
};

refine flow MQTT_Flow += {
	function proc_mqtt_pubrec(msg: MQTT_pubrec, is_orig: bool): bool
		%{
		if ( mqtt_pubrec )
			{
			zeek::BifEvent::enqueue_mqtt_pubrec(connection()->zeek_analyzer(),
			                              connection()->zeek_analyzer()->Conn(),
			                              is_orig,
			                              ${msg.msg_id});
			}
		return true;
		%}
};
