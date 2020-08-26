refine casetype Command += {
	MQTT_PUBACK  -> puback  : MQTT_puback(pdu);
};

type MQTT_puback(pdu: MQTT_PDU) = record {
	msg_id : uint16;
} &let {
	proc: bool = $context.flow.proc_mqtt_puback(this, pdu.is_orig);
};

refine flow MQTT_Flow += {
	function proc_mqtt_puback(msg: MQTT_puback, is_orig: bool): bool
		%{
		if ( mqtt_puback )
			{
			zeek::BifEvent::enqueue_mqtt_puback(connection()->zeek_analyzer(),
			                              connection()->zeek_analyzer()->Conn(),
			                              is_orig,
			                              ${msg.msg_id});
			}
		return true;
		%}
};
