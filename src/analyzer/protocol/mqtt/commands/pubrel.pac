refine casetype Command += {
	MQTT_PUBREL  -> pubrel  : MQTT_pubrel(pdu);
};

type MQTT_pubrel(pdu: MQTT_PDU) = record {
	msg_id : uint16;
} &let {
	proc: bool = $context.flow.proc_mqtt_pubrel(this, pdu.is_orig);
};

refine flow MQTT_Flow += {
	function proc_mqtt_pubrel(msg: MQTT_pubrel, is_orig: bool): bool
		%{
		if ( mqtt_pubrel )
			{
			zeek::BifEvent::enqueue_mqtt_pubrel(connection()->zeek_analyzer(),
			                              connection()->zeek_analyzer()->Conn(),
			                              is_orig,
			                              ${msg.msg_id});
			}
		return true;
		%}
};
