refine casetype Command += {
	MQTT_PUBCOMP -> pubcomp : MQTT_pubcomp(pdu);
};

type MQTT_pubcomp(pdu: MQTT_PDU) = record {
	msg_id : uint16;
} &let {
	proc: bool = $context.flow.proc_mqtt_pubcomp(this, pdu.is_orig);
};

refine flow MQTT_Flow += {
	function proc_mqtt_pubcomp(msg: MQTT_pubcomp, is_orig: bool): bool
		%{
		if ( mqtt_pubcomp )
			{
			zeek::BifEvent::enqueue_mqtt_pubcomp(connection()->zeek_analyzer(),
			                               connection()->zeek_analyzer()->Conn(),
			                               is_orig,
			                               ${msg.msg_id});
			}
		return true;
		%}
};
