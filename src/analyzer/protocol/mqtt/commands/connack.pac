refine casetype Command += {
	MQTT_CONNACK -> connack : MQTT_connack;
};

type MQTT_connack = record {
	flags       : uint8;
	return_code : uint8;
} &let {
	session_present : bool  = (flags & 0x01) != 0;
	proc: bool = $context.flow.proc_mqtt_connack(this);
};

refine flow MQTT_Flow += {
	function proc_mqtt_connack(msg: MQTT_connack): bool
		%{
		if ( mqtt_connack )
			{
			auto m = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::MQTT::ConnectAckMsg);
			m->Assign(0, ${msg.return_code});
			m->Assign(1, ${msg.session_present});
			zeek::BifEvent::enqueue_mqtt_connack(connection()->zeek_analyzer(),
			                               connection()->zeek_analyzer()->Conn(),
			                               std::move(m));
			}

		return true;
		%}
};
