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
			auto m = new RecordVal(BifType::Record::MQTT::ConnectAckMsg);
			m->Assign(0, val_mgr->GetBool(${msg.return_code}));
			m->Assign(1, val_mgr->GetBool(${msg.session_present}));
			BifEvent::generate_mqtt_connack(connection()->bro_analyzer(),
			                                connection()->bro_analyzer()->Conn(),
			                                m);
			}

		return true;
		%}
};
