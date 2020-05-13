refine casetype Command += {
	MQTT_PUBLISH -> publish : MQTT_publish(pdu);
};

type MQTT_publish(pdu: MQTT_PDU) = record {
	topic   : MQTT_string;
	# If qos is zero, there won't be a msg_id field.
	has_msg_id: case qos of {
		0       -> none   : empty;
		default -> msg_id : uint16;
	};
	payload : bytestring &restofdata;
} &let {
	dup    : bool  = (pdu.fixed_header & 0x08) != 0;
	qos    : uint8 = (pdu.fixed_header & 0x06) >> 1;
	retain : bool  = (pdu.fixed_header & 0x01) != 0;

	proc: bool = $context.flow.proc_mqtt_publish(this, pdu);
};

refine flow MQTT_Flow += {
	function proc_mqtt_publish(msg: MQTT_publish, pdu: MQTT_PDU): bool
		%{
		if ( mqtt_publish )
			{
			auto m = make_intrusive<RecordVal>(BifType::Record::MQTT::PublishMsg);
			m->Assign(0, val_mgr->Bool(${msg.dup}));
			m->Assign(1, val_mgr->Count(${msg.qos}));
			m->Assign(2, val_mgr->Bool(${msg.retain}));
			m->Assign(3, new StringVal(${msg.topic.str}.length(),
			                           reinterpret_cast<const char*>(${msg.topic.str}.begin())));

			auto len = ${msg.payload}.length();
			static auto max_payload_size = zeek::id::lookup("MQTT::max_payload_size");
			auto max = max_payload_size->GetVal()->AsCount();

			if ( len > static_cast<int>(max) )
				len = max;

			m->Assign(4, new StringVal(len,
			                           reinterpret_cast<const char*>(${msg.payload}.begin())));

			m->Assign(5, val_mgr->Count(${msg.payload}.length()));

			BifEvent::enqueue_mqtt_publish(connection()->bro_analyzer(),
			                               connection()->bro_analyzer()->Conn(),
			                               ${pdu.is_orig},
			                               ${msg.qos} == 0 ? 0 : ${msg.msg_id},
			                               std::move(m));
			}

		// If a publish message was seen, let's say that confirms it.
		connection()->bro_analyzer()->ProtocolConfirmation();

		return true;
		%}
};
