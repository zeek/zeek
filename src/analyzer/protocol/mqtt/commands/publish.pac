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
			auto m = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::MQTT::PublishMsg);
			m->Assign(0, ${msg.dup});
			m->Assign(1, ${msg.qos});
			m->Assign(2, ${msg.retain});
			m->Assign<zeek::StringVal>(3, ${msg.topic.str}.length(),
			                     reinterpret_cast<const char*>(${msg.topic.str}.begin()));

			auto len = ${msg.payload}.length();
			static auto max_payload_size = zeek::id::find("MQTT::max_payload_size");
			auto max = max_payload_size->GetVal()->AsCount();

			if ( len > static_cast<int>(max) )
				len = max;

			m->Assign<zeek::StringVal>(4, len,
			                     reinterpret_cast<const char*>(${msg.payload}.begin()));

			m->Assign(5, ${msg.payload}.length());

			zeek::BifEvent::enqueue_mqtt_publish(connection()->zeek_analyzer(),
			                               connection()->zeek_analyzer()->Conn(),
			                               ${pdu.is_orig},
			                               ${msg.qos} == 0 ? 0 : ${msg.msg_id},
			                               std::move(m));
			}

		// If a publish message was seen, let's say that confirms it.
		connection()->zeek_analyzer()->AnalyzerConfirmation();

		return true;
		%}
};
