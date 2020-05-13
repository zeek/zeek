refine casetype Command += {
	MQTT_SUBSCRIBE -> subscribe : MQTT_subscribe;
};

type MQTT_subscribe_topic = record {
	name          : MQTT_string;
	requested_QoS : uint8;
};

type MQTT_subscribe = record {
	msg_id : uint16;
	topics : MQTT_subscribe_topic[];
} &let {
	proc: bool = $context.flow.proc_mqtt_subscribe(this);
};

refine flow MQTT_Flow += {
	function proc_mqtt_subscribe(msg: MQTT_subscribe): bool
		%{
		if ( mqtt_subscribe )
			{
			auto topics = make_intrusive<VectorVal>(zeek::id::string_vec);
			auto qos_levels = make_intrusive<VectorVal>(zeek::id::index_vec);

			for ( auto topic: *${msg.topics} )
				{
				auto subscribe_topic = new StringVal(${topic.name.str}.length(),
				                                     reinterpret_cast<const char*>(${topic.name.str}.begin()));
				auto qos = val_mgr->Count(${topic.requested_QoS});
				topics->Assign(topics->Size(), subscribe_topic);
				qos_levels->Assign(qos_levels->Size(), qos);
				}

			BifEvent::enqueue_mqtt_subscribe(connection()->bro_analyzer(),
			                                 connection()->bro_analyzer()->Conn(),
			                                 ${msg.msg_id},
			                                 std::move(topics),
			                                 std::move(qos_levels));
			}

		return true;
		%}
};
