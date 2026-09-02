refine casetype Command += {
	MQTT_UNSUBSCRIBE -> unsubscribe : MQTT_unsubscribe;
};

type MQTT_unsubscribe = record {
	msg_id : uint16;
	topic_counter : MQTT_subscription_topic_counter;
	topics : MQTT_string[]
		&until($element != nullptr && $context.flow.subscription_topic_limit_reached());
	excess_topics : bytestring &restofdata &transient;
} &let {
	has_excess_topics: bool = sizeof(excess_topics) > 0;
	proc: bool = $context.flow.proc_mqtt_unsubscribe(this);
};

refine flow MQTT_Flow += {
	function proc_mqtt_unsubscribe(msg: MQTT_unsubscribe): bool
		%{
		if ( ${msg.has_excess_topics} )
			connection()->zeek_analyzer()->LimitReachedWeird("mqtt_excessive_subscription_topics", zeek::BifConst::MQTT::max_topics_per_subscription);

		if ( mqtt_unsubscribe )
			{
			auto topics = zeek::make_intrusive<zeek::VectorVal>(zeek::id::string_vec);

			for ( auto topic: *${msg.topics} )
				{
				auto unsubscribe_topic = zeek::make_intrusive<zeek::StringVal>(${topic.str}.length(),
				                                  reinterpret_cast<const char*>(${topic.str}.begin()));
				topics->Assign(topics->Size(), std::move(unsubscribe_topic));
				}

			zeek::BifEvent::enqueue_mqtt_unsubscribe(connection()->zeek_analyzer(),
			                                   connection()->zeek_analyzer()->Conn(),
			                                   ${msg.msg_id},
			                                   std::move(topics));
			}

		return true;
		%}
};
