refine casetype Command += {
	MQTT_CONNECT -> connect : MQTT_connect;
};

type MQTT_will = record {
	topic : MQTT_string;
	msg   : MQTT_string;
};

type MQTT_connect = record {
	protocol_name    : MQTT_string;
	protocol_version : int8;
	connect_flags    : uint8;
	keep_alive       : uint16;
	client_id        : MQTT_string;

	# payload starts
	will_fields: case will_flag of {
		true  -> will     : MQTT_will;
		false -> nofield1 : empty;
	};
	username_fields: case username of {
		true  -> uname    : MQTT_string;
		false -> nofield2 : empty;
	};
	password_fields: case password of {
		true  -> pass     : MQTT_string;
		false -> nofield3 : empty;
	};
} &let {
	username      : bool  = (connect_flags & 0x80) != 0;
	password      : bool  = (connect_flags & 0x40) != 0;
	will_retain   : bool  = (connect_flags & 0x20) != 0;
	will_qos      : uint8 = (connect_flags & 0x18) >> 3;
	will_flag     : bool  = (connect_flags & 0x04) != 0;
	clean_session : bool  = (connect_flags & 0x02) != 0;

	proc: bool = $context.flow.proc_mqtt_connect(this);
};


refine flow MQTT_Flow += {
	function proc_mqtt_connect(msg: MQTT_connect): bool
		%{
		if ( mqtt_connect )
			{
			auto m = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::MQTT::ConnectMsg);
			m->Assign(0, zeek::make_intrusive<zeek::StringVal>(${msg.protocol_name.str}.length(),
			                           reinterpret_cast<const char*>(${msg.protocol_name.str}.begin())));
			m->Assign(1, ${msg.protocol_version});
			m->Assign(2, zeek::make_intrusive<zeek::StringVal>(${msg.client_id.str}.length(),
			                           reinterpret_cast<const char*>(${msg.client_id.str}.begin())));
			m->AssignInterval(3, double(${msg.keep_alive}));

			m->Assign(4, ${msg.clean_session});
			m->Assign(5, ${msg.will_retain});
			m->Assign(6, ${msg.will_qos});

			if ( ${msg.will_flag} )
				{
				m->Assign(7, zeek::make_intrusive<zeek::StringVal>(${msg.will.topic.str}.length(),
				                           reinterpret_cast<const char*>(${msg.will.topic.str}.begin())));
				m->Assign(8, zeek::make_intrusive<zeek::StringVal>(${msg.will.msg.str}.length(),
				                           reinterpret_cast<const char*>(${msg.will.msg.str}.begin())));
				}

			if ( ${msg.username} )
				{
				m->Assign(9, zeek::make_intrusive<zeek::StringVal>(${msg.uname.str}.length(),
				                           reinterpret_cast<const char*>(${msg.uname.str}.begin())));
				}
			if ( ${msg.password} )
				{
				m->Assign(10, zeek::make_intrusive<zeek::StringVal>(${msg.pass.str}.length(),
				                            reinterpret_cast<const char*>(${msg.pass.str}.begin())));
				}

			zeek::BifEvent::enqueue_mqtt_connect(connection()->zeek_analyzer(),
			                               connection()->zeek_analyzer()->Conn(),
			                               std::move(m));
			}

		// If a connect message was seen, let's say that confirms it.
		connection()->zeek_analyzer()->AnalyzerConfirmation();
		return true;
		%}
};
