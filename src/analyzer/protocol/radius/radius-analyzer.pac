
refine flow RADIUS_Flow += {
	function proc_radius_message(msg: RADIUS_PDU): bool
		%{
		connection()->zeek_analyzer()->AnalyzerConfirmation();

		if ( ! radius_message )
			return false;

		auto result = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::RADIUS::Message);
		result->Assign(0, ${msg.code});
		result->Assign(1, ${msg.trans_id});
		result->Assign(2, to_stringval(${msg.authenticator}));

		if ( ${msg.attributes}->size() )
			{
			auto attributes = zeek::make_intrusive<zeek::TableVal>(zeek::BifType::Table::RADIUS::Attributes);

			for ( uint i = 0; i < ${msg.attributes}->size(); ++i )
				{
				auto index = zeek::val_mgr->Count(${msg.attributes[i].code});

				// Do we already have a vector of attributes for this type?
				auto current = attributes->FindOrDefault(index);
				zeek::ValPtr val = to_stringval(${msg.attributes[i].value});

				if ( current )
					{
					zeek::VectorVal* vcurrent = current->AsVectorVal();
					vcurrent->Assign(vcurrent->Size(), std::move(val));
					}

				else
					{
					auto attribute_list = zeek::make_intrusive<zeek::VectorVal>(zeek::BifType::Vector::RADIUS::AttributeList);
					attribute_list->Assign((unsigned int)0, std::move(val));
					attributes->Assign(std::move(index), std::move(attribute_list));
					}
				}

			result->Assign(3, std::move(attributes));
			}

		zeek::BifEvent::enqueue_radius_message(connection()->zeek_analyzer(), connection()->zeek_analyzer()->Conn(), std::move(result));
		return true;
		%}

	function proc_radius_attribute(attr: RADIUS_Attribute): bool
		%{
		if ( ! radius_attribute )
			return false;

		zeek::BifEvent::enqueue_radius_attribute(connection()->zeek_analyzer(), connection()->zeek_analyzer()->Conn(),
		                                    ${attr.code}, to_stringval(${attr.value}));
		return true;
		%}
};

refine typeattr RADIUS_PDU += &let {
	proc: bool = $context.flow.proc_radius_message(this);
};

refine typeattr RADIUS_Attribute += &let {
	proc: bool = $context.flow.proc_radius_attribute(this);
};
