
refine flow RADIUS_Flow += {
	function proc_radius_message(msg: RADIUS_PDU): bool
		%{
		connection()->bro_analyzer()->ProtocolConfirmation();

		if ( ! radius_message )
			return false;

		auto result = make_intrusive<RecordVal>(zeek::BifType::Record::RADIUS::Message);
		result->Assign(0, val_mgr->Count(${msg.code}));
		result->Assign(1, val_mgr->Count(${msg.trans_id}));
		result->Assign(2, to_stringval(${msg.authenticator}));

		if ( ${msg.attributes}->size() )
			{
			auto attributes = make_intrusive<TableVal>(zeek::BifType::Table::RADIUS::Attributes);

			for ( uint i = 0; i < ${msg.attributes}->size(); ++i )
				{
				auto index = val_mgr->Count(${msg.attributes[i].code});

				// Do we already have a vector of attributes for this type?
				auto current = attributes->Lookup(index.get());
				IntrusivePtr<Val> val = to_stringval(${msg.attributes[i].value});

				if ( current )
					{
					VectorVal* vcurrent = current->AsVectorVal();
					vcurrent->Assign(vcurrent->Size(), std::move(val));
					}

				else
					{
					auto attribute_list = make_intrusive<VectorVal>(zeek::BifType::Vector::RADIUS::AttributeList);
					attribute_list->Assign((unsigned int)0, std::move(val));
					attributes->Assign(index.get(), std::move(attribute_list));
					}
				}

			result->Assign(3, std::move(attributes));
			}

		zeek::BifEvent::enqueue_radius_message(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), std::move(result));
		return true;
		%}

	function proc_radius_attribute(attr: RADIUS_Attribute): bool
		%{
		if ( ! radius_attribute )
			return false;

		zeek::BifEvent::enqueue_radius_attribute(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(),
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
