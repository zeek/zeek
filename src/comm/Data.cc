#include "Data.h"
#include "comm/comm.bif.h"

using namespace std;

OpaqueType* comm::opaque_of_data_type;

static broker::port::protocol to_broker_port_proto(TransportProto tp)
	{
	switch ( tp ) {
	case TRANSPORT_TCP:
		return broker::port::protocol::tcp;
	case TRANSPORT_UDP:
		return broker::port::protocol::udp;
	case TRANSPORT_ICMP:
		return broker::port::protocol::icmp;
	case TRANSPORT_UNKNOWN:
	default:
		return broker::port::protocol::unknown;
	}
	}

static TransportProto to_bro_port_proto(broker::port::protocol tp)
	{
	switch ( tp ) {
	case broker::port::protocol::tcp:
		return TRANSPORT_TCP;
	case broker::port::protocol::udp:
		return TRANSPORT_UDP;
	case broker::port::protocol::icmp:
		return TRANSPORT_ICMP;
	case broker::port::protocol::unknown:
	default:
		return TRANSPORT_UNKNOWN;
	}
	}

struct val_converter {
	using result_type = Val*;

	BroType* type;

	result_type operator()(bool a)
		{
		if ( type->Tag() == TYPE_BOOL )
			return new Val(a, TYPE_BOOL);
		return nullptr;
		}

	result_type operator()(uint64_t a)
		{
		if ( type->Tag() == TYPE_COUNT )
			return new Val(a, TYPE_COUNT);
		if ( type->Tag() == TYPE_COUNTER )
			return new Val(a, TYPE_COUNTER);
		return nullptr;
		}

	result_type operator()(int64_t a)
		{
		if ( type->Tag() == TYPE_INT )
			return new Val(a, TYPE_INT);
		return nullptr;
		}

	result_type operator()(double a)
		{
		if ( type->Tag() == TYPE_DOUBLE )
			return new Val(a, TYPE_DOUBLE);
		return nullptr;
		}

	result_type operator()(const std::string& a)
		{
		switch ( type->Tag() ) {
		case TYPE_STRING:
			return new StringVal(a.size(), a.data());
		case TYPE_FILE:
			{
			auto file = BroFile::GetFile(a.data());

			if ( file )
				{
				Ref(file);
				return new Val(file);
				}

			return nullptr;
			}
		case TYPE_FUNC:
			{
			auto id = lookup_ID(a.data(), GLOBAL_MODULE_NAME);
			auto rval = id ? id->ID_Val() : nullptr;
			Unref(id);

			if ( rval && rval->Type()->Tag() == TYPE_FUNC )
				return rval;

			return nullptr;
			}
		default:
			return nullptr;
		}
		}

	result_type operator()(const broker::address& a)
		{
		if ( type->Tag() == TYPE_ADDR )
			{
			auto bits = reinterpret_cast<const in6_addr*>(&a.bytes());
			return new AddrVal(IPAddr(*bits));
			}

		return nullptr;
		}

	result_type operator()(const broker::subnet& a)
		{
		if ( type->Tag() == TYPE_SUBNET )
			{
			auto bits = reinterpret_cast<const in6_addr*>(&a.network().bytes());
			return new SubNetVal(IPPrefix(IPAddr(*bits), a.length()));
			}

		return nullptr;
		}

	result_type operator()(const broker::port& a)
		{
		if ( type->Tag() == TYPE_PORT )
			return new PortVal(a.number(), to_bro_port_proto(a.type()));

		return nullptr;
		}

	result_type operator()(const broker::time_point& a)
		{
		if ( type->Tag() == TYPE_TIME )
			return new Val(a.value, TYPE_TIME);

		return nullptr;
		}

	result_type operator()(const broker::time_duration& a)
		{
		if ( type->Tag() == TYPE_INTERVAL )
			return new Val(a.value, TYPE_INTERVAL);

		return nullptr;
		}

	result_type operator()(const broker::enum_value& a)
		{
		if ( type->Tag() == TYPE_ENUM )
			{
			auto etype = type->AsEnumType();
			auto i = etype->Lookup(GLOBAL_MODULE_NAME, a.name.data());

			if ( i == -1 )
				return nullptr;

			return new EnumVal(i, etype);
			}

		return nullptr;
		}

	result_type operator()(broker::set& a)
		{
		if ( ! type->IsSet() )
			return nullptr;

		auto tt = type->AsTableType();
		auto rval = new TableVal(tt);

		for ( auto& item : a )
			{
			auto indices = broker::get<broker::vector>(item);

			if ( ! indices )
				{
				Unref(rval);
				return nullptr;
				}

			auto expected_index_types = tt->Indices()->Types();

			if ( expected_index_types->length() != indices->size() )
				{
				Unref(rval);
				return nullptr;
				}

			auto list_val = new ListVal(TYPE_ANY);

			for ( auto i = 0u; i < indices->size(); ++i )
				{
				auto index_val = comm::data_to_val(move((*indices)[i]),
				                                   (*expected_index_types)[i]);

				if ( ! index_val )
					{
					Unref(rval);
					Unref(list_val);
					return nullptr;
					}

				list_val->Append(index_val);
				}


			rval->Assign(list_val, nullptr);
			Unref(list_val);
			}

		return rval;
		}

	result_type operator()(broker::table& a)
		{
		if ( ! type->IsTable() )
			return nullptr;

		auto tt = type->AsTableType();
		auto rval = new TableVal(tt);

		for ( auto& item : a )
			{
			auto indices = broker::get<broker::vector>(item.first);

			if ( ! indices )
				{
				Unref(rval);
				return nullptr;
				}

			auto expected_index_types = tt->Indices()->Types();

			if ( expected_index_types->length() != indices->size() )
				{
				Unref(rval);
				return nullptr;
				}

			auto list_val = new ListVal(TYPE_ANY);

			for ( auto i = 0u; i < indices->size(); ++i )
				{
				auto index_val = comm::data_to_val(move((*indices)[i]),
				                                   (*expected_index_types)[i]);

				if ( ! index_val )
					{
					Unref(rval);
					Unref(list_val);
					return nullptr;
					}

				list_val->Append(index_val);
				}

			auto value_val = comm::data_to_val(move(item.second),
			                                   tt->YieldType());

			if ( ! value_val )
				{
				Unref(rval);
				Unref(list_val);
				return nullptr;
				}

			rval->Assign(list_val, value_val);
			Unref(list_val);
			}

		return rval;
		}

	result_type operator()(broker::vector& a)
		{
		if ( type->Tag() != TYPE_VECTOR )
			return nullptr;

		auto vt = type->AsVectorType();
		auto rval = new VectorVal(vt);

		for ( auto& item : a )
			{
			auto item_val = comm::data_to_val(move(item), vt->YieldType());

			if ( ! item_val )
				{
				Unref(rval);
				return nullptr;
				}

			rval->Assign(rval->Size(), item_val);
			}

		return rval;
		}

	result_type operator()(broker::record& a)
		{
		if ( type->Tag() != TYPE_RECORD )
			return nullptr;

		auto rt = type->AsRecordType();

		if ( a.fields.size() != rt->NumFields() )
			return nullptr;

		auto rval = new RecordVal(rt);

		for ( auto i = 0u; i < a.fields.size(); ++i )
			{
			if ( ! a.fields[i] )
				{
				rval->Assign(i, nullptr);
				continue;
				}

			auto item_val = comm::data_to_val(move(*a.fields[i]),
			                                  rt->FieldType(i));

			if ( ! item_val )
				{
				Unref(rval);
				return nullptr;
				}

			rval->Assign(i, item_val);
			}

		return rval;
		}
};

Val* comm::data_to_val(broker::data d, BroType* type)
	{
	return broker::visit(val_converter{type}, d);
	}

broker::util::optional<broker::data> comm::val_to_data(const Val* v)
	{
	switch ( v->Type()->Tag() ) {
	case TYPE_BOOL:
		return {v->AsBool()};
	case TYPE_INT:
		return {v->AsInt()};
	case TYPE_COUNT:
		return {v->AsCount()};
	case TYPE_COUNTER:
		return {v->AsCounter()};
	case TYPE_PORT:
		{
		auto p = v->AsPortVal();
		return {broker::port(p->Port(), to_broker_port_proto(p->PortType()))};
		}
	case TYPE_ADDR:
		{
		auto a = v->AsAddr();
		in6_addr tmp;
		a.CopyIPv6(&tmp);
		return {broker::address(reinterpret_cast<const uint32_t*>(&tmp),
			                    broker::address::family::ipv6,
			                    broker::address::byte_order::network)};
		}
		break;
	case TYPE_SUBNET:
		{
		auto s = v->AsSubNet();
		in6_addr tmp;
		s.Prefix().CopyIPv6(&tmp);
		auto a = broker::address(reinterpret_cast<const uint32_t*>(&tmp),
		                         broker::address::family::ipv6,
		                         broker::address::byte_order::network);
		return {broker::subnet(a, s.Length())};
		}
		break;
	case TYPE_DOUBLE:
		return {v->AsDouble()};
	case TYPE_TIME:
		return {broker::time_point(v->AsTime())};
	case TYPE_INTERVAL:
		return {broker::time_duration(v->AsInterval())};
	case TYPE_ENUM:
		{
		auto enum_type = v->Type()->AsEnumType();
		auto enum_name = enum_type->Lookup(v->AsEnum());
		return {broker::enum_value(enum_name ? "<unknown enum>" : enum_name)};
		}
	case TYPE_STRING:
		{
		auto s = v->AsString();
		return {string(reinterpret_cast<const char*>(s->Bytes()), s->Len())};
		}
	case TYPE_FILE:
		return {string(v->AsFile()->Name())};
	case TYPE_FUNC:
		return {string(v->AsFunc()->Name())};
	case TYPE_TABLE:
		{
		auto is_set = v->Type()->IsSet();
		auto table = v->AsTable();
		auto table_val = v->AsTableVal();
		auto c = table->InitForIteration();
		broker::data rval;

		if ( is_set )
			rval = broker::set();
		else
			rval = broker::table();

		struct iter_guard {
			iter_guard(HashKey* arg_k, ListVal* arg_lv)
			    : k(arg_k), lv(arg_lv)
				{}

			~iter_guard()
				{
				delete k;
				Unref(lv);
				}

			HashKey* k;
			ListVal* lv;
		};

		for ( auto i = 0; i < table->Length(); ++i )
			{
			HashKey* k;
			auto entry = table->NextEntry(k, c);
			auto vl = table_val->RecoverIndex(k);
			iter_guard ig(k, vl);
			broker::vector key;

			for ( auto k = 0; k < vl->Length(); ++k )
				{
				auto key_part = val_to_data((*vl->Vals())[k]);

				if ( ! key_part )
					return {};

				key.emplace_back(move(*key_part));
				}

			if ( is_set )
				broker::get<broker::set>(rval)->emplace(move(key));
			else
				{
				auto val = val_to_data(entry->Value());

				if ( ! val )
					return {};

				broker::get<broker::table>(rval)->emplace(move(key),
				                                          move(*val));
				}
			}

		return {rval};
		}
	case TYPE_VECTOR:
		{
		auto vec = v->AsVectorVal();
		broker::vector rval;
		rval.reserve(vec->Size());

		for ( auto i = 0u; i < vec->Size(); ++i )
			{
			auto item_val = vec->Lookup(i);

			if ( ! item_val )
				continue;

			auto item = val_to_data(item_val);

			if ( ! item )
				return {};

			rval.emplace_back(move(*item));
			}

		return {rval};
		}
	case TYPE_RECORD:
		{
		auto rec = v->AsRecordVal();
		broker::record rval;
		auto num_fields = v->Type()->AsRecordType()->NumFields();
		rval.fields.reserve(num_fields);

		for ( auto i = 0u; i < num_fields; ++i )
			{
			auto item_val = rec->LookupWithDefault(i);

			if ( ! item_val )
				{
				rval.fields.emplace_back(broker::record::field{});
				continue;
				}

			auto item = val_to_data(item_val);
			Unref(item_val);

			if ( ! item )
				return {};

			rval.fields.emplace_back(broker::record::field{move(*item)});
			}

		return {rval};
		}
	default:
		reporter->Error("unsupported Comm::Data type: %s",
		                type_name(v->Type()->Tag()));
		break;
	}

	return {};
	}

RecordVal* comm::make_data_val(const Val* v)
	{
	auto rval = new RecordVal(BifType::Record::Comm::Data);
	auto data = val_to_data(v);

	if ( data )
		rval->Assign(0, new DataVal(move(*data)));

	return rval;
	}
