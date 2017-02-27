#include "Data.h"
#include "broker/data.bif.h"
#include <caf/binary_serializer.hpp>
#include <caf/binary_deserializer.hpp>

using namespace std;

OpaqueType* bro_broker::opaque_of_data_type;
OpaqueType* bro_broker::opaque_of_set_iterator;
OpaqueType* bro_broker::opaque_of_table_iterator;
OpaqueType* bro_broker::opaque_of_vector_iterator;
OpaqueType* bro_broker::opaque_of_record_iterator;

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

TransportProto bro_broker::to_bro_port_proto(broker::port::protocol tp)
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
	bool require_log_attr;

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

	result_type operator()(std::string& a)
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

	result_type operator()(broker::address& a)
		{
		if ( type->Tag() == TYPE_ADDR )
			{
			auto bits = reinterpret_cast<const in6_addr*>(&a.bytes());
			return new AddrVal(IPAddr(*bits));
			}

		return nullptr;
		}

	result_type operator()(broker::subnet& a)
		{
		if ( type->Tag() == TYPE_SUBNET )
			{
			auto bits = reinterpret_cast<const in6_addr*>(&a.network().bytes());
			return new SubNetVal(IPPrefix(IPAddr(*bits), a.length()));
			}

		return nullptr;
		}

	result_type operator()(broker::port& a)
		{
		if ( type->Tag() == TYPE_PORT )
			return new PortVal(a.number(), bro_broker::to_bro_port_proto(a.type()));

		return nullptr;
		}

	result_type operator()(broker::time_point& a)
		{
		if ( type->Tag() == TYPE_TIME )
			return new Val(a.value, TYPE_TIME);

		return nullptr;
		}

	result_type operator()(broker::time_duration& a)
		{
		if ( type->Tag() == TYPE_INTERVAL )
			return new Val(a.value, TYPE_INTERVAL);

		return nullptr;
		}

	result_type operator()(broker::enum_value& a)
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
			broker::vector composite_key;
			auto indices = broker::get<broker::vector>(item);

			if ( ! indices )
				{
				composite_key.emplace_back(move(item));
				indices = &composite_key;
				}

			auto expected_index_types = tt->Indices()->Types();

			if ( static_cast<size_t>(expected_index_types->length()) !=
			     indices->size() )
				{
				Unref(rval);
				return nullptr;
				}

			auto list_val = new ListVal(TYPE_ANY);

			for ( auto i = 0u; i < indices->size(); ++i )
				{
				auto index_val = bro_broker::data_to_val(move((*indices)[i]),
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
			broker::vector composite_key;
			auto indices = broker::get<broker::vector>(item.first);

			if ( ! indices )
				{
				composite_key.emplace_back(move(item.first));
				indices = &composite_key;
				}

			auto expected_index_types = tt->Indices()->Types();

			if ( static_cast<size_t>(expected_index_types->length()) !=
			     indices->size() )
				{
				Unref(rval);
				return nullptr;
				}

			auto list_val = new ListVal(TYPE_ANY);

			for ( auto i = 0u; i < indices->size(); ++i )
				{
				auto index_val = bro_broker::data_to_val(move((*indices)[i]),
				                                         (*expected_index_types)[i]);

				if ( ! index_val )
					{
					Unref(rval);
					Unref(list_val);
					return nullptr;
					}

				list_val->Append(index_val);
				}

			auto value_val = bro_broker::data_to_val(move(item.second),
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
			auto item_val = bro_broker::data_to_val(move(item), vt->YieldType());

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
		auto rval = new RecordVal(rt);
		auto idx = 0u;

		for ( auto i = 0u; i < static_cast<size_t>(rt->NumFields()); ++i )
			{
			if ( require_log_attr && ! rt->FieldDecl(i)->FindAttr(ATTR_LOG) )
				continue;

			if ( idx >= a.fields.size() )
				{
				Unref(rval);
				return nullptr;
				}

			if ( ! a.fields[idx] )
				{
				rval->Assign(i, nullptr);
				++idx;
				continue;
				}

			auto item_val = bro_broker::data_to_val(move(*a.fields[idx]),
			                                        rt->FieldType(i));

			if ( ! item_val )
				{
				Unref(rval);
				return nullptr;
				}

			rval->Assign(i, item_val);
			++idx;
			}

		return rval;
		}
};

Val* bro_broker::data_to_val(broker::data d, BroType* type, bool require_log_attr)
	{
	return broker::visit(val_converter{type, require_log_attr}, d);
	}

broker::util::optional<broker::data> bro_broker::val_to_data(Val* v)
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
		return {broker::enum_value(enum_name ? enum_name : "<unknown enum>")};
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

		HashKey* k;
		TableEntryVal* entry;
		auto c = table->InitForIteration();

		while ( (entry = table->NextEntry(k, c)) )
			{
			auto vl = table_val->RecoverIndex(k);
			iter_guard ig(k, vl);

			broker::vector composite_key;
			composite_key.reserve(vl->Length());

			for ( auto k = 0; k < vl->Length(); ++k )
				{
				auto key_part = val_to_data((*vl->Vals())[k]);

				if ( ! key_part )
					return {};

				composite_key.emplace_back(move(*key_part));
				}

			broker::data key;

			if ( composite_key.size() == 1 )
				key = move(composite_key[0]);
			else
				key = move(composite_key);

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
		size_t num_fields = v->Type()->AsRecordType()->NumFields();
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
		reporter->Error("unsupported Broker::Data type: %s",
		                type_name(v->Type()->Tag()));
		break;
	}

	return {};
	}

RecordVal* bro_broker::make_data_val(Val* v)
	{
	auto rval = new RecordVal(BifType::Record::Broker::Data);
	auto data = val_to_data(v);

	if ( data )
		rval->Assign(0, new DataVal(move(*data)));

	return rval;
	}

RecordVal* bro_broker::make_data_val(broker::data d)
	{
	auto rval = new RecordVal(BifType::Record::Broker::Data);
	rval->Assign(0, new DataVal(move(d)));
	return rval;
	}

struct data_type_getter {
	using result_type = EnumVal*;

	result_type operator()(bool a)
		{
		return new EnumVal(BifEnum::Broker::BOOL,
		                   BifType::Enum::Broker::DataType);
		}

	result_type operator()(uint64_t a)
		{
		return new EnumVal(BifEnum::Broker::COUNT,
		                   BifType::Enum::Broker::DataType);
		}

	result_type operator()(int64_t a)
		{
		return new EnumVal(BifEnum::Broker::INT,
		                   BifType::Enum::Broker::DataType);
		}

	result_type operator()(double a)
		{
		return new EnumVal(BifEnum::Broker::DOUBLE,
		                   BifType::Enum::Broker::DataType);
		}

	result_type operator()(const std::string& a)
		{
		return new EnumVal(BifEnum::Broker::STRING,
		                   BifType::Enum::Broker::DataType);
		}

	result_type operator()(const broker::address& a)
		{
		return new EnumVal(BifEnum::Broker::ADDR,
		                   BifType::Enum::Broker::DataType);
		}

	result_type operator()(const broker::subnet& a)
		{
		return new EnumVal(BifEnum::Broker::SUBNET,
		                   BifType::Enum::Broker::DataType);
		}

	result_type operator()(const broker::port& a)
		{
		return new EnumVal(BifEnum::Broker::PORT,
		                   BifType::Enum::Broker::DataType);
		}

	result_type operator()(const broker::time_point& a)
		{
		return new EnumVal(BifEnum::Broker::TIME,
		                   BifType::Enum::Broker::DataType);
		}

	result_type operator()(const broker::time_duration& a)
		{
		return new EnumVal(BifEnum::Broker::INTERVAL,
		                   BifType::Enum::Broker::DataType);
		}

	result_type operator()(const broker::enum_value& a)
		{
		return new EnumVal(BifEnum::Broker::ENUM,
		                   BifType::Enum::Broker::DataType);
		}

	result_type operator()(const broker::set& a)
		{
		return new EnumVal(BifEnum::Broker::SET,
		                   BifType::Enum::Broker::DataType);
		}

	result_type operator()(const broker::table& a)
		{
		return new EnumVal(BifEnum::Broker::TABLE,
		                   BifType::Enum::Broker::DataType);
		}

	result_type operator()(const broker::vector& a)
		{
		return new EnumVal(BifEnum::Broker::VECTOR,
		                   BifType::Enum::Broker::DataType);
		}

	result_type operator()(const broker::record& a)
		{
		return new EnumVal(BifEnum::Broker::RECORD,
		                   BifType::Enum::Broker::DataType);
		}
};

EnumVal* bro_broker::get_data_type(RecordVal* v, Frame* frame)
	{
	return broker::visit(data_type_getter{}, opaque_field_to_data(v, frame));
	}

broker::data& bro_broker::opaque_field_to_data(RecordVal* v, Frame* f)
	{
	Val* d = v->Lookup(0);

	if ( ! d )
		reporter->RuntimeError(f->GetCall()->GetLocationInfo(),
		                       "Broker::Data's opaque field is not set");

	return static_cast<DataVal*>(d)->data;
	}

IMPLEMENT_SERIAL(bro_broker::DataVal, SER_COMM_DATA_VAL);

bool bro_broker::DataVal::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_COMM_DATA_VAL, OpaqueVal);

	std::string serial;
	caf::binary_serializer bs(std::back_inserter(serial));
	bs << data;

	if ( ! SERIALIZE_STR(serial.data(), serial.size()) )
		return false;

	return true;
	}

bool bro_broker::DataVal::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(OpaqueVal);

	const char* serial;
	int len;

	if ( ! UNSERIALIZE_STR(&serial, &len) )
		return false;

	caf::binary_deserializer bd(serial, len);
	caf::uniform_typeid<broker::data>()->deserialize(&data, &bd);
	delete [] serial;
	return true;
	}

static broker::util::optional<broker::data> threading_val_to_data_internal(TypeTag type, const threading::Value::_val& val)
	{
	switch ( type ) {
	case TYPE_BOOL:
	        return {val.int_val != 0};

	case TYPE_INT:
	        return {val.int_val};

	case TYPE_COUNT:
	case TYPE_COUNTER:
	        return {val.uint_val};

	case TYPE_PORT:
		return {broker::port(val.port_val.port, to_broker_port_proto(val.port_val.proto))};

	case TYPE_ADDR:
		{
		IPAddr a;

		switch ( val.addr_val.family ) {
		case IPv4:
			a = IPAddr(val.addr_val.in.in4);
			break;

		case IPv6:
			a = IPAddr(val.addr_val.in.in6);
			break;

		default:
			reporter->InternalError("unsupported protocol family in threading_val_to_data");
		}

		in6_addr tmp;
		a.CopyIPv6(&tmp);
		return {broker::address(reinterpret_cast<const uint32_t*>(&tmp),
					broker::address::family::ipv6,
					broker::address::byte_order::network)};
		}

	case TYPE_SUBNET:
		{
		IPAddr a;
		int length;

		switch ( val.subnet_val.prefix.family ) {
		case IPv4:
			a = IPAddr(val.subnet_val.prefix.in.in4);
			length = (val.subnet_val.length - 96);
			break;

		case IPv6:
			a = IPAddr(val.subnet_val.prefix.in.in6);
			length = val.subnet_val.length;
			break;

		default:
			reporter->InternalError("unsupported protocol family in threading_val_to_data");
		}

		in6_addr tmp;
		a.CopyIPv6(&tmp);

		auto s = broker::address(reinterpret_cast<const uint32_t*>(&tmp),
		                         broker::address::family::ipv6,
		                         broker::address::byte_order::network);
		return {broker::subnet(s, length)};
		}

	case TYPE_DOUBLE:
	        return {val.double_val};

	case TYPE_TIME:
		return {broker::time_point(val.double_val)};

	case TYPE_INTERVAL:
		return {broker::time_duration(val.double_val)};

	case TYPE_ENUM:
		return {broker::enum_value(std::string(val.string_val.data, val.string_val.length))};

	case TYPE_STRING:
	case TYPE_FILE:
	case TYPE_FUNC:
		return {std::string(val.string_val.data, val.string_val.length)};

	case TYPE_TABLE:
		{
		auto s = broker::set();

		for ( int i = 0; i < val.set_val.size; ++i )
			{
			auto c = bro_broker::threading_val_to_data(val.set_val.vals[i]);

			if ( ! c )
				return {};

			s.emplace(*c);
			}

		return {move(s)};
		}

	case TYPE_VECTOR:
		{
		auto s = broker::vector();

		for ( int i = 0; i < val.vector_val.size; ++i )
			{
			auto c = bro_broker::threading_val_to_data(val.vector_val.vals[i]);

			if ( ! c )
				return {};

			s.emplace_back(*c);
			}

		return {move(s)};
		}

	default:
		reporter->InternalError("unsupported type %s in threading_val_to_data",
		                        type_name(type));
	}

	return {};
	}


broker::util::optional<broker::data> bro_broker::threading_val_to_data(const threading::Value* v)
	{
	broker::util::optional<broker::data> d;

	if ( v->present )
		{
		d = threading_val_to_data_internal(v->type, v->val);

		if ( ! d )
			return {};
		}

	auto type = broker::record::field(static_cast<uint64_t>(v->type));
	auto present = broker::record::field(v->present);
	auto data = (v->present) ? broker::record::field(*d) : broker::util::optional<broker::data>();

	return {broker::record({move(type), move(present), move(data)})};
	};

struct threading_val_converter {
	using result_type = bool;

	TypeTag type;
	threading::Value::_val& val;

	result_type operator()(bool a)
		{
		if ( type == TYPE_BOOL )
			{
			val.int_val = (a ? 1 : 0);
			return true;
			}

		return false;
		}

	result_type operator()(uint64_t a)
		{
		if ( type == TYPE_COUNT || type == TYPE_COUNTER )
			{
			val.uint_val = a;
			return true;
			}

		return false;
		}

	result_type operator()(int64_t a)
		{
		if ( type == TYPE_INT )
			{
			val.int_val = a;
			return true;
			}

		return false;
		}

	result_type operator()(double a)
		{
		if ( type == TYPE_DOUBLE )
			{
			val.double_val = a;
			return true;
			}

		return false;
		}


	result_type operator()(const std::string& a)
		{
		if ( type == TYPE_STRING || type == TYPE_FILE || type == TYPE_FUNC )
			{
			auto n = a.size();
			val.string_val.length = n;
			val.string_val.data = new char[n];
			memcpy(val.string_val.data, a.data(), n);
			return true;
			}

		return false;
		}

	result_type operator()(const broker::address& a)
		{
		if ( type == TYPE_ADDR )
			{
			auto bits = reinterpret_cast<const in6_addr*>(&a.bytes());
			auto b = IPAddr(*bits);

			if ( a.is_v4() )
				{
				val.addr_val.family = IPv4;
				b.CopyIPv4(&val.addr_val.in.in4);
				return true;
				}

			if ( a.is_v6() )
				{
				val.addr_val.family = IPv6;
				b.CopyIPv6(&val.addr_val.in.in6);
				return true;
				}
			}

		return false;
		}

	result_type operator()(const broker::subnet& s)
		{
		if ( type == TYPE_SUBNET )
			{
			auto bits = reinterpret_cast<const in6_addr*>(&s.network().bytes());
			auto a = IPAddr(*bits);

			val.subnet_val.length = s.length();

			if ( s.network().is_v4() )
				{
				val.subnet_val.prefix.family = IPv4;
				a.CopyIPv4(&val.subnet_val.prefix.in.in4);
				val.subnet_val.length += 96;
				return true;
				}

			if ( s.network().is_v6() )
				{
				val.subnet_val.prefix.family = IPv6;
				a.CopyIPv6(&val.subnet_val.prefix.in.in6);
				return true;
				}
			}

		return false;
		}

	result_type operator()(const broker::port& a)
		{
		if ( type == TYPE_PORT )
			{
			val.port_val.port = a.number();
			val.port_val.proto = bro_broker::to_bro_port_proto(a.type());
			return true;
			}

		return false;
		}

	result_type operator()(const broker::time_point& a)
		{
		if ( type == TYPE_TIME )
			{
			val.double_val = a.value;
			return true;
			}

		return false;
		}

	result_type operator()(const broker::time_duration& a)
		{
		if ( type == TYPE_INTERVAL )
			{
			val.double_val = a.value;
			return true;
			}

		return false;
		}

	result_type operator()(const broker::enum_value& a)
		{
		if ( type == TYPE_ENUM )
			{
			auto n = a.name.size();
			val.string_val.length = n;
			val.string_val.data = new char[n];
			memcpy(val.string_val.data, a.name.data(), n);
			return true;
			}

		return false;
		}

	result_type operator()(const broker::set& a)
		{
		if ( type == TYPE_TABLE )
			{
			val.set_val.size = a.size();
			val.set_val.vals = new threading::Value* [val.set_val.size];

			auto p = val.set_val.vals;

			for ( auto& i : a )
				*p++ = bro_broker::data_to_threading_val(move(i));

			return true;
			}

		return false;
		}

	result_type operator()(const broker::table& a)
		{
		return false;
		}

	result_type operator()(const broker::vector& a)
		{
		if ( type == TYPE_VECTOR )
			{
			val.vector_val.size = a.size();
			val.vector_val.vals = new threading::Value* [val.vector_val.size];

			auto p = val.vector_val.vals;

			for ( auto& i : a )
				*p++ = bro_broker::data_to_threading_val(move(i));

			return true;
			}

		return false;
		}

	result_type operator()(const broker::record& a)
		{
		return false;
		}
};

threading::Value* bro_broker::data_to_threading_val(broker::data d)
	{
	auto r = broker::get<broker::record>(d);

	if ( ! r )
		return nullptr;

	auto type = broker::get<uint64_t>(*r->get(0));
	auto present = broker::get<bool>(*r->get(1));
	auto data = r->get(2);

	if ( ! (type && present) )
		return nullptr;

	if ( *present && ! data )
		return nullptr;

	auto tv = new threading::Value;
	tv->type = static_cast<TypeTag>(*type);
	tv->present = *present;

	if ( *present && ! broker::visit(threading_val_converter{tv->type, tv->val}, *data) )
		{
		delete tv;
		return nullptr;
		}

	return tv;
	}

broker::data bro_broker::threading_field_to_data(const threading::Field* f)
	{
	auto name = broker::record::field(f->name);
	auto type = broker::record::field(static_cast<uint64_t>(f->type));
	auto subtype = broker::record::field(static_cast<uint64_t>(f->subtype));
	auto optional = broker::record::field(f->optional);

	broker::util::optional<broker::data> secondary;

	if ( f->secondary_name )
		secondary = {f->secondary_name};

	return move(broker::record({name, secondary, type, subtype, optional}));
	}

threading::Field* bro_broker::data_to_threading_field(broker::data d)
	{
	auto r = broker::get<broker::record>(d);

	if ( ! r )
		return nullptr;

	auto name = broker::get<std::string>(*r->get(0));
	auto secondary = r->get(1);
	auto type = broker::get<uint64_t>(*r->get(2));
	auto subtype = broker::get<uint64_t>(*r->get(3));
	auto optional = broker::get<bool>(*r->get(4));

	if ( ! (name && type && subtype && optional) )
		return nullptr;

	if ( secondary && ! broker::is<std::string>(*secondary) )
		return nullptr;

	return new threading::Field(name->c_str(),
				    secondary ? broker::get<std::string>(*secondary)->c_str() : nullptr,
				    static_cast<TypeTag>(*type),
				    static_cast<TypeTag>(*subtype),
				    *optional);
	}
