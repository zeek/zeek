#include "Data.h"
#include "broker/data.bif.h"
#include <caf/stream_serializer.hpp>
#include <caf/stream_deserializer.hpp>
#include <caf/streambuf.hpp>

using namespace std;

OpaqueType* bro_broker::opaque_of_data_type;
OpaqueType* bro_broker::opaque_of_set_iterator;
OpaqueType* bro_broker::opaque_of_table_iterator;
OpaqueType* bro_broker::opaque_of_vector_iterator;
OpaqueType* bro_broker::opaque_of_record_iterator;

BroType* bro_broker::DataVal::script_data_type = nullptr;

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

	result_type operator()(broker::none)
		{
		return nullptr;
		}

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
			auto id = global_scope()->Lookup(a.data());

			if ( ! id )
				return nullptr;

			auto rval = id->ID_Val();

			if ( ! rval )
				return nullptr;

			auto t = rval->Type();

			if ( ! t )
				return nullptr;

			if ( t->Tag() != TYPE_FUNC )
				return nullptr;

			return rval->Ref();
			}
		case TYPE_OPAQUE:
			{
			SerializationFormat* form = new BinarySerializationFormat();
			form->StartRead(a.data(), a.size());
			CloneSerializer ss(form);
			UnserialInfo uinfo(&ss);
			uinfo.cache = false;
			return Val::Unserialize(&uinfo, type->Tag());
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
			return port_mgr->Get(a.number(), bro_broker::to_bro_port_proto(a.type()));

		return nullptr;
		}

	result_type operator()(broker::timestamp& a)
		{
		if ( type->Tag() != TYPE_TIME )
			return nullptr;

		using namespace std::chrono;
		auto s = duration_cast<broker::fractional_seconds>(a.time_since_epoch());
		return new Val(s.count(), TYPE_TIME);
		}

	result_type operator()(broker::timespan& a)
		{
		if ( type->Tag() != TYPE_INTERVAL )
			return nullptr;

		using namespace std::chrono;
		auto s = duration_cast<broker::fractional_seconds>(a);
		return new Val(s.count(), TYPE_INTERVAL);
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
			auto indices = broker::get_if<broker::vector>(item);

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
			auto indices = broker::get_if<broker::vector>(item.first);

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
		if ( type->Tag() == TYPE_VECTOR )
			{
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
		else if ( type->Tag() == TYPE_RECORD )
			{
			auto rt = type->AsRecordType();
			auto rval = new RecordVal(rt);
			auto idx = 0u;

			for ( auto i = 0u; i < static_cast<size_t>(rt->NumFields()); ++i )
				{
				if ( require_log_attr && ! rt->FieldDecl(i)->FindAttr(ATTR_LOG) )
					continue;

				if ( idx >= a.size() )
					{
					Unref(rval);
					return nullptr;
					}

				if ( broker::get_if<broker::none>(a[idx]) != nullptr )
					{
					rval->Assign(i, nullptr);
					++idx;
					continue;
					}

				auto item_val = bro_broker::data_to_val(move(a[idx]),
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
		else if ( type->Tag() == TYPE_PATTERN )
			{
			if ( a.size() != 2 )
				return nullptr;

			auto exact_text = broker::get_if<std::string>(a[0]);
			auto anywhere_text = broker::get_if<std::string>(a[1]);

			if ( ! exact_text || ! anywhere_text )
				return nullptr;

			RE_Matcher* re = new RE_Matcher(exact_text->c_str(),
			                                anywhere_text->c_str());

			if ( ! re->Compile() )
				{
				reporter->Error("failed compiling unserialized pattern: %s, %s",
				                exact_text->c_str(), anywhere_text->c_str());
				delete re;
				return nullptr;
				}

			auto rval = new PatternVal(re);
			return rval;
			}

		return nullptr;
		}
};

Val* bro_broker::data_to_val(broker::data d, BroType* type, bool require_log_attr)
	{
	return broker::visit(val_converter{type, require_log_attr}, std::move(d));
	}

broker::expected<broker::data> bro_broker::val_to_data(Val* v)
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
		{
	  auto secs = broker::fractional_seconds{v->AsTime()};
	  auto since_epoch = std::chrono::duration_cast<broker::timespan>(secs);
		return {broker::timestamp{since_epoch}};
		}
	case TYPE_INTERVAL:
		{
	  auto secs = broker::fractional_seconds{v->AsInterval()};
		return {std::chrono::duration_cast<broker::timespan>(secs)};
		}
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
					return broker::ec::invalid_data;

				composite_key.emplace_back(move(*key_part));
				}

			broker::data key;

			if ( composite_key.size() == 1 )
				key = move(composite_key[0]);
			else
				key = move(composite_key);

			if ( is_set )
				broker::get<broker::set>(rval).emplace(move(key));
			else
				{
				auto val = val_to_data(entry->Value());

				if ( ! val )
					return broker::ec::invalid_data;

				broker::get<broker::table>(rval).emplace(move(key), move(*val));
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
				return broker::ec::invalid_data;

			rval.emplace_back(move(*item));
			}

		return {rval};
		}
	case TYPE_RECORD:
		{
		auto rec = v->AsRecordVal();
		broker::vector rval;
		size_t num_fields = v->Type()->AsRecordType()->NumFields();
		rval.reserve(num_fields);

		for ( auto i = 0u; i < num_fields; ++i )
			{
			auto item_val = rec->LookupWithDefault(i);

			if ( ! item_val )
				{
				rval.emplace_back(broker::nil);
				continue;
				}

			auto item = val_to_data(item_val);
			Unref(item_val);

			if ( ! item )
				return broker::ec::invalid_data;

			rval.emplace_back(move(*item));
			}

		return {rval};
		}
	case TYPE_PATTERN:
		{
		RE_Matcher* p = v->AsPattern();
		broker::vector rval = {p->PatternText(), p->AnywherePatternText()};
		return {rval};
		}
	case TYPE_OPAQUE:
		{
		SerializationFormat* form = new BinarySerializationFormat();
		form->StartWrite();
		CloneSerializer ss(form);
		SerialInfo sinfo(&ss);
		sinfo.cache = false;
		sinfo.include_locations = false;

		if ( ! v->Serialize(&sinfo) )
			return broker::ec::invalid_data;

		char* data;
		uint32 len = form->EndWrite(&data);
		string rval(data, len);
		free(data);
		return {rval};
		}
	default:
		reporter->Error("unsupported Broker::Data type: %s",
		                type_name(v->Type()->Tag()));
		break;
	}

	return broker::ec::invalid_data;
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

	result_type operator()(broker::none)
		{
		return new EnumVal(BifEnum::Broker::NONE,
		                   BifType::Enum::Broker::DataType);
		}

	result_type operator()(bool)
		{
		return new EnumVal(BifEnum::Broker::BOOL,
		                   BifType::Enum::Broker::DataType);
		}

	result_type operator()(uint64_t)
		{
		return new EnumVal(BifEnum::Broker::COUNT,
		                   BifType::Enum::Broker::DataType);
		}

	result_type operator()(int64_t)
		{
		return new EnumVal(BifEnum::Broker::INT,
		                   BifType::Enum::Broker::DataType);
		}

	result_type operator()(double)
		{
		return new EnumVal(BifEnum::Broker::DOUBLE,
		                   BifType::Enum::Broker::DataType);
		}

	result_type operator()(const std::string&)
		{
		return new EnumVal(BifEnum::Broker::STRING,
		                   BifType::Enum::Broker::DataType);
		}

	result_type operator()(const broker::address&)
		{
		return new EnumVal(BifEnum::Broker::ADDR,
		                   BifType::Enum::Broker::DataType);
		}

	result_type operator()(const broker::subnet&)
		{
		return new EnumVal(BifEnum::Broker::SUBNET,
		                   BifType::Enum::Broker::DataType);
		}

	result_type operator()(const broker::port&)
		{
		return new EnumVal(BifEnum::Broker::PORT,
		                   BifType::Enum::Broker::DataType);
		}

	result_type operator()(const broker::timestamp&)
		{
		return new EnumVal(BifEnum::Broker::TIME,
		                   BifType::Enum::Broker::DataType);
		}

	result_type operator()(const broker::timespan&)
		{
		return new EnumVal(BifEnum::Broker::INTERVAL,
		                   BifType::Enum::Broker::DataType);
		}

	result_type operator()(const broker::enum_value&)
		{
		return new EnumVal(BifEnum::Broker::ENUM,
		                   BifType::Enum::Broker::DataType);
		}

	result_type operator()(const broker::set&)
		{
		return new EnumVal(BifEnum::Broker::SET,
		                   BifType::Enum::Broker::DataType);
		}

	result_type operator()(const broker::table&)
		{
		return new EnumVal(BifEnum::Broker::TABLE,
		                   BifType::Enum::Broker::DataType);
		}

	result_type operator()(const broker::vector&)
		{
		auto result = result_type{nullptr};
		if (type->Tag() == TYPE_VECTOR)
			result = new EnumVal(BifEnum::Broker::VECTOR,
					     BifType::Enum::Broker::DataType);
		else if (type->Tag() == TYPE_RECORD)
			result = new EnumVal(BifEnum::Broker::RECORD,
					     BifType::Enum::Broker::DataType);
		assert(result);
		return result;
		}

	BroType* type;
};

EnumVal* bro_broker::get_data_type(RecordVal* v, Frame* frame)
	{
	return broker::visit(data_type_getter{v->Type()},
			     opaque_field_to_data(v, frame));
	}

broker::data& bro_broker::opaque_field_to_data(RecordVal* v, Frame* f)
	{
	Val* d = v->Lookup(0);

	if ( ! d )
		reporter->RuntimeError(f->GetCall()->GetLocationInfo(),
		                       "Broker::Data's opaque field is not set");

	return static_cast<DataVal*>(d)->data;
	}

bool bro_broker::DataVal::canCastTo(BroType* t) const
	{
	// TODO: This is much more work than we need. We should add a
	// type_check visitor that checks if data_to_val() would return a
	// given type.
	auto v = data_to_val(data, t, false);
	auto can_cast = (v != nullptr);
	Unref(v);
	return can_cast;
	}

Val* bro_broker::DataVal::castTo(BroType* t)
	{
	return data_to_val(data, t, false);
	}

IMPLEMENT_SERIAL(bro_broker::DataVal, SER_COMM_DATA_VAL);

bool bro_broker::DataVal::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_COMM_DATA_VAL, OpaqueVal);

	std::string buffer;
	caf::containerbuf<std::string> sb{buffer};
	caf::stream_serializer<caf::containerbuf<std::string>&> serializer{sb};
	serializer << data;

	if ( ! SERIALIZE_STR(buffer.data(), buffer.size()) )
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

	caf::arraybuf<char> sb{const_cast<char*>(serial), // will not write
	                       static_cast<size_t>(len)};
	caf::stream_deserializer<caf::arraybuf<char>&> deserializer{sb};
	deserializer >> data;

	delete [] serial;
	return true;
	}

static broker::expected<broker::data> threading_val_to_data_internal(TypeTag type, const threading::Value::_val& val)
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
	        {
		broker::timestamp ts;
                broker::convert(val.double_val, ts);
		return ts;
		}

	case TYPE_INTERVAL:
	        {
		broker::timespan ts;
                broker::convert(val.double_val, ts);
		return ts;
		}

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
				return broker::ec::invalid_data;

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
				return broker::ec::invalid_data;

			s.emplace_back(*c);
			}

		return {move(s)};
		}

	default:
		reporter->InternalError("unsupported type %s in threading_val_to_data",
		                        type_name(type));
	}

	return broker::ec::invalid_data;
	}


broker::expected<broker::data> bro_broker::threading_val_to_data(const threading::Value* v)
	{
	broker::data d(broker::nil);

	if ( v->present )
		{
		auto x = threading_val_to_data_internal(v->type, v->val);

		if ( ! x )
			return broker::ec::invalid_data;

		d = *x;
		}

	return broker::vector{static_cast<uint64_t>(v->type), v->present, std::move(d)};
	};

struct threading_val_converter {
	using result_type = bool;

	TypeTag type;
	threading::Value::_val& val;

	result_type operator()(broker::none)
		{
		return false;
		}

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

	result_type operator()(const broker::timestamp& a)
		{
		if ( type == TYPE_TIME )
			{
			broker::convert(a, val.double_val);
			return true;
			}

		return false;
		}

	result_type operator()(const broker::timespan& a)
		{
		if ( type == TYPE_INTERVAL )
			{
			broker::convert(a, val.double_val);
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
};

threading::Value* bro_broker::data_to_threading_val(broker::data d)
	{
	if ( ! broker::is<broker::vector>(d) )
		return nullptr;

	auto v = broker::get<broker::vector>(d);
	auto type = broker::get_if<uint64_t>(v[0]);
	auto present = broker::get_if<bool>(v[1]);
	auto data = v[2];

	if ( ! (type && present) )
		return nullptr;

	if ( *present && data == broker::nil )
		return nullptr;

	auto tv = new threading::Value;
	tv->type = static_cast<TypeTag>(*type);
	tv->present = *present;

	if ( *present && ! broker::visit(threading_val_converter{tv->type, tv->val}, data) )
		{
		delete tv;
		return nullptr;
		}

	return tv;
	}

broker::data bro_broker::threading_field_to_data(const threading::Field* f)
	{
	auto name = f->name;
	auto type = static_cast<uint64_t>(f->type);
	auto subtype = static_cast<uint64_t>(f->subtype);
	auto optional = f->optional;

	broker::data secondary = broker::nil;

	if ( f->secondary_name )
		secondary = {f->secondary_name};

	return broker::vector({name, secondary, type, subtype, optional});
	}

threading::Field* bro_broker::data_to_threading_field(broker::data d)
	{
	if ( ! broker::is<broker::vector>(d) )
		return nullptr;

	auto v = broker::get<broker::vector>(d);
	auto name = broker::get_if<std::string>(v[0]);
	auto secondary = v[1];
	auto type = broker::get_if<broker::count>(v[2]);
	auto subtype = broker::get_if<broker::count>(v[3]);
	auto optional = broker::get_if<broker::boolean>(v[4]);

	if ( ! (name && type && subtype && optional) )
		return nullptr;

	if ( secondary != broker::nil && ! broker::is<std::string>(secondary) )
		return nullptr;

	return new threading::Field(name->c_str(),
				    secondary != broker::nil ? broker::get<std::string>(secondary).c_str() : nullptr,
				    static_cast<TypeTag>(*type),
				    static_cast<TypeTag>(*subtype),
				    *optional);
	}
