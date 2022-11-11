#include "zeek/broker/Data.h"

#include <broker/error.hh>

#include "zeek/3rdparty/doctest.h"
#include "zeek/Desc.h"
#include "zeek/File.h"
#include "zeek/Func.h"
#include "zeek/ID.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/RE.h"
#include "zeek/Scope.h"
#include "zeek/broker/data.bif.h"
#include "zeek/module_util.h"

using namespace std;

zeek::OpaqueTypePtr zeek::Broker::detail::opaque_of_data_type;
zeek::OpaqueTypePtr zeek::Broker::detail::opaque_of_set_iterator;
zeek::OpaqueTypePtr zeek::Broker::detail::opaque_of_table_iterator;
zeek::OpaqueTypePtr zeek::Broker::detail::opaque_of_vector_iterator;
zeek::OpaqueTypePtr zeek::Broker::detail::opaque_of_record_iterator;

static broker::port::protocol to_broker_port_proto(TransportProto tp)
	{
	switch ( tp )
		{
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

TEST_CASE("converting Zeek to Broker protocol constants")
	{
	CHECK_EQ(to_broker_port_proto(TRANSPORT_TCP), broker::port::protocol::tcp);
	CHECK_EQ(to_broker_port_proto(TRANSPORT_UDP), broker::port::protocol::udp);
	CHECK_EQ(to_broker_port_proto(TRANSPORT_ICMP), broker::port::protocol::icmp);
	CHECK_EQ(to_broker_port_proto(TRANSPORT_UNKNOWN), broker::port::protocol::unknown);
	}

namespace zeek::Broker::detail
	{

// Returns true if the given Zeek type is serialized as a broker::vector
static bool serialized_as_vector(TypeTag tag)
	{
	switch ( tag )
		{
		case TYPE_VECTOR:
		case TYPE_RECORD:
		case TYPE_FUNC:
		case TYPE_PATTERN:
		case TYPE_OPAQUE:
			return true;
		default:
			return false;
		}
	return false;
	}

static bool data_type_check(const broker::data& d, Type* t);

TransportProto to_zeek_port_proto(broker::port::protocol tp)
	{
	switch ( tp )
		{
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

TEST_CASE("converting Broker to Zeek protocol constants")
	{
	CHECK_EQ(to_zeek_port_proto(broker::port::protocol::tcp), TRANSPORT_TCP);
	CHECK_EQ(to_zeek_port_proto(broker::port::protocol::udp), TRANSPORT_UDP);
	CHECK_EQ(to_zeek_port_proto(broker::port::protocol::icmp), TRANSPORT_ICMP);
	CHECK_EQ(to_zeek_port_proto(broker::port::protocol::unknown), TRANSPORT_UNKNOWN);
	}

struct val_converter
	{
	using result_type = ValPtr;

	Type* type;

	result_type operator()(broker::none) { return nullptr; }

	result_type operator()(bool a)
		{
		if ( type->Tag() == TYPE_BOOL )
			return val_mgr->Bool(a);
		return nullptr;
		}

	result_type operator()(uint64_t a)
		{
		if ( type->Tag() == TYPE_COUNT )
			return val_mgr->Count(a);
		return nullptr;
		}

	result_type operator()(int64_t a)
		{
		if ( type->Tag() == TYPE_INT )
			return val_mgr->Int(a);
		return nullptr;
		}

	result_type operator()(double a)
		{
		if ( type->Tag() == TYPE_DOUBLE )
			return make_intrusive<DoubleVal>(a);
		return nullptr;
		}

	result_type operator()(std::string& a)
		{
		switch ( type->Tag() )
			{
			case TYPE_STRING:
				return make_intrusive<StringVal>(a.size(), a.data());
			case TYPE_FILE:
				{
				auto file = File::Get(a.data());

				if ( file )
					return make_intrusive<FileVal>(std::move(file));

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
			return make_intrusive<AddrVal>(IPAddr(*bits));
			}

		return nullptr;
		}

	result_type operator()(broker::subnet& a)
		{
		if ( type->Tag() == TYPE_SUBNET )
			{
			auto bits = reinterpret_cast<const in6_addr*>(&a.network().bytes());
			return make_intrusive<SubNetVal>(IPPrefix(IPAddr(*bits), a.length()));
			}

		return nullptr;
		}

	result_type operator()(broker::port& a)
		{
		if ( type->Tag() == TYPE_PORT )
			return val_mgr->Port(a.number(), to_zeek_port_proto(a.type()));

		return nullptr;
		}

	result_type operator()(broker::timestamp& a)
		{
		if ( type->Tag() != TYPE_TIME )
			return nullptr;

		using namespace std::chrono;
		auto s = duration_cast<broker::fractional_seconds>(a.time_since_epoch());
		return make_intrusive<TimeVal>(s.count());
		}

	result_type operator()(broker::timespan& a)
		{
		if ( type->Tag() != TYPE_INTERVAL )
			return nullptr;

		using namespace std::chrono;
		auto s = duration_cast<broker::fractional_seconds>(a);
		return make_intrusive<IntervalVal>(s.count());
		}

	result_type operator()(broker::enum_value& a)
		{
		if ( type->Tag() == TYPE_ENUM )
			{
			auto etype = type->AsEnumType();
			auto i = etype->Lookup(zeek::detail::GLOBAL_MODULE_NAME, a.name.data());

			if ( i == -1 )
				return nullptr;

			auto rval = etype->GetEnumVal(i);
			return rval;
			}

		return nullptr;
		}

	result_type operator()(broker::set& a)
		{
		if ( ! type->IsSet() )
			return nullptr;

		auto tt = type->AsTableType();
		auto rval = make_intrusive<TableVal>(IntrusivePtr{NewRef{}, tt});

		for ( auto& item : a )
			{
			const auto& expected_index_types = tt->GetIndices()->GetTypes();
			broker::vector composite_key;
			auto indices = get_if<broker::vector>(&item);

			if ( indices )
				{
				if ( expected_index_types.size() == 1 )
					{
					auto disambiguate = serialized_as_vector(expected_index_types[0]->Tag());

					if ( disambiguate )
						{
						// Disambiguate from composite key w/ multiple vals.
						composite_key.emplace_back(move(item));
						indices = &composite_key;
						}
					}
				}
			else
				{
				composite_key.emplace_back(move(item));
				indices = &composite_key;
				}

			if ( expected_index_types.size() != indices->size() )
				return nullptr;

			auto list_val = make_intrusive<ListVal>(TYPE_ANY);

			for ( size_t i = 0; i < indices->size(); ++i )
				{
				auto index_val = data_to_val(move((*indices)[i]), expected_index_types[i].get());

				if ( ! index_val )
					return nullptr;

				list_val->Append(std::move(index_val));
				}

			rval->Assign(std::move(list_val), nullptr);
			}

		return rval;
		}

	result_type operator()(broker::table& a)
		{
		if ( ! type->IsTable() )
			return nullptr;

		auto tt = type->AsTableType();
		auto rval = make_intrusive<TableVal>(IntrusivePtr{NewRef{}, tt});

		for ( auto& item : a )
			{
			const auto& expected_index_types = tt->GetIndices()->GetTypes();
			broker::vector composite_key;
			auto indices = get_if<broker::vector>(&item.first);

			if ( indices )
				{
				if ( expected_index_types.size() == 1 )
					{
					auto disambiguate = serialized_as_vector(expected_index_types[0]->Tag());

					if ( disambiguate )
						{
						// Disambiguate from composite key w/ multiple vals.
						composite_key.emplace_back(move(item.first));
						indices = &composite_key;
						}
					}
				}
			else
				{
				composite_key.emplace_back(move(item.first));
				indices = &composite_key;
				}

			if ( expected_index_types.size() != indices->size() )
				return nullptr;

			auto list_val = make_intrusive<ListVal>(TYPE_ANY);

			for ( size_t i = 0; i < indices->size(); ++i )
				{
				auto index_val = data_to_val(move((*indices)[i]), expected_index_types[i].get());

				if ( ! index_val )
					return nullptr;

				list_val->Append(std::move(index_val));
				}

			auto value_val = data_to_val(move(item.second), tt->Yield().get());

			if ( ! value_val )
				return nullptr;

			rval->Assign(std::move(list_val), std::move(value_val));
			}

		return rval;
		}

	result_type operator()(broker::vector& a)
		{
		if ( type->Tag() == TYPE_VECTOR )
			{
			auto vt = type->AsVectorType();
			auto rval = make_intrusive<VectorVal>(IntrusivePtr{NewRef{}, vt});

			for ( auto& item : a )
				{
				auto item_val = data_to_val(move(item), vt->Yield().get());

				if ( ! item_val )
					return nullptr;

				rval->Assign(rval->Size(), std::move(item_val));
				}

			return rval;
			}
		else if ( type->Tag() == TYPE_LIST )
			{
			// lists are just treated as vectors on the broker side.
			auto lt = type->AsTypeList();
			auto pure = lt->IsPure();
			const auto& types = lt->GetTypes();

			if ( ! pure && a.size() > types.size() )
				return nullptr;

			auto lt_tag = pure ? lt->GetPureType()->Tag() : TYPE_ANY;
			auto rval = make_intrusive<ListVal>(lt_tag);

			unsigned int pos = 0;
			for ( auto& item : a )
				{
				auto item_val = data_to_val(move(item),
				                            pure ? lt->GetPureType().get() : types[pos].get());
				pos++;

				if ( ! item_val )
					return nullptr;

				rval->Append(std::move(item_val));
				}
			return rval;
			}
		else if ( type->Tag() == TYPE_FUNC )
			{
			if ( a.size() < 1 || a.size() > 2 )
				return nullptr;

			auto name = broker::get_if<std::string>(a[0]);
			if ( ! name )
				return nullptr;

			const auto& id = zeek::detail::global_scope()->Find(*name);
			if ( ! id )
				return nullptr;

			const auto& rval = id->GetVal();
			if ( ! rval )
				return nullptr;

			const auto& t = rval->GetType();
			if ( ! t )
				return nullptr;

			if ( t->Tag() != TYPE_FUNC )
				return nullptr;

			if ( a.size() == 2 ) // we have a closure/capture frame
				{
				// Note, seems if we already have a separate
				// instance of the same lambda, then unless
				// we use a cloned value, we'll step on that
				// one's captures, too.  This is because
				// the capture mapping lives with the Func
				// object rather than the FuncVal.  However,
				// we can't readily Clone() here because
				// rval is const (and, grrr, Clone() is not).
				// -VP
				// rval = rval->Clone();

				auto frame = broker::get_if<broker::vector>(a[1]);
				if ( ! frame )
					return nullptr;

				auto* b = dynamic_cast<zeek::detail::ScriptFunc*>(rval->AsFunc());
				if ( ! b || ! b->DeserializeCaptures(*frame) )
					return nullptr;
				}

			return rval;
			}
		else if ( type->Tag() == TYPE_RECORD )
			{
			auto rt = type->AsRecordType();
			auto rval = make_intrusive<RecordVal>(IntrusivePtr{NewRef{}, rt});
			auto idx = 0u;

			for ( size_t i = 0; i < static_cast<size_t>(rt->NumFields()); ++i )
				{
				if ( idx >= a.size() )
					return nullptr;

				if ( get_if<broker::none>(&a[idx]) != nullptr )
					{
					rval->Remove(i);
					++idx;
					continue;
					}

				auto item_val = data_to_val(move(a[idx]), rt->GetFieldType(i).get());

				if ( ! item_val )
					return nullptr;

				rval->Assign(i, std::move(item_val));
				++idx;
				}

			return rval;
			}
		else if ( type->Tag() == TYPE_PATTERN )
			{
			if ( a.size() != 2 )
				return nullptr;

			auto exact_text = get_if<std::string>(&a[0]);
			auto anywhere_text = get_if<std::string>(&a[1]);

			if ( ! exact_text || ! anywhere_text )
				return nullptr;

			auto* re = new RE_Matcher(exact_text->c_str(), anywhere_text->c_str());

			if ( ! re->Compile() )
				{
				reporter->Error("failed compiling unserialized pattern: %s, %s",
				                exact_text->c_str(), anywhere_text->c_str());
				delete re;
				return nullptr;
				}

			auto rval = make_intrusive<PatternVal>(re);
			return rval;
			}
		else if ( type->Tag() == TYPE_OPAQUE )
			return OpaqueVal::Unserialize(a);

		return nullptr;
		}
	};

struct type_checker
	{
	using result_type = bool;

	Type* type;

	result_type operator()(broker::none) { return false; }

	result_type operator()(bool a)
		{
		if ( type->Tag() == TYPE_BOOL )
			return true;
		return false;
		}

	result_type operator()(uint64_t a)
		{
		if ( type->Tag() == TYPE_COUNT )
			return true;
		return false;
		}

	result_type operator()(int64_t a)
		{
		if ( type->Tag() == TYPE_INT )
			return true;
		return false;
		}

	result_type operator()(double a)
		{
		if ( type->Tag() == TYPE_DOUBLE )
			return true;
		return false;
		}

	result_type operator()(const std::string& a)
		{
		switch ( type->Tag() )
			{
			case TYPE_STRING:
				return true;
			case TYPE_FILE:
				return true;
			default:
				return false;
			}
		}

	result_type operator()(const broker::address& a)
		{
		if ( type->Tag() == TYPE_ADDR )
			return true;

		return false;
		}

	result_type operator()(const broker::subnet& a)
		{
		if ( type->Tag() == TYPE_SUBNET )
			return true;

		return false;
		}

	result_type operator()(const broker::port& a)
		{
		if ( type->Tag() == TYPE_PORT )
			return true;

		return false;
		}

	result_type operator()(const broker::timestamp& a)
		{
		if ( type->Tag() == TYPE_TIME )
			return true;

		return false;
		}

	result_type operator()(const broker::timespan& a)
		{
		if ( type->Tag() == TYPE_INTERVAL )
			return true;

		return false;
		}

	result_type operator()(const broker::enum_value& a)
		{
		if ( type->Tag() == TYPE_ENUM )
			{
			auto etype = type->AsEnumType();
			auto i = etype->Lookup(zeek::detail::GLOBAL_MODULE_NAME, a.name.data());
			return i != -1;
			}

		return false;
		}

	result_type operator()(const broker::set& a)
		{
		if ( ! type->IsSet() )
			return false;

		auto tt = type->AsTableType();

		for ( const auto& item : a )
			{
			const auto& expected_index_types = tt->GetIndices()->GetTypes();
			auto indices = get_if<broker::vector>(&item);
			vector<const broker::data*> indices_to_check;

			if ( indices )
				{
				if ( expected_index_types.size() == 1 )
					{
					auto disambiguate = serialized_as_vector(expected_index_types[0]->Tag());

					if ( disambiguate )
						// Disambiguate from composite key w/ multiple vals.
						indices_to_check.emplace_back(&item);
					else
						{
						indices_to_check.reserve(indices->size());

						for ( size_t i = 0; i < indices->size(); ++i )
							indices_to_check.emplace_back(&(*indices)[i]);
						}
					}
				else
					{
					indices_to_check.reserve(indices->size());

					for ( size_t i = 0; i < indices->size(); ++i )
						indices_to_check.emplace_back(&(*indices)[i]);
					}
				}
			else
				indices_to_check.emplace_back(&item);

			if ( expected_index_types.size() != indices_to_check.size() )
				return false;

			for ( size_t i = 0; i < indices_to_check.size(); ++i )
				{
				auto expect = expected_index_types[i].get();
				auto& index_to_check = *(indices_to_check)[i];

				if ( ! data_type_check(index_to_check, expect) )
					return false;
				}
			}

		return true;
		}

	result_type operator()(const broker::table& a)
		{
		if ( ! type->IsTable() )
			return false;

		auto tt = type->AsTableType();

		for ( auto& item : a )
			{
			const auto& expected_index_types = tt->GetIndices()->GetTypes();
			auto indices = get_if<broker::vector>(&item.first);
			vector<const broker::data*> indices_to_check;

			if ( indices )
				{
				if ( expected_index_types.size() == 1 )
					{
					auto disambiguate = serialized_as_vector(expected_index_types[0]->Tag());

					if ( disambiguate )
						// Disambiguate from composite key w/ multiple vals.
						indices_to_check.emplace_back(&item.first);
					else
						{
						indices_to_check.reserve(indices->size());

						for ( size_t i = 0; i < indices->size(); ++i )
							indices_to_check.emplace_back(&(*indices)[i]);
						}
					}
				else
					{
					indices_to_check.reserve(indices->size());

					for ( size_t i = 0; i < indices->size(); ++i )
						indices_to_check.emplace_back(&(*indices)[i]);
					}
				}
			else
				indices_to_check.emplace_back(&item.first);

			if ( expected_index_types.size() != indices_to_check.size() )
				{
				return false;
				}

			for ( size_t i = 0; i < indices_to_check.size(); ++i )
				{
				auto expect = expected_index_types[i].get();
				auto& index_to_check = *(indices_to_check)[i];

				if ( ! data_type_check(index_to_check, expect) )
					return false;
				}

			if ( ! data_type_check(item.second, tt->Yield().get()) )
				return false;
			}

		return true;
		}

	result_type operator()(const broker::vector& a)
		{
		if ( type->Tag() == TYPE_VECTOR )
			{
			auto vt = type->AsVectorType();

			for ( auto& item : a )
				{
				if ( ! data_type_check(item, vt->Yield().get()) )
					return false;
				}

			return true;
			}
		else if ( type->Tag() == TYPE_FUNC )
			{
			if ( a.size() < 1 || a.size() > 2 )
				return false;

			auto name = broker::get_if<std::string>(a[0]);
			if ( ! name )
				return false;

			const auto& id = zeek::detail::global_scope()->Find(*name);
			if ( ! id )
				return false;

			const auto& rval = id->GetVal();
			if ( ! rval )
				return false;

			const auto& t = rval->GetType();
			if ( ! t )
				return false;

			if ( t->Tag() != TYPE_FUNC )
				return false;

			return true;
			}
		else if ( type->Tag() == TYPE_RECORD )
			{
			auto rt = type->AsRecordType();
			auto idx = 0u;

			for ( size_t i = 0; i < static_cast<size_t>(rt->NumFields()); ++i )
				{
				if ( idx >= a.size() )
					return false;

				if ( get_if<broker::none>(&a[idx]) != nullptr )
					{
					++idx;
					continue;
					}

				if ( ! data_type_check(a[idx], rt->GetFieldType(i).get()) )
					return false;

				++idx;
				}

			return true;
			}
		else if ( type->Tag() == TYPE_PATTERN )
			{
			if ( a.size() != 2 )
				return false;

			auto exact_text = get_if<std::string>(&a[0]);
			auto anywhere_text = get_if<std::string>(&a[1]);

			if ( ! exact_text || ! anywhere_text )
				return false;

			auto* re = new RE_Matcher(exact_text->c_str(), anywhere_text->c_str());
			auto compiled = re->Compile();
			delete re;

			if ( ! compiled )
				{
				reporter->Error("failed compiling pattern: %s, %s", exact_text->c_str(),
				                anywhere_text->c_str());
				return false;
				}

			return true;
			}
		else if ( type->Tag() == TYPE_OPAQUE )
			{
			// TODO: Could avoid doing the full unserialization here
			// and just check if the type is a correct match.
			auto ov = OpaqueVal::Unserialize(a);
			return ov != nullptr;
			}

		return false;
		}
	};

static bool data_type_check(const broker::data& d, Type* t)
	{
	if ( t->Tag() == TYPE_ANY )
		return true;

	return visit(type_checker{t}, d);
	}

ValPtr data_to_val(broker::data d, Type* type)
	{
	if ( type->Tag() == TYPE_ANY )
		return make_data_val(move(d));

	return visit(val_converter{type}, d);
	}

broker::expected<broker::data> val_to_data(const Val* v)
	{
	switch ( v->GetType()->Tag() )
		{
		case TYPE_BOOL:
			return {v->AsBool()};
		case TYPE_INT:
			return {v->AsInt()};
		case TYPE_COUNT:
			return {v->AsCount()};
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
			return {broker::subnet(std::move(a), s.Length())};
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
			auto enum_type = v->GetType()->AsEnumType();
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
			{
			const Func* f = v->AsFunc();
			std::string name(f->Name());

			broker::vector rval;
			rval.push_back(name);

			if ( name.find("lambda_<") == 0 )
				{
				// Only ScriptFuncs have closures.
				if ( auto b = dynamic_cast<const zeek::detail::ScriptFunc*>(f) )
					{
					auto bc = b->SerializeCaptures();
					if ( ! bc )
						return broker::ec::invalid_data;

					rval.emplace_back(std::move(*bc));
					}
				else
					{
					reporter->InternalWarning("Closure with non-ScriptFunc");
					return broker::ec::invalid_data;
					}
				}

			return {std::move(rval)};
			}
		case TYPE_TABLE:
			{
			auto is_set = v->GetType()->IsSet();
			auto table = v->AsTable();
			auto table_val = v->AsTableVal();
			broker::data rval;

			if ( is_set )
				rval = broker::set();
			else
				rval = broker::table();

			for ( const auto& te : *table )
				{
				auto hk = te.GetHashKey();
				auto vl = table_val->RecreateIndex(*hk);

				broker::vector composite_key;
				composite_key.reserve(vl->Length());

				for ( auto k = 0; k < vl->Length(); ++k )
					{
					auto key_part = val_to_data(vl->Idx(k).get());

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
					get<broker::set>(rval).emplace(move(key));
				else
					{
					auto val = val_to_data(te.value->GetVal().get());

					if ( ! val )
						return broker::ec::invalid_data;

					get<broker::table>(rval).emplace(move(key), move(*val));
					}
				}

			return {std::move(rval)};
			}
		case TYPE_VECTOR:
			{
			auto vec = v->AsVectorVal();
			broker::vector rval;
			rval.reserve(vec->Size());

			for ( auto i = 0u; i < vec->Size(); ++i )
				{
				auto item_val = vec->ValAt(i);

				if ( ! item_val )
					continue;

				auto item = val_to_data(item_val.get());

				if ( ! item )
					return broker::ec::invalid_data;

				rval.emplace_back(move(*item));
				}

			return {std::move(rval)};
			}
		case TYPE_LIST:
			{
			// We don't really support lists on the broker side.
			// So we just pretend that it is a vector instead.
			auto list = v->AsListVal();
			broker::vector rval;
			rval.reserve(list->Length());

			for ( auto i = 0; i < list->Length(); ++i )
				{
				const auto& item_val = list->Idx(i);

				if ( ! item_val )
					continue;

				auto item = val_to_data(item_val.get());

				if ( ! item )
					return broker::ec::invalid_data;

				rval.emplace_back(move(*item));
				}

			return {std::move(rval)};
			}
		case TYPE_RECORD:
			{
			auto rec = v->AsRecordVal();
			broker::vector rval;
			size_t num_fields = v->GetType()->AsRecordType()->NumFields();
			rval.reserve(num_fields);

			for ( size_t i = 0; i < num_fields; ++i )
				{
				auto item_val = rec->GetFieldOrDefault(i);

				if ( ! item_val )
					{
					rval.emplace_back(broker::nil);
					continue;
					}

				auto item = val_to_data(item_val.get());

				if ( ! item )
					return broker::ec::invalid_data;

				rval.emplace_back(move(*item));
				}

			return {std::move(rval)};
			}
		case TYPE_PATTERN:
			{
			const RE_Matcher* p = v->AsPattern();
			broker::vector rval = {p->PatternText(), p->AnywherePatternText()};
			return {std::move(rval)};
			}
		case TYPE_OPAQUE:
			{
			auto c = v->AsOpaqueVal()->Serialize();
			if ( ! c )
				{
				reporter->Error("unsupported opaque type for serialization");
				break;
				}

			return {c};
			}
		default:
			reporter->Error("unsupported Broker::Data type: %s", type_name(v->GetType()->Tag()));
			break;
		}

	return broker::ec::invalid_data;
	}

RecordValPtr make_data_val(Val* v)
	{
	auto rval = make_intrusive<RecordVal>(BifType::Record::Broker::Data);
	auto data = val_to_data(v);

	if ( data )
		rval->Assign(0, make_intrusive<DataVal>(move(*data)));
	else
		reporter->Warning("did not get a value from val_to_data");

	return rval;
	}

RecordValPtr make_data_val(broker::data d)
	{
	auto rval = make_intrusive<RecordVal>(BifType::Record::Broker::Data);
	rval->Assign(0, make_intrusive<DataVal>(move(d)));
	return rval;
	}

struct data_type_getter
	{
	using result_type = EnumValPtr;

	result_type operator()(broker::none)
		{
		return BifType::Enum::Broker::DataType->GetEnumVal(BifEnum::Broker::NONE);
		}

	result_type operator()(bool)
		{
		return BifType::Enum::Broker::DataType->GetEnumVal(BifEnum::Broker::BOOL);
		}

	result_type operator()(uint64_t)
		{
		return BifType::Enum::Broker::DataType->GetEnumVal(BifEnum::Broker::COUNT);
		}

	result_type operator()(int64_t)
		{
		return BifType::Enum::Broker::DataType->GetEnumVal(BifEnum::Broker::INT);
		}

	result_type operator()(double)
		{
		return BifType::Enum::Broker::DataType->GetEnumVal(BifEnum::Broker::DOUBLE);
		}

	result_type operator()(const std::string&)
		{
		return BifType::Enum::Broker::DataType->GetEnumVal(BifEnum::Broker::STRING);
		}

	result_type operator()(const broker::address&)
		{
		return BifType::Enum::Broker::DataType->GetEnumVal(BifEnum::Broker::ADDR);
		}

	result_type operator()(const broker::subnet&)
		{
		return BifType::Enum::Broker::DataType->GetEnumVal(BifEnum::Broker::SUBNET);
		}

	result_type operator()(const broker::port&)
		{
		return BifType::Enum::Broker::DataType->GetEnumVal(BifEnum::Broker::PORT);
		}

	result_type operator()(const broker::timestamp&)
		{
		return BifType::Enum::Broker::DataType->GetEnumVal(BifEnum::Broker::TIME);
		}

	result_type operator()(const broker::timespan&)
		{
		return BifType::Enum::Broker::DataType->GetEnumVal(BifEnum::Broker::INTERVAL);
		}

	result_type operator()(const broker::enum_value&)
		{
		return BifType::Enum::Broker::DataType->GetEnumVal(BifEnum::Broker::ENUM);
		}

	result_type operator()(const broker::set&)
		{
		return BifType::Enum::Broker::DataType->GetEnumVal(BifEnum::Broker::SET);
		}

	result_type operator()(const broker::table&)
		{
		return BifType::Enum::Broker::DataType->GetEnumVal(BifEnum::Broker::TABLE);
		}

	result_type operator()(const broker::vector&)
		{
		// Note that Broker uses vectors to store record data, so there's
		// no actual way to tell if this data was originally associated
		// with a Zeek record.
		return BifType::Enum::Broker::DataType->GetEnumVal(BifEnum::Broker::VECTOR);
		}
	};

EnumValPtr get_data_type(RecordVal* v, zeek::detail::Frame* frame)
	{
	return visit(data_type_getter{}, opaque_field_to_data(v, frame));
	}

broker::data& opaque_field_to_data(RecordVal* v, zeek::detail::Frame* f)
	{
	const auto& d = v->GetField(0);

	if ( ! d )
		reporter->RuntimeError(f->GetCallLocation(), "Broker::Data's opaque field is not set");

	// RuntimeError throws an exception which causes this line to never execute.
	// NOLINTNEXTLINE(clang-analyzer-core.uninitialized.UndefReturn)
	return static_cast<DataVal*>(d.get())->data;
	}

void DataVal::ValDescribe(ODesc* d) const
	{
	d->Add("broker::data{");
	d->Add(broker::to_string(data));
	d->Add("}");
	}

bool DataVal::canCastTo(zeek::Type* t) const
	{
	return data_type_check(data, t);
	}

ValPtr DataVal::castTo(zeek::Type* t)
	{
	return data_to_val(data, t);
	}

const TypePtr& DataVal::ScriptDataType()
	{
	static auto script_data_type = id::find_type("Broker::Data");
	return script_data_type;
	}

IMPLEMENT_OPAQUE_VALUE(zeek::Broker::detail::DataVal)

broker::expected<broker::data> DataVal::DoSerialize() const
	{
	return data;
	}

bool DataVal::DoUnserialize(const broker::data& data_)
	{
	data = data_;
	return true;
	}

IMPLEMENT_OPAQUE_VALUE(zeek::Broker::detail::SetIterator)

broker::expected<broker::data> SetIterator::DoSerialize() const
	{
	return broker::vector{dat, *it};
	}

bool SetIterator::DoUnserialize(const broker::data& data)
	{
	auto v = get_if<broker::vector>(&data);
	if ( ! (v && v->size() == 2) )
		return false;

	auto x = get_if<broker::set>(&(*v)[0]);

	// We set the iterator by finding the element it used to point to.
	// This is not perfect, as there's no guarantee that the restored
	// container will list the elements in the same order. But it's as
	// good as we can do, and it should generally work out.
	if ( x->find((*v)[1]) == x->end() )
		return false;

	dat = *x;
	it = dat.find((*v)[1]);
	return true;
	}

IMPLEMENT_OPAQUE_VALUE(zeek::Broker::detail::TableIterator)

broker::expected<broker::data> TableIterator::DoSerialize() const
	{
	return broker::vector{dat, it->first};
	}

bool TableIterator::DoUnserialize(const broker::data& data)
	{
	auto v = get_if<broker::vector>(&data);
	if ( ! (v && v->size() == 2) )
		return false;

	auto x = get_if<broker::table>(&(*v)[0]);

	// We set the iterator by finding the element it used to point to.
	// This is not perfect, as there's no guarantee that the restored
	// container will list the elements in the same order. But it's as
	// good as we can do, and it should generally work out.
	if ( x->find((*v)[1]) == x->end() )
		return false;

	dat = *x;
	it = dat.find((*v)[1]);
	return true;
	}

IMPLEMENT_OPAQUE_VALUE(zeek::Broker::detail::VectorIterator)

broker::expected<broker::data> VectorIterator::DoSerialize() const
	{
	broker::integer difference = it - dat.begin();
	return broker::vector{dat, difference};
	}

bool VectorIterator::DoUnserialize(const broker::data& data)
	{
	auto v = get_if<broker::vector>(&data);
	if ( ! (v && v->size() == 2) )
		return false;

	auto x = get_if<broker::vector>(&(*v)[0]);
	auto y = get_if<broker::integer>(&(*v)[1]);

	if ( ! (x && y) )
		return false;

	dat = *x;
	it = dat.begin() + *y;
	return true;
	}

IMPLEMENT_OPAQUE_VALUE(zeek::Broker::detail::RecordIterator)

broker::expected<broker::data> RecordIterator::DoSerialize() const
	{
	broker::integer difference = it - dat.begin();
	return broker::vector{dat, difference};
	}

bool RecordIterator::DoUnserialize(const broker::data& data)
	{
	auto v = get_if<broker::vector>(&data);
	if ( ! (v && v->size() == 2) )
		return false;

	auto x = get_if<broker::vector>(&(*v)[0]);
	auto y = get_if<broker::integer>(&(*v)[1]);

	if ( ! (x && y) )
		return false;

	dat = *x;
	it = dat.begin() + *y;
	return true;
	}

broker::data threading_field_to_data(const threading::Field* f)
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

threading::Field* data_to_threading_field(broker::data d)
	{
	if ( ! holds_alternative<broker::vector>(d) )
		return nullptr;

	auto& v = get<broker::vector>(d);
	auto name = get_if<std::string>(&v[0]);
	auto secondary = v[1];
	auto type = get_if<broker::count>(&v[2]);
	auto subtype = get_if<broker::count>(&v[3]);
	auto optional = get_if<broker::boolean>(&v[4]);

	if ( ! (name && type && subtype && optional) )
		return nullptr;

	if ( secondary != broker::nil && ! holds_alternative<std::string>(secondary) )
		return nullptr;

	return new threading::Field(
		name->c_str(), secondary != broker::nil ? get<std::string>(secondary).c_str() : nullptr,
		static_cast<TypeTag>(*type), static_cast<TypeTag>(*subtype), *optional);
	}

	} // namespace zeek::Broker::detail
