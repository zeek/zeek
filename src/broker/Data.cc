#include <broker/error.hh>
#include "broker/data.bif.h"
#include "3rdparty/doctest.h"

#include "Data.h"
#include "File.h"
#include "Desc.h"
#include "IntrusivePtr.h"
#include "RE.h"
#include "ID.h"
#include "Scope.h"
#include "Func.h"
#include "module_util.h"

using namespace std;

zeek::OpaqueTypePtr zeek::Broker::detail::opaque_of_data_type;
zeek::OpaqueTypePtr& bro_broker::opaque_of_data_type = zeek::Broker::detail::opaque_of_data_type;
zeek::OpaqueTypePtr zeek::Broker::detail::opaque_of_set_iterator;
zeek::OpaqueTypePtr& bro_broker::opaque_of_set_iterator = zeek::Broker::detail::opaque_of_set_iterator;
zeek::OpaqueTypePtr zeek::Broker::detail::opaque_of_table_iterator;
zeek::OpaqueTypePtr& bro_broker::opaque_of_table_iterator = zeek::Broker::detail::opaque_of_table_iterator;
zeek::OpaqueTypePtr zeek::Broker::detail::opaque_of_vector_iterator;
zeek::OpaqueTypePtr& bro_broker::opaque_of_vector_iterator = zeek::Broker::detail::opaque_of_vector_iterator;
zeek::OpaqueTypePtr zeek::Broker::detail::opaque_of_record_iterator;
zeek::OpaqueTypePtr& bro_broker::opaque_of_record_iterator = zeek::Broker::detail::opaque_of_record_iterator;

static bool data_type_check(const broker::data& d, zeek::Type* t);

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

TEST_CASE("converting Zeek to Broker protocol constants")
	{
	CHECK_EQ(to_broker_port_proto(TRANSPORT_TCP), broker::port::protocol::tcp);
	CHECK_EQ(to_broker_port_proto(TRANSPORT_UDP), broker::port::protocol::udp);
	CHECK_EQ(to_broker_port_proto(TRANSPORT_ICMP),
	         broker::port::protocol::icmp);
	CHECK_EQ(to_broker_port_proto(TRANSPORT_UNKNOWN),
	         broker::port::protocol::unknown);
	}

TransportProto zeek::Broker::detail::to_zeek_port_proto(broker::port::protocol tp)
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

TEST_CASE("converting Broker to Zeek protocol constants")
	{
	using zeek::Broker::detail::to_zeek_port_proto;
	CHECK_EQ(to_zeek_port_proto(broker::port::protocol::tcp), TRANSPORT_TCP);
	CHECK_EQ(to_zeek_port_proto(broker::port::protocol::udp), TRANSPORT_UDP);
	CHECK_EQ(to_zeek_port_proto(broker::port::protocol::icmp), TRANSPORT_ICMP);
	CHECK_EQ(to_zeek_port_proto(broker::port::protocol::unknown),
	         TRANSPORT_UNKNOWN);
	}

struct val_converter {
	using result_type = zeek::ValPtr;

	zeek::Type* type;

	result_type operator()(broker::none)
		{
		return nullptr;
		}

	result_type operator()(bool a)
		{
		if ( type->Tag() == zeek::TYPE_BOOL )
			return zeek::val_mgr->Bool(a);
		return nullptr;
		}

	result_type operator()(uint64_t a)
		{
		if ( type->Tag() == zeek::TYPE_COUNT )
			return zeek::val_mgr->Count(a);
		return nullptr;
		}

	result_type operator()(int64_t a)
		{
		if ( type->Tag() == zeek::TYPE_INT )
			return zeek::val_mgr->Int(a);
		return nullptr;
		}

	result_type operator()(double a)
		{
		if ( type->Tag() == zeek::TYPE_DOUBLE )
			return zeek::make_intrusive<zeek::DoubleVal>(a);
		return nullptr;
		}

	result_type operator()(std::string& a)
		{
		switch ( type->Tag() ) {
		case zeek::TYPE_STRING:
			return zeek::make_intrusive<zeek::StringVal>(a.size(), a.data());
		case zeek::TYPE_FILE:
			{
			auto file = zeek::File::Get(a.data());

			if ( file )
				return zeek::make_intrusive<zeek::Val>(std::move(file));

			return nullptr;
			}
		default:
			return nullptr;
		}
		}

	result_type operator()(broker::address& a)
		{
		if ( type->Tag() == zeek::TYPE_ADDR )
			{
			auto bits = reinterpret_cast<const in6_addr*>(&a.bytes());
			return zeek::make_intrusive<zeek::AddrVal>(zeek::IPAddr(*bits));
			}

		return nullptr;
		}

	result_type operator()(broker::subnet& a)
		{
		if ( type->Tag() == zeek::TYPE_SUBNET )
			{
			auto bits = reinterpret_cast<const in6_addr*>(&a.network().bytes());
			return zeek::make_intrusive<zeek::SubNetVal>(zeek::IPPrefix(zeek::IPAddr(*bits), a.length()));
			}

		return nullptr;
		}

	result_type operator()(broker::port& a)
		{
		if ( type->Tag() == zeek::TYPE_PORT )
			return zeek::val_mgr->Port(a.number(), zeek::Broker::detail::to_zeek_port_proto(a.type()));

		return nullptr;
		}

	result_type operator()(broker::timestamp& a)
		{
		if ( type->Tag() != zeek::TYPE_TIME )
			return nullptr;

		using namespace std::chrono;
		auto s = duration_cast<broker::fractional_seconds>(a.time_since_epoch());
		return zeek::make_intrusive<zeek::TimeVal>(s.count());
		}

	result_type operator()(broker::timespan& a)
		{
		if ( type->Tag() != zeek::TYPE_INTERVAL )
			return nullptr;

		using namespace std::chrono;
		auto s = duration_cast<broker::fractional_seconds>(a);
		return zeek::make_intrusive<zeek::IntervalVal>(s.count());
		}

	result_type operator()(broker::enum_value& a)
		{
		if ( type->Tag() == zeek::TYPE_ENUM )
			{
			auto etype = type->AsEnumType();
			auto i = etype->Lookup(GLOBAL_MODULE_NAME, a.name.data());

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
		auto rval = zeek::make_intrusive<zeek::TableVal>(zeek::IntrusivePtr{zeek::NewRef{}, tt});

		for ( auto& item : a )
			{
			const auto& expected_index_types = tt->GetIndices()->GetTypes();
			broker::vector composite_key;
			auto indices = caf::get_if<broker::vector>(&item);

			if ( indices )
				{
				if ( expected_index_types.size() == 1 )
					{
					auto index_is_vector_or_record =
					     expected_index_types[0]->Tag() == zeek::TYPE_RECORD ||
					     expected_index_types[0]->Tag() == zeek::TYPE_VECTOR;

					if ( index_is_vector_or_record )
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

			auto list_val = zeek::make_intrusive<zeek::ListVal>(zeek::TYPE_ANY);

			for ( size_t i = 0; i < indices->size(); ++i )
				{
				auto index_val = zeek::Broker::detail::data_to_val(move((*indices)[i]),
				                                           expected_index_types[i].get());

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
		auto rval = zeek::make_intrusive<zeek::TableVal>(zeek::IntrusivePtr{zeek::NewRef{}, tt});

		for ( auto& item : a )
			{
			const auto& expected_index_types = tt->GetIndices()->GetTypes();
			broker::vector composite_key;
			auto indices = caf::get_if<broker::vector>(&item.first);

			if ( indices )
				{
				if ( expected_index_types.size() == 1 )
					{
					auto index_is_vector_or_record =
					     expected_index_types[0]->Tag() == zeek::TYPE_RECORD ||
					     expected_index_types[0]->Tag() == zeek::TYPE_VECTOR;

					if ( index_is_vector_or_record )
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

			auto list_val = zeek::make_intrusive<zeek::ListVal>(zeek::TYPE_ANY);

			for ( size_t i = 0; i < indices->size(); ++i )
				{
				auto index_val = zeek::Broker::detail::data_to_val(move((*indices)[i]),
				                                           expected_index_types[i].get());

				if ( ! index_val )
					return nullptr;

				list_val->Append(std::move(index_val));
				}

			auto value_val = zeek::Broker::detail::data_to_val(move(item.second),
			                                           tt->Yield().get());

			if ( ! value_val )
				return nullptr;

			rval->Assign(std::move(list_val), std::move(value_val));
			}

		return rval;
		}

	result_type operator()(broker::vector& a)
		{
		if ( type->Tag() == zeek::TYPE_VECTOR )
			{
			auto vt = type->AsVectorType();
			auto rval = zeek::make_intrusive<zeek::VectorVal>(zeek::IntrusivePtr{zeek::NewRef{}, vt});

			for ( auto& item : a )
				{
				auto item_val = zeek::Broker::detail::data_to_val(move(item), vt->Yield().get());

				if ( ! item_val )
					return nullptr;

				rval->Assign(rval->Size(), std::move(item_val));
				}

			return rval;
			}
		else if ( type->Tag() == zeek::TYPE_FUNC )
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

			if ( t->Tag() != zeek::TYPE_FUNC )
				return nullptr;

			if ( a.size() == 2 ) // We have a closure.
				{
				auto frame = broker::get_if<broker::vector>(a[1]);
				if ( ! frame )
					return nullptr;

				auto* b = dynamic_cast<zeek::detail::ScriptFunc*>(rval->AsFunc());
				if ( ! b )
					return nullptr;

				if ( ! b->UpdateClosure(*frame) )
					return nullptr;
				}

			return rval;
			}
		else if ( type->Tag() == zeek::TYPE_RECORD )
			{
			auto rt = type->AsRecordType();
			auto rval = zeek::make_intrusive<zeek::RecordVal>(zeek::IntrusivePtr{zeek::NewRef{}, rt});
			auto idx = 0u;

			for ( size_t i = 0; i < static_cast<size_t>(rt->NumFields()); ++i )
				{
				if ( idx >= a.size() )
					return nullptr;

				if ( caf::get_if<broker::none>(&a[idx]) != nullptr )
					{
					rval->Assign(i, nullptr);
					++idx;
					continue;
					}

				auto item_val = zeek::Broker::detail::data_to_val(move(a[idx]),
				                                          rt->GetFieldType(i).get());

				if ( ! item_val )
					return nullptr;

				rval->Assign(i, std::move(item_val));
				++idx;
				}

			return rval;
			}
		else if ( type->Tag() == zeek::TYPE_PATTERN )
			{
			if ( a.size() != 2 )
				return nullptr;

			auto exact_text = caf::get_if<std::string>(&a[0]);
			auto anywhere_text = caf::get_if<std::string>(&a[1]);

			if ( ! exact_text || ! anywhere_text )
				return nullptr;

			auto* re = new zeek::RE_Matcher(exact_text->c_str(),
			                                anywhere_text->c_str());

			if ( ! re->Compile() )
				{
				zeek::reporter->Error("failed compiling unserialized pattern: %s, %s",
				                      exact_text->c_str(), anywhere_text->c_str());
				delete re;
				return nullptr;
				}

			auto rval = zeek::make_intrusive<zeek::PatternVal>(re);
			return rval;
			}
		else if ( type->Tag() == zeek::TYPE_OPAQUE )
			return zeek::OpaqueVal::Unserialize(a);

		return nullptr;
		}
};

struct type_checker {
	using result_type = bool;

	zeek::Type* type;

	result_type operator()(broker::none)
		{
		return false;
		}

	result_type operator()(bool a)
		{
		if ( type->Tag() == zeek::TYPE_BOOL )
			return true;
		return false;
		}

	result_type operator()(uint64_t a)
		{
		if ( type->Tag() == zeek::TYPE_COUNT )
			return true;
		return false;
		}

	result_type operator()(int64_t a)
		{
		if ( type->Tag() == zeek::TYPE_INT )
			return true;
		return false;
		}

	result_type operator()(double a)
		{
		if ( type->Tag() == zeek::TYPE_DOUBLE )
			return true;
		return false;
		}

	result_type operator()(const std::string& a)
		{
		switch ( type->Tag() ) {
		case zeek::TYPE_STRING:
			return true;
		case zeek::TYPE_FILE:
			return true;
		default:
			return false;
		}
		}

	result_type operator()(const broker::address& a)
		{
		if ( type->Tag() == zeek::TYPE_ADDR )
			return true;

		return false;
		}

	result_type operator()(const broker::subnet& a)
		{
		if ( type->Tag() == zeek::TYPE_SUBNET )
			return true;

		return false;
		}

	result_type operator()(const broker::port& a)
		{
		if ( type->Tag() == zeek::TYPE_PORT )
			return true;

		return false;
		}

	result_type operator()(const broker::timestamp& a)
		{
		if ( type->Tag() == zeek::TYPE_TIME )
			return true;

		return false;
		}

	result_type operator()(const broker::timespan& a)
		{
		if ( type->Tag() == zeek::TYPE_INTERVAL )
			return true;

		return false;
		}

	result_type operator()(const broker::enum_value& a)
		{
		if ( type->Tag() == zeek::TYPE_ENUM )
			{
			auto etype = type->AsEnumType();
			auto i = etype->Lookup(GLOBAL_MODULE_NAME, a.name.data());
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
			auto indices = caf::get_if<broker::vector>(&item);
			vector<const broker::data*> indices_to_check;

			if ( indices )
				{
				if ( expected_index_types.size() == 1 )
					{
					auto index_is_vector_or_record =
					     expected_index_types[0]->Tag() == zeek::TYPE_RECORD ||
					     expected_index_types[0]->Tag() == zeek::TYPE_VECTOR;

					if ( index_is_vector_or_record )
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
			auto indices = caf::get_if<broker::vector>(&item.first);
			vector<const broker::data*> indices_to_check;

			if ( indices )
				{
				if ( expected_index_types.size() == 1 )
					{
					auto index_is_vector_or_record =
					     expected_index_types[0]->Tag() == zeek::TYPE_RECORD ||
					     expected_index_types[0]->Tag() == zeek::TYPE_VECTOR;

					if ( index_is_vector_or_record )
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
		if ( type->Tag() == zeek::TYPE_VECTOR )
			{
			auto vt = type->AsVectorType();

			for ( auto& item : a )
				{
				if ( ! data_type_check(item, vt->Yield().get()) )
					return false;
				}

			return true;
			}
		else if ( type->Tag() == zeek::TYPE_FUNC )
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

			if ( t->Tag() != zeek::TYPE_FUNC )
				return false;

			return true;
			}
		else if ( type->Tag() == zeek::TYPE_RECORD )
			{
			auto rt = type->AsRecordType();
			auto idx = 0u;

			for ( size_t i = 0; i < static_cast<size_t>(rt->NumFields()); ++i )
				{
				if ( idx >= a.size() )
					return false;

				if ( caf::get_if<broker::none>(&a[idx]) != nullptr )
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
		else if ( type->Tag() == zeek::TYPE_PATTERN )
			{
			if ( a.size() != 2 )
				return false;

			auto exact_text = caf::get_if<std::string>(&a[0]);
			auto anywhere_text = caf::get_if<std::string>(&a[1]);

			if ( ! exact_text || ! anywhere_text )
				return false;

			auto* re = new zeek::RE_Matcher(exact_text->c_str(),
			                                anywhere_text->c_str());
			auto compiled = re->Compile();
			delete re;

			if ( ! compiled )
				{
				zeek::reporter->Error("failed compiling pattern: %s, %s",
				                      exact_text->c_str(), anywhere_text->c_str());
				return false;
				}

			return true;
			}
		else if ( type->Tag() == zeek::TYPE_OPAQUE )
			{
			// TODO: Could avoid doing the full unserialization here
			// and just check if the type is a correct match.
			auto ov = zeek::OpaqueVal::Unserialize(a);
			return ov != nullptr;
			}

		return false;
		}
};

static bool data_type_check(const broker::data& d, zeek::Type* t)
	{
	if ( t->Tag() == zeek::TYPE_ANY )
		return true;

	return caf::visit(type_checker{t}, d);
	}

zeek::ValPtr zeek::Broker::detail::data_to_val(broker::data d, zeek::Type* type)
	{
	if ( type->Tag() == zeek::TYPE_ANY )
		return zeek::Broker::detail::make_data_val(move(d));

	return caf::visit(val_converter{type}, std::move(d));
	}

broker::expected<broker::data> zeek::Broker::detail::val_to_data(const zeek::Val* v)
	{
	switch ( v->GetType()->Tag() ) {
	case zeek::TYPE_BOOL:
		return {v->AsBool()};
	case zeek::TYPE_INT:
		return {v->AsInt()};
	case zeek::TYPE_COUNT:
		return {v->AsCount()};
	case zeek::TYPE_PORT:
		{
		auto p = v->AsPortVal();
		return {broker::port(p->Port(), to_broker_port_proto(p->PortType()))};
		}
	case zeek::TYPE_ADDR:
		{
		auto a = v->AsAddr();
		in6_addr tmp;
		a.CopyIPv6(&tmp);
		return {broker::address(reinterpret_cast<const uint32_t*>(&tmp),
			                    broker::address::family::ipv6,
			                    broker::address::byte_order::network)};
		}
		break;
	case zeek::TYPE_SUBNET:
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
	case zeek::TYPE_DOUBLE:
		return {v->AsDouble()};
	case zeek::TYPE_TIME:
		{
		auto secs = broker::fractional_seconds{v->AsTime()};
		auto since_epoch = std::chrono::duration_cast<broker::timespan>(secs);
		return {broker::timestamp{since_epoch}};
		}
	case zeek::TYPE_INTERVAL:
		{
		auto secs = broker::fractional_seconds{v->AsInterval()};
		return {std::chrono::duration_cast<broker::timespan>(secs)};
		}
	case zeek::TYPE_ENUM:
		{
		auto enum_type = v->GetType()->AsEnumType();
		auto enum_name = enum_type->Lookup(v->AsEnum());
		return {broker::enum_value(enum_name ? enum_name : "<unknown enum>")};
		}
	case zeek::TYPE_STRING:
		{
		auto s = v->AsString();
		return {string(reinterpret_cast<const char*>(s->Bytes()), s->Len())};
		}
	case zeek::TYPE_FILE:
		return {string(v->AsFile()->Name())};
	case zeek::TYPE_FUNC:
		{
		const zeek::Func* f = v->AsFunc();
		std::string name(f->Name());

		broker::vector rval;
		rval.push_back(name);

		if ( name.find("lambda_<") == 0 )
			{
			// Only ScriptFuncs have closures.
			if ( auto b = dynamic_cast<const zeek::detail::ScriptFunc*>(f) )
				{
				auto bc = b->SerializeClosure();
				if ( ! bc )
					return broker::ec::invalid_data;

				rval.emplace_back(std::move(*bc));
				}
			else
				{
				zeek::reporter->InternalWarning("Closure with non-ScriptFunc");
				return broker::ec::invalid_data;
				}
			}

		return {std::move(rval)};
		}
	case zeek::TYPE_TABLE:
		{
		auto is_set = v->GetType()->IsSet();
		auto table = v->AsTable();
		auto table_val = v->AsTableVal();
		broker::data rval;

		if ( is_set )
			rval = broker::set();
		else
			rval = broker::table();

		zeek::detail::HashKey* hk;
		zeek::TableEntryVal* entry;
		auto c = table->InitForIteration();

		while ( (entry = table->NextEntry(hk, c)) )
			{
			auto vl = table_val->RecreateIndex(*hk);
			delete hk;

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
				caf::get<broker::set>(rval).emplace(move(key));
			else
				{
				auto val = val_to_data(entry->GetVal().get());

				if ( ! val )
					return broker::ec::invalid_data;

				caf::get<broker::table>(rval).emplace(move(key), move(*val));
				}
			}

		return {std::move(rval)};
		}
	case zeek::TYPE_VECTOR:
		{
		auto vec = v->AsVectorVal();
		broker::vector rval;
		rval.reserve(vec->Size());

		for ( auto i = 0u; i < vec->Size(); ++i )
			{
			const auto& item_val = vec->At(i);

			if ( ! item_val )
				continue;

			auto item = val_to_data(item_val.get());

			if ( ! item )
				return broker::ec::invalid_data;

			rval.emplace_back(move(*item));
			}

		return {std::move(rval)};
		}
	case zeek::TYPE_RECORD:
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
	case zeek::TYPE_PATTERN:
		{
		const zeek::RE_Matcher* p = v->AsPattern();
		broker::vector rval = {p->PatternText(), p->AnywherePatternText()};
		return {std::move(rval)};
		}
	case zeek::TYPE_OPAQUE:
		{
		auto c = v->AsOpaqueVal()->Serialize();
		if ( ! c )
			{
			zeek::reporter->Error("unsupported opaque type for serialization");
			break;
			}

		return {c};
		}
	default:
		zeek::reporter->Error("unsupported Broker::Data type: %s",
		                      zeek::type_name(v->GetType()->Tag()));
		break;
	}

	return broker::ec::invalid_data;
	}

zeek::RecordValPtr zeek::Broker::detail::make_data_val(zeek::Val* v)
	{
	auto rval = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::Broker::Data);
	auto data = val_to_data(v);

	if  ( data )
		rval->Assign(0, zeek::make_intrusive<DataVal>(move(*data)));
	else
		zeek::reporter->Warning("did not get a value from val_to_data");

	return rval;
	}

zeek::RecordValPtr zeek::Broker::detail::make_data_val(broker::data d)
	{
	auto rval = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::Broker::Data);
	rval->Assign(0, zeek::make_intrusive<DataVal>(move(d)));
	return rval;
	}

struct data_type_getter {
	using result_type = zeek::EnumValPtr;

	result_type operator()(broker::none)
		{
		return zeek::BifType::Enum::Broker::DataType->GetEnumVal(BifEnum::Broker::NONE);
		}

	result_type operator()(bool)
		{
		return zeek::BifType::Enum::Broker::DataType->GetEnumVal(BifEnum::Broker::BOOL);
		}

	result_type operator()(uint64_t)
		{
		return zeek::BifType::Enum::Broker::DataType->GetEnumVal(BifEnum::Broker::COUNT);
		}

	result_type operator()(int64_t)
		{
		return zeek::BifType::Enum::Broker::DataType->GetEnumVal(BifEnum::Broker::INT);
		}

	result_type operator()(double)
		{
		return zeek::BifType::Enum::Broker::DataType->GetEnumVal(BifEnum::Broker::DOUBLE);
		}

	result_type operator()(const std::string&)
		{
		return zeek::BifType::Enum::Broker::DataType->GetEnumVal(BifEnum::Broker::STRING);
		}

	result_type operator()(const broker::address&)
		{
		return zeek::BifType::Enum::Broker::DataType->GetEnumVal(BifEnum::Broker::ADDR);
		}

	result_type operator()(const broker::subnet&)
		{
		return zeek::BifType::Enum::Broker::DataType->GetEnumVal(BifEnum::Broker::SUBNET);
		}

	result_type operator()(const broker::port&)
		{
		return zeek::BifType::Enum::Broker::DataType->GetEnumVal(BifEnum::Broker::PORT);
		}

	result_type operator()(const broker::timestamp&)
		{
		return zeek::BifType::Enum::Broker::DataType->GetEnumVal(BifEnum::Broker::TIME);
		}

	result_type operator()(const broker::timespan&)
		{
		return zeek::BifType::Enum::Broker::DataType->GetEnumVal(BifEnum::Broker::INTERVAL);
		}

	result_type operator()(const broker::enum_value&)
		{
		return zeek::BifType::Enum::Broker::DataType->GetEnumVal(BifEnum::Broker::ENUM);
		}

	result_type operator()(const broker::set&)
		{
		return zeek::BifType::Enum::Broker::DataType->GetEnumVal(BifEnum::Broker::SET);
		}

	result_type operator()(const broker::table&)
		{
		return zeek::BifType::Enum::Broker::DataType->GetEnumVal(BifEnum::Broker::TABLE);
		}

	result_type operator()(const broker::vector&)
		{
		// Note that Broker uses vectors to store record data, so there's
		// no actual way to tell if this data was originally associated
		// with a Bro record.
		return zeek::BifType::Enum::Broker::DataType->GetEnumVal(BifEnum::Broker::VECTOR);
		}
};

zeek::EnumValPtr zeek::Broker::detail::get_data_type(zeek::RecordVal* v, zeek::detail::Frame* frame)
	{
	return caf::visit(data_type_getter{}, opaque_field_to_data(v, frame));
	}

broker::data& zeek::Broker::detail::opaque_field_to_data(zeek::RecordVal* v, zeek::detail::Frame* f)
	{
	const auto& d = v->GetField(0);

	if ( ! d )
		zeek::reporter->RuntimeError(f->GetCall()->GetLocationInfo(),
		                             "Broker::Data's opaque field is not set");

	// RuntimeError throws an exception which causes this line to never exceute.
	// NOLINTNEXTLINE(clang-analyzer-core.uninitialized.UndefReturn)
	return static_cast<DataVal*>(d.get())->data;
	}

void zeek::Broker::detail::DataVal::ValDescribe(zeek::ODesc* d) const
	{
	d->Add("broker::data{");
	d->Add(broker::to_string(data));
	d->Add("}");
	}

bool zeek::Broker::detail::DataVal::canCastTo(zeek::Type* t) const
	{
	return data_type_check(data, t);
	}

zeek::ValPtr zeek::Broker::detail::DataVal::castTo(zeek::Type* t)
	{
	return data_to_val(data, t);
	}

const zeek::TypePtr& zeek::Broker::detail::DataVal::ScriptDataType()
	{
	static auto script_data_type = zeek::id::find_type("Broker::Data");
	return script_data_type;
	}

IMPLEMENT_OPAQUE_VALUE(zeek::Broker::detail::DataVal)

broker::expected<broker::data> zeek::Broker::detail::DataVal::DoSerialize() const
	{
	return data;
	}

bool zeek::Broker::detail::DataVal::DoUnserialize(const broker::data& data_)
	{
	data = data_;
	return true;
	}

IMPLEMENT_OPAQUE_VALUE(zeek::Broker::detail::SetIterator)

broker::expected<broker::data> zeek::Broker::detail::SetIterator::DoSerialize() const
	{
	return broker::vector{dat, *it};
	}

bool zeek::Broker::detail::SetIterator::DoUnserialize(const broker::data& data)
	{
	auto v = caf::get_if<broker::vector>(&data);
	if ( ! (v && v->size() == 2) )
		return false;

	auto x = caf::get_if<broker::set>(&(*v)[0]);

	// We set the iterator by finding the element it used to point to.
	// This is not perfect, as there's no guarantee that the restored
	// container will list the elements in the same order. But it's as
	// good as we can do, and it should generally work out.
	if( x->find((*v)[1]) == x->end() )
		return false;

	dat = *x;
	it = dat.find((*v)[1]);
	return true;
	}

IMPLEMENT_OPAQUE_VALUE(zeek::Broker::detail::TableIterator)

broker::expected<broker::data> zeek::Broker::detail::TableIterator::DoSerialize() const
	{
	return broker::vector{dat, it->first};
	}

bool zeek::Broker::detail::TableIterator::DoUnserialize(const broker::data& data)
	{
	auto v = caf::get_if<broker::vector>(&data);
	if ( ! (v && v->size() == 2) )
		return false;

	auto x = caf::get_if<broker::table>(&(*v)[0]);

	// We set the iterator by finding the element it used to point to.
	// This is not perfect, as there's no guarantee that the restored
	// container will list the elements in the same order. But it's as
	// good as we can do, and it should generally work out.
	if( x->find((*v)[1]) == x->end() )
		return false;

	dat = *x;
	it = dat.find((*v)[1]);
	return true;
	}

IMPLEMENT_OPAQUE_VALUE(zeek::Broker::detail::VectorIterator)

broker::expected<broker::data> zeek::Broker::detail::VectorIterator::DoSerialize() const
	{
	broker::integer difference = it - dat.begin();
	return broker::vector{dat, difference};
	}

bool zeek::Broker::detail::VectorIterator::DoUnserialize(const broker::data& data)
	{
	auto v = caf::get_if<broker::vector>(&data);
	if ( ! (v && v->size() == 2) )
		return false;

	auto x = caf::get_if<broker::vector>(&(*v)[0]);
	auto y = caf::get_if<broker::integer>(&(*v)[1]);

	if ( ! (x && y) )
		return false;

	dat = *x;
	it = dat.begin() + *y;
	return true;
	}

IMPLEMENT_OPAQUE_VALUE(zeek::Broker::detail::RecordIterator)

broker::expected<broker::data> zeek::Broker::detail::RecordIterator::DoSerialize() const
	{
	broker::integer difference = it - dat.begin();
	return broker::vector{dat, difference};
	}

bool zeek::Broker::detail::RecordIterator::DoUnserialize(const broker::data& data)
	{
	auto v = caf::get_if<broker::vector>(&data);
	if ( ! (v && v->size() == 2) )
		return false;

	auto x = caf::get_if<broker::vector>(&(*v)[0]);
	auto y = caf::get_if<broker::integer>(&(*v)[1]);

	if ( ! (x && y) )
		return false;

	dat = *x;
	it = dat.begin() + *y;
	return true;
	}

broker::data zeek::Broker::detail::threading_field_to_data(const zeek::threading::Field* f)
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

zeek::threading::Field* zeek::Broker::detail::data_to_threading_field(broker::data d)
	{
	if ( ! caf::holds_alternative<broker::vector>(d) )
		return nullptr;

	auto& v = caf::get<broker::vector>(d);
	auto name = caf::get_if<std::string>(&v[0]);
	auto secondary = v[1];
	auto type = caf::get_if<broker::count>(&v[2]);
	auto subtype = caf::get_if<broker::count>(&v[3]);
	auto optional = caf::get_if<broker::boolean>(&v[4]);

	if ( ! (name && type && subtype && optional) )
		return nullptr;

	if ( secondary != broker::nil && ! caf::holds_alternative<std::string>(secondary) )
		return nullptr;

	return new zeek::threading::Field(name->c_str(),
	                                  secondary != broker::nil ? caf::get<std::string>(secondary).c_str() : nullptr,
	                                  static_cast<zeek::TypeTag>(*type),
	                                  static_cast<zeek::TypeTag>(*subtype),
	                                  *optional);
	}
