#include "zeek/broker/Store.h"

#include "zeek/Desc.h"
#include "zeek/ID.h"
#include "zeek/broker/Manager.h"

zeek::OpaqueTypePtr zeek::Broker::detail::opaque_of_store_handle;

namespace zeek::Broker::detail
	{

EnumValPtr query_status(bool success)
	{
	static EnumType* store_query_status = nullptr;
	static int success_val;
	static int failure_val;

	if ( ! store_query_status )
		{
		store_query_status = id::find_type("Broker::QueryStatus")->AsEnumType();
		success_val = store_query_status->Lookup("Broker", "SUCCESS");
		failure_val = store_query_status->Lookup("Broker", "FAILURE");
		}

	auto rval = store_query_status->GetEnumVal(success ? success_val : failure_val);
	return rval;
	}

void StoreHandleVal::ValDescribe(ODesc* d) const
	{
	d->Add("broker::store::");

	d->Add("{");
	d->Add(store.name());

	d->Add("}");
	}

IMPLEMENT_OPAQUE_VALUE(StoreHandleVal)

broker::expected<broker::data> StoreHandleVal::DoSerialize() const
	{
	// Cannot serialize.
	return broker::ec::invalid_data;
	}

bool StoreHandleVal::DoUnserialize(const broker::data& data)
	{
	// Cannot unserialize.
	return false;
	}

broker::backend to_backend_type(BifEnum::Broker::BackendType type)
	{
	switch ( type )
		{
		case BifEnum::Broker::MEMORY:
			return broker::backend::memory;

		case BifEnum::Broker::SQLITE:
			return broker::backend::sqlite;
		}

	throw std::runtime_error("unknown broker backend");
	}

broker::backend_options to_backend_options(broker::backend backend, RecordVal* options)
	{
	static auto failure_mode_type = id::find_type("Broker::SQLiteFailureMode")->AsEnumType();
	static auto sqlite_synchronous_type = id::find_type("Broker::SQLiteSynchronous")->AsEnumType();
	static auto sqlite_journal_mode_type = id::find_type("Broker::SQLiteJournalMode")->AsEnumType();

	broker::backend_options result;

	switch ( backend )
		{
		case broker::backend::sqlite:
			{
			auto sqlite_opts = options->GetField<RecordVal>("sqlite");
			result["path"] = sqlite_opts->GetField<StringVal>("path")->CheckString();

			if ( auto synchronous = sqlite_opts->GetField<EnumVal>("synchronous") )
				result["synchronous"] = broker::enum_value(
					sqlite_synchronous_type->Lookup(synchronous->Get()));

			if ( auto journal_mode = sqlite_opts->GetField<EnumVal>("journal_mode") )
				result["journal_mode"] = broker::enum_value(
					sqlite_journal_mode_type->Lookup(journal_mode->Get()));

			auto failure_mode = sqlite_opts->GetField<EnumVal>("failure_mode");
			result["failure_mode"] = broker::enum_value(
				failure_mode_type->Lookup(failure_mode->Get()));

			auto integrity_check = sqlite_opts->GetField<BoolVal>("integrity_check")->Get();
			result["integrity_check"] = integrity_check;

			break;
			}

		default:
			break;
		}

	return result;
	}

	} // namespace zeek::Broker
