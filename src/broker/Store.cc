#include "Store.h"
#include "Desc.h"
#include "ID.h"
#include "broker/Manager.h"

namespace bro_broker {

OpaqueType* opaque_of_store_handle;

EnumVal* query_status(bool success)
	{
	static EnumType* store_query_status = nullptr;
	static int success_val;
	static int failure_val;

	if ( ! store_query_status )
		{
		store_query_status = zeek::id::lookup_type("Broker::QueryStatus")->AsEnumType();
		success_val = store_query_status->Lookup("Broker", "SUCCESS");
		failure_val = store_query_status->Lookup("Broker", "FAILURE");
		}

	return store_query_status->GetVal(success ? success_val : failure_val).release();
	}

void StoreHandleVal::ValDescribe(ODesc* d) const
	{
	//using BifEnum::Broker::BackendType;
	d->Add("broker::store::");

	//switch ( store_type ) {
  //  case broker::frontend::FRONTEND:
	//	d->Add("frontend");
	//	break;
  //  case broker::frontend::MASTER:
	//	d->Add("master");
	//	break;
  //  case broker::frontend::CLONE:
	//	d->Add("clone");
	//	break;
	//default:
	//	d->Add("unknown");
	//	}

	d->Add("{");
	d->Add(store.name());

	//if ( backend_type )
	//	{
	//	d->Add(", ");

	//	switch ( *backend_type ) {
	//	case BackendType::MEMORY:
	//		d->Add("memory");
	//		break;
	//	case BackendType::SQLITE:
	//		d->Add("sqlite");
	//		break;
	//	case BackendType::ROCKSDB:
	//		d->Add("rocksdb");
	//		break;
	//	default:
	//		d->Add("unknown");
	//		}
	//	}

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
	switch ( type ) {
	case BifEnum::Broker::MEMORY:
		return broker::memory;

	case BifEnum::Broker::SQLITE:
		return broker::sqlite;

	case BifEnum::Broker::ROCKSDB:
		return broker::rocksdb;
	}

	throw std::runtime_error("unknown broker backend");
	}

broker::backend_options to_backend_options(broker::backend backend,
                                           RecordVal* options)
	{
	switch ( backend ) {
	case broker::sqlite:
		{
		auto path = options->Lookup(0)->AsRecordVal()
			->Lookup(0)->AsStringVal()->CheckString();
		return {{"path", path}};
		}

	case broker::rocksdb:
		{
		auto path = options->Lookup(1)->AsRecordVal()
			->Lookup(0)->AsStringVal()->CheckString();
		return {{"path", path}};
		}

	default:
		break;
	}

	return broker::backend_options{};
	}

} // namespace bro_broker
