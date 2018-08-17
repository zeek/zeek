#include "Store.h"
#include "broker/Manager.h"

namespace bro_broker {

OpaqueType* opaque_of_store_handle;

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

IMPLEMENT_SERIAL(StoreHandleVal, SER_COMM_STORE_HANDLE_VAL);

bool StoreHandleVal::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_COMM_STORE_HANDLE_VAL, OpaqueVal);

	auto name = store.name();
	if ( ! SERIALIZE_STR(name.data(), name.size()) )
		return false;

	return true;
	}

bool StoreHandleVal::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(OpaqueVal);

	const char* name_str;
	int len;

	if ( ! UNSERIALIZE_STR(&name_str, &len) )
		return false;

	std::string name(name_str, len);
	delete [] name_str;

	auto handle = broker_mgr->LookupStore(name);
	if ( ! handle )
		{
		// Passing serialized version of store handles to other Bro processes
		// doesn't make sense, only allow local clones of the handle val.
		reporter->Error("failed to look up unserialized store handle %s",
		                name.c_str());
		return false;
		}

	store = handle->store;
	proxy = broker::store::proxy{store};

	return true;
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
