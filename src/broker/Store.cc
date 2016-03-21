#include "Store.h"
#include "broker/Manager.h"

#include <broker/store/master.hh>
#include <broker/store/clone.hh>
#include <broker/store/sqlite_backend.hh>

#ifdef HAVE_ROCKSDB
#include <broker/store/rocksdb_backend.hh>
#include <rocksdb/db.h>
#endif

OpaqueType* bro_broker::opaque_of_store_handle;

bro_broker::StoreHandleVal::StoreHandleVal(broker::store::identifier id,
                                     bro_broker::StoreType arg_type,
                                     broker::util::optional<BifEnum::BrokerStore::BackendType> arg_back,
                                     RecordVal* backend_options, std::chrono::duration<double> resync)
	: OpaqueVal(opaque_of_store_handle),
	  store(), store_type(arg_type), backend_type(arg_back)
	{
	using BifEnum::BrokerStore::BackendType;
	std::unique_ptr<broker::store::backend> backend;

	if ( backend_type )
		switch ( *backend_type ) {
		case BackendType::MEMORY:
			backend.reset(new broker::store::memory_backend);
			break;
		case BackendType::SQLITE:
			{
			auto sqlite = new broker::store::sqlite_backend;
			std::string path = backend_options->Lookup(0)->AsRecordVal()
			                   ->Lookup(0)->AsStringVal()->CheckString();

			if ( sqlite->open(path) )
				backend.reset(sqlite);
			else
				{
				reporter->Error("failed to open sqlite backend at path %s: %s",
				                path.data(), sqlite->last_error().data());
				delete sqlite;
				}
			}
			break;
		case BackendType::ROCKSDB:
			{
#ifdef HAVE_ROCKSDB
			std::string path = backend_options->Lookup(1)->AsRecordVal()
			                   ->Lookup(0)->AsStringVal()->CheckString();
			rocksdb::Options rock_op;
			rock_op.create_if_missing = true;

			auto rocksdb = new broker::store::rocksdb_backend;

			if ( rocksdb->open(path, options).ok() )
				backend.reset(rocksdb);
			else
				{
				reporter->Error("failed to open rocksdb backend at path %s: %s",
				                path.data(), rocksdb->last_error().data());
				delete rocksdb;
				}
#else
			reporter->Error("rocksdb backend support is not enabled");
#endif
			}
			break;
		default:
			reporter->FatalError("unknown data store backend: %d",
			                     static_cast<int>(*backend_type));
			}

	switch ( store_type ) {
	case StoreType::FRONTEND:
		store = new broker::store::frontend(broker_mgr->Endpoint(), move(id));
		break;
	case StoreType::MASTER:
		store = new broker::store::master(broker_mgr->Endpoint(), move(id),
		                                  move(backend));
		break;
	case StoreType::CLONE:
		store = new broker::store::clone(broker_mgr->Endpoint(), move(id), resync,
		                                 move(backend));
		break;
	default:
		reporter->FatalError("unknown data store type: %d",
		                     static_cast<int>(store_type));
		}
	}

void bro_broker::StoreHandleVal::ValDescribe(ODesc* d) const
	{
	using BifEnum::BrokerStore::BackendType;
	d->Add("broker::store::");

	switch ( store_type ) {
	case StoreType::FRONTEND:
		d->Add("frontend");
		break;
	case StoreType::MASTER:
		d->Add("master");
		break;
	case StoreType::CLONE:
		d->Add("clone");
		break;
	default:
		d->Add("unknown");
		}

	d->Add("{");
	d->Add(store->id());

	if ( backend_type )
		{
		d->Add(", ");

		switch ( *backend_type ) {
		case BackendType::MEMORY:
			d->Add("memory");
			break;
		case BackendType::SQLITE:
			d->Add("sqlite");
			break;
		case BackendType::ROCKSDB:
			d->Add("rocksdb");
			break;
		default:
			d->Add("unknown");
			}
		}

	d->Add("}");
	}

IMPLEMENT_SERIAL(bro_broker::StoreHandleVal, SER_COMM_STORE_HANDLE_VAL);

bool bro_broker::StoreHandleVal::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_COMM_STORE_HANDLE_VAL, OpaqueVal);

	bool have_store = store != nullptr;

	if ( ! SERIALIZE(have_store) )
		return false;

	if ( ! have_store )
		return true;

	if ( ! SERIALIZE(static_cast<int>(store_type)) )
		return false;

	if ( ! SERIALIZE_STR(store->id().data(), store->id().size()) )
		return false;

	return true;
	}

bool bro_broker::StoreHandleVal::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(OpaqueVal);

	bool have_store;

	if ( ! UNSERIALIZE(&have_store) )
		return false;

	if ( ! have_store )
		{
		store = nullptr;
		return true;
		}

	int type;

	if ( ! UNSERIALIZE(&type) )
		return false;

	const char* id_str;
	int len;

	if ( ! UNSERIALIZE_STR(&id_str, &len) )
		return false;

	broker::store::identifier id(id_str, len);
	delete [] id_str;

	auto handle = broker_mgr->LookupStore(id, static_cast<bro_broker::StoreType>(type));

	if ( ! handle )
		{
		// Passing serialized version of store handles to other Bro processes
		// doesn't make sense, only allow local clones of the handle val.
		reporter->Error("failed to look up unserialized store handle %s, %d",
		                id.data(), type);
		store = nullptr;
		return false;
		}

	store = handle->store;
	store_type = handle->store_type;
	backend_type = handle->backend_type;
	return true;
	}
