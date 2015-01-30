#include "Store.h"
#include "comm/Manager.h"

#include <broker/store/master.hh>
#include <broker/store/clone.hh>
#include <broker/store/sqlite_backend.hh>

#ifdef HAVE_ROCKSDB
#include <broker/store/rocksdb_backend.hh>
#include <rocksdb/db.h>
#endif

OpaqueType* comm::opaque_of_store_handle;

comm::StoreHandleVal::StoreHandleVal(broker::store::identifier id,
                                     comm::StoreType arg_type,
                                     broker::util::optional<BifEnum::Store::BackendType> arg_back,
                                     RecordVal* backend_options, std::chrono::duration<double> resync)
    : OpaqueVal(opaque_of_store_handle),
      store(), store_type(arg_type), backend_type(arg_back)
	{
	using BifEnum::Store::BackendType;
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
			bool use_merge_op = backend_options->Lookup(1)->AsRecordVal()
			                    ->Lookup(1)->AsBool();
			rocksdb::Options rock_op;
			rock_op.create_if_missing = true;

			if ( use_merge_op )
				options.merge_operator.reset(new rocksdb_merge_operator);

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
		store.reset(new broker::store::frontend(comm_mgr->Endpoint(),
		                                        move(id)));
		break;
	case StoreType::MASTER:
		store.reset(new broker::store::master(comm_mgr->Endpoint(),
		                                      move(id), move(backend)));
		break;
	case StoreType::CLONE:
		store.reset(new broker::store::clone(comm_mgr->Endpoint(),
		                                     move(id), resync,
		                                     move(backend)));
		break;
	default:
		reporter->FatalError("unknown data store type: %d",
		                     static_cast<int>(store_type));
		}
	}

void comm::StoreHandleVal::ValDescribe(ODesc* d) const
	{
	using BifEnum::Store::BackendType;
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
