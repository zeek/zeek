#ifndef BRO_COMM_STORE_H
#define BRO_COMM_STORE_H

#include "comm/store.bif.h"
#include "comm/data.bif.h"
#include "Reporter.h"
#include "Type.h"
#include "Val.h"
#include "Trigger.h"

#include <broker/store/frontend.hh>

namespace comm {

extern OpaqueType* opaque_of_store_handle;

enum StoreType {
    FRONTEND,
    MASTER,
    CLONE,
};

inline EnumVal* query_status(bool success)
	{
	static EnumType* store_query_status = nullptr;
	static int success_val;
	static int failure_val;

	if ( ! store_query_status )
		{
		store_query_status = internal_type("Store::QueryStatus")->AsEnumType();
		success_val = store_query_status->Lookup("Store", "SUCCESS");
		failure_val = store_query_status->Lookup("Store", "FAILURE");
		}

	return new EnumVal(success ? success_val : failure_val, store_query_status);
	}

inline RecordVal* query_result()
	{
	auto rval = new RecordVal(BifType::Record::Store::QueryResult);
	rval->Assign(0, query_status(false));
	rval->Assign(1, new RecordVal(BifType::Record::Comm::Data));
	return rval;
	}

inline RecordVal* query_result(RecordVal* data)
	{
	auto rval = new RecordVal(BifType::Record::Store::QueryResult);
	rval->Assign(0, query_status(true));
	rval->Assign(1, data);
	return rval;
	}

class StoreQueryCallback {
public:

	StoreQueryCallback(Trigger* arg_trigger, const CallExpr* arg_call,
					   broker::store::identifier arg_store_id,
	                   StoreType arg_store_type)
		: trigger(arg_trigger), call(arg_call), store_id(move(arg_store_id)),
	      store_type(arg_store_type)
		{
		Ref(trigger);
		}

	~StoreQueryCallback()
		{
		Unref(trigger);
		}

	void Result(RecordVal* result)
		{
		trigger->Cache(call, result);
		trigger->Release();
		Unref(result);
		}

	void Abort()
		{
		auto result = query_result();
		trigger->Cache(call, result);
		trigger->Release();
		Unref(result);
		}

	const broker::store::identifier& StoreID() const
		{ return store_id; }

	StoreType GetStoreType() const
		{ return store_type; }

private:

	Trigger* trigger;
	const CallExpr* call;
	broker::store::identifier store_id;
	StoreType store_type;
};

// TODO: actually need to implement Bro's serialization to support copying vals
// but doesn't make sense to "copy" a master data store, so assert we can
// lookup a store by <id, type> pair locally (i.e. shouldn't send handles remotely).
class StoreHandleVal : public OpaqueVal {
public:

    StoreHandleVal(broker::store::identifier id,
                   comm::StoreType arg_type,
                   broker::util::optional<BifEnum::Store::BackendType> arg_back,
                   RecordVal* backend_options,
                   std::chrono::duration<double> resync = std::chrono::seconds(1));

    void ValDescribe(ODesc* d) const override;

	std::unique_ptr<broker::store::frontend> store;
	comm::StoreType store_type;
	broker::util::optional<BifEnum::Store::BackendType> backend_type;
};

} // namespace comm

#endif // BRO_COMM_STORE_H
