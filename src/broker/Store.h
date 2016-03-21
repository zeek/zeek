#ifndef BRO_COMM_STORE_H
#define BRO_COMM_STORE_H

#include "broker/store.bif.h"
#include "broker/data.bif.h"
#include "Reporter.h"
#include "Type.h"
#include "Val.h"
#include "Trigger.h"

#include <broker/store/frontend.hh>

namespace bro_broker {

extern OpaqueType* opaque_of_store_handle;

/**
 * Enumerates the possible types of data stores.
 */
enum StoreType {
	// Just a view in to a remote store, contains no data itself.
	FRONTEND,
	MASTER,
	CLONE,
};

/**
 * Create a BrokerStore::QueryStatus value.
 * @param success whether the query status should be set to success or failure.
 * @return a BrokerStore::QueryStatus value.
 */
inline EnumVal* query_status(bool success)
	{
	static EnumType* store_query_status = nullptr;
	static int success_val;
	static int failure_val;

	if ( ! store_query_status )
		{
		store_query_status = internal_type("BrokerStore::QueryStatus")->AsEnumType();
		success_val = store_query_status->Lookup("BrokerStore", "SUCCESS");
		failure_val = store_query_status->Lookup("BrokerStore", "FAILURE");
		}

	return new EnumVal(success ? success_val : failure_val, store_query_status);
	}

/**
 * @return a BrokerStore::QueryResult value that has a BrokerStore::QueryStatus indicating
 * a failure.
 */
inline RecordVal* query_result()
	{
	auto rval = new RecordVal(BifType::Record::BrokerStore::QueryResult);
	rval->Assign(0, query_status(false));
	rval->Assign(1, new RecordVal(BifType::Record::BrokerComm::Data));
	return rval;
	}

/**
 * @param data the result of the query.
 * @return a BrokerStore::QueryResult value that has a BrokerStore::QueryStatus indicating
 * a success.
 */
inline RecordVal* query_result(RecordVal* data)
	{
	auto rval = new RecordVal(BifType::Record::BrokerStore::QueryResult);
	rval->Assign(0, query_status(true));
	rval->Assign(1, data);
	return rval;
	}

/**
 * Used for asynchronous data store queries which use "when" statements.
 */
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

	bool Disabled() const
		{ return trigger->Disabled(); }

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

/**
 * An opaque handle which wraps a Broker data store.
 */
class StoreHandleVal : public OpaqueVal {
public:

	StoreHandleVal(broker::store::identifier id,
		       bro_broker::StoreType arg_type,
		       broker::util::optional<BifEnum::BrokerStore::BackendType> arg_back,
		       RecordVal* backend_options,
		       std::chrono::duration<double> resync = std::chrono::seconds(1));

	void ValDescribe(ODesc* d) const override;

	DECLARE_SERIAL(StoreHandleVal);

	broker::store::frontend* store;
	bro_broker::StoreType store_type;
	broker::util::optional<BifEnum::BrokerStore::BackendType> backend_type;

protected:

	StoreHandleVal()
		{}
};

} // namespace bro_broker

#endif // BRO_COMM_STORE_H
