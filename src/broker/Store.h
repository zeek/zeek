#ifndef BRO_COMM_STORE_H
#define BRO_COMM_STORE_H

#include "broker/store.bif.h"
#include "broker/data.bif.h"
#include "Reporter.h"
#include "Type.h"
#include "Val.h"
#include "Trigger.h"

#include <broker/broker.hh>

namespace bro_broker {

extern OpaqueType* opaque_of_store_handle;

/**
 * Create a Broker::QueryStatus value.
 * @param success whether the query status should be set to success or failure.
 * @return a Broker::QueryStatus value.
 */
inline EnumVal* query_status(bool success)
	{
	static EnumType* store_query_status = nullptr;
	static int success_val;
	static int failure_val;

	if ( ! store_query_status )
		{
		store_query_status = internal_type("Broker::QueryStatus")->AsEnumType();
		success_val = store_query_status->Lookup("Broker", "SUCCESS");
		failure_val = store_query_status->Lookup("Broker", "FAILURE");
		}

	return new EnumVal(success ? success_val : failure_val, store_query_status);
	}

/**
 * @return a Broker::QueryResult value that has a Broker::QueryStatus indicating
 * a failure.
 */
inline RecordVal* query_result()
	{
	auto rval = new RecordVal(BifType::Record::Broker::QueryResult);
	rval->Assign(0, query_status(false));
	rval->Assign(1, new RecordVal(BifType::Record::Broker::Data));
	return rval;
	}

/**
 * @param data the result of the query.
 * @return a Broker::QueryResult value that has a Broker::QueryStatus indicating
 * a success.
 */
inline RecordVal* query_result(RecordVal* data)
	{
	auto rval = new RecordVal(BifType::Record::Broker::QueryResult);
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
			   broker::store store)
		: trigger(arg_trigger), call(arg_call), store(move(store))
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

	const broker::store& Store() const
		{ return store; }

private:

	Trigger* trigger;
	const CallExpr* call;
	broker::store store;
};

/**
 * An opaque handle which wraps a Broker data store.
 */
class StoreHandleVal : public OpaqueVal {
public:
	StoreHandleVal(broker::store s)
		: OpaqueVal(bro_broker::opaque_of_store_handle), store{s}, proxy{store}
		{ }

	void ValDescribe(ODesc* d) const override;

	DECLARE_SERIAL(StoreHandleVal);

	broker::store store;
	broker::store::proxy proxy;

protected:
	StoreHandleVal() = default;
};

// Helper function to construct a broker backend type from script land.
broker::backend to_backend_type(BifEnum::Broker::BackendType type);

// Helper function to construct broker backend options from script land.
broker::backend_options to_backend_options(broker::backend backend,
                                           RecordVal* options);

} // namespace bro_broker

#endif // BRO_COMM_STORE_H
