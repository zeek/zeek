#pragma once

#include "broker/store.bif.h"
#include "broker/data.bif.h"
#include "OpaqueVal.h"
#include "Trigger.h"

#include <broker/store.hh>
#include <broker/backend.hh>
#include <broker/backend_options.hh>

namespace bro_broker {

extern IntrusivePtr<OpaqueType> opaque_of_store_handle;

/**
 * Create a Broker::QueryStatus value.
 * @param success whether the query status should be set to success or failure.
 * @return a Broker::QueryStatus value.
 */
IntrusivePtr<EnumVal> query_status(bool success);

/**
 * @return a Broker::QueryResult value that has a Broker::QueryStatus indicating
 * a failure.
 */
inline IntrusivePtr<RecordVal> query_result()
	{
	auto rval = make_intrusive<RecordVal>(zeek::BifType::Record::Broker::QueryResult);
	rval->Assign(0, query_status(false));
	rval->Assign(1, make_intrusive<RecordVal>(zeek::BifType::Record::Broker::Data));
	return rval;
	}

/**
 * @param data the result of the query.
 * @return a Broker::QueryResult value that has a Broker::QueryStatus indicating
 * a success.
 */
inline IntrusivePtr<RecordVal> query_result(IntrusivePtr<RecordVal> data)
	{
	auto rval = make_intrusive<RecordVal>(zeek::BifType::Record::Broker::QueryResult);
	rval->Assign(0, query_status(true));
	rval->Assign(1, std::move(data));
	return rval;
	}

/**
 * Used for asynchronous data store queries which use "when" statements.
 */
class StoreQueryCallback {
public:
	StoreQueryCallback(trigger::Trigger* arg_trigger, const zeek::detail::CallExpr* arg_call,
			   broker::store store)
		: trigger(arg_trigger), call(arg_call), store(std::move(store))
		{
		Ref(trigger);
		}

	~StoreQueryCallback()
		{
		Unref(trigger);
		}

	void Result(const IntrusivePtr<RecordVal>& result)
		{
		trigger->Cache(call, result.get());
		trigger->Release();
		}

	void Abort()
		{
		auto result = query_result();
		trigger->Cache(call, result.get());
		trigger->Release();
		}

	bool Disabled() const
		{ return trigger->Disabled(); }

	const broker::store& Store() const
		{ return store; }

private:

	trigger::Trigger* trigger;
	const zeek::detail::CallExpr* call;
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

	broker::store store;
	broker::store::proxy proxy;

protected:
	StoreHandleVal()
		: OpaqueVal(bro_broker::opaque_of_store_handle)
		{}

	DECLARE_OPAQUE_VALUE(StoreHandleVal)
};

// Helper function to construct a broker backend type from script land.
broker::backend to_backend_type(BifEnum::Broker::BackendType type);

// Helper function to construct broker backend options from script land.
broker::backend_options to_backend_options(broker::backend backend,
                                           RecordVal* options);

} // namespace bro_broker
