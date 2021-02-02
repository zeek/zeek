#pragma once

#include <broker/store.hh>
#include <broker/store_event.hh>
#include <broker/backend.hh>
#include <broker/backend_options.hh>

#include "zeek/OpaqueVal.h"
#include "zeek/Trigger.h"

#include "broker/store.bif.h"
#include "broker/data.bif.h"

namespace zeek::Broker::detail {

extern OpaqueTypePtr opaque_of_store_handle;

/**
 * Create a Broker::QueryStatus value.
 * @param success whether the query status should be set to success or failure.
 * @return a Broker::QueryStatus value.
 */
EnumValPtr query_status(bool success);

/**
 * @return a Broker::QueryResult value that has a Broker::QueryStatus indicating
 * a failure.
 */
inline RecordValPtr query_result()
	{
	auto rval = make_intrusive<RecordVal>(BifType::Record::Broker::QueryResult);
	rval->Assign(0, query_status(false));
	rval->Assign(1, make_intrusive<RecordVal>(BifType::Record::Broker::Data));
	return rval;
	}

/**
 * @param data the result of the query.
 * @return a Broker::QueryResult value that has a Broker::QueryStatus indicating
 * a success.
 */
inline RecordValPtr query_result(RecordValPtr data)
	{
	auto rval = make_intrusive<RecordVal>(BifType::Record::Broker::QueryResult);
	rval->Assign(0, query_status(true));
	rval->Assign(1, std::move(data));
	return rval;
	}

/**
 * Convert an expiry from a double (used by Zeek) to the format required by Broker
 * @param e: expire interval as double; 0 if no expiry
 * @return expire interval in Broker format
 */
static broker::optional<broker::timespan> convert_expiry(double e)
	{
	broker::optional<broker::timespan> ts;

	if ( e )
		{
		broker::timespan x;
		broker::convert(e, x);
		ts = x;
		}

	return ts;
	}

/**
 * Used for asynchronous data store queries which use "when" statements.
 */
class StoreQueryCallback {
public:
	StoreQueryCallback(zeek::detail::trigger::Trigger* arg_trigger, const zeek::detail::CallExpr* arg_call,
	                   broker::store store)
		: trigger(arg_trigger), call(arg_call), store(std::move(store))
		{
		Ref(trigger);
		}

	~StoreQueryCallback()
		{
		Unref(trigger);
		}

	void Result(const RecordValPtr& result)
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

	zeek::detail::trigger::Trigger* trigger;
	const zeek::detail::CallExpr* call;
	broker::store store;
};

/**
 * An opaque handle which wraps a Broker data store.
 */
class StoreHandleVal : public OpaqueVal {
public:
	StoreHandleVal(broker::store s)
		: OpaqueVal(Broker::detail::opaque_of_store_handle), store{s}, proxy{store}, store_pid{store.frontend_id()}
		{ }

	void ValDescribe(ODesc* d) const override;

	broker::store store;
	broker::store::proxy proxy;
	broker::publisher_id store_pid;
	// Zeek table that events are forwarded to.
	TableValPtr forward_to;

protected:

	IntrusivePtr<Val> DoClone(CloneState* state) override
		{ return { NewRef{}, this }; }

	StoreHandleVal()
		: OpaqueVal(Broker::detail::opaque_of_store_handle)
		{}

	DECLARE_OPAQUE_VALUE(StoreHandleVal)
};

// Helper function to construct a broker backend type from script land.
broker::backend to_backend_type(BifEnum::Broker::BackendType type);

// Helper function to construct broker backend options from script land.
broker::backend_options to_backend_options(broker::backend backend,
                                           RecordVal* options);

} // namespace zeek::Broker
