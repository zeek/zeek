#pragma once

#include "broker/store.bif.h"
#include "broker/data.bif.h"
#include "OpaqueVal.h"
#include "Trigger.h"

#include <broker/store.hh>
#include <broker/store_event.hh>
#include <broker/backend.hh>
#include <broker/backend_options.hh>

namespace zeek::Broker::detail {

extern zeek::OpaqueTypePtr opaque_of_store_handle;

/**
 * Create a Broker::QueryStatus value.
 * @param success whether the query status should be set to success or failure.
 * @return a Broker::QueryStatus value.
 */
zeek::EnumValPtr query_status(bool success);

/**
 * @return a Broker::QueryResult value that has a Broker::QueryStatus indicating
 * a failure.
 */
inline zeek::RecordValPtr query_result()
	{
	auto rval = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::Broker::QueryResult);
	rval->Assign(0, query_status(false));
	rval->Assign(1, zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::Broker::Data));
	return rval;
	}

/**
 * @param data the result of the query.
 * @return a Broker::QueryResult value that has a Broker::QueryStatus indicating
 * a success.
 */
inline zeek::RecordValPtr query_result(zeek::RecordValPtr data)
	{
	auto rval = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::Broker::QueryResult);
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

	void Result(const zeek::RecordValPtr& result)
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
class StoreHandleVal : public zeek::OpaqueVal {
public:
	StoreHandleVal(broker::store s)
		: zeek::OpaqueVal(zeek::Broker::detail::opaque_of_store_handle), store{s}, proxy{store}, store_pid{store.frontend_id()}
		{ }

	void ValDescribe(zeek::ODesc* d) const override;

	broker::store store;
	broker::store::proxy proxy;
	broker::publisher_id store_pid;
	// Zeek table that events are forwarded to.
	zeek::TableValPtr forward_to;

protected:

	zeek::IntrusivePtr<Val> DoClone(CloneState* state) override
		{ return { zeek::NewRef{}, this }; }

	StoreHandleVal()
		: zeek::OpaqueVal(zeek::Broker::detail::opaque_of_store_handle)
		{}

	DECLARE_OPAQUE_VALUE(StoreHandleVal)
};

// Helper function to construct a broker backend type from script land.
broker::backend to_backend_type(BifEnum::Broker::BackendType type);

// Helper function to construct broker backend options from script land.
broker::backend_options to_backend_options(broker::backend backend,
                                           zeek::RecordVal* options);

} // namespace zeek::Broker

namespace bro_broker {

	extern zeek::OpaqueTypePtr& opaque_of_store_handle [[deprecated("Remove in v4.1. Use zeek::Broker::detail::opaque_of_store_handle.")]];

	[[deprecated("Remove in v4.1. Use zeek::Broker::detail::query_result.")]]
	inline zeek::RecordValPtr query_result()
		{
		return zeek::Broker::detail::query_result();
		}

	[[deprecated("Remove in v4.1. Use zeek::Broker::detail::query_result.")]]
	inline zeek::RecordValPtr query_result(zeek::RecordValPtr data)
		{
		return zeek::Broker::detail::query_result();
		}

	constexpr auto convert_expiry [[deprecated("Remove in v4.1. Use zeek::Broker::detail::convert_expiry.")]] = zeek::Broker::detail::convert_expiry;
	using StoreQueryCallback [[deprecated("Remove in v4.1. Use zeek::Broker::detail::StoreQueryCallback.")]] = zeek::Broker::detail::StoreQueryCallback;
	using StoreHandleVal [[deprecated("Remove in v4.1. Use zeek::Broker::detail::StoreHandleVal.")]] = zeek::Broker::detail::StoreHandleVal;

	constexpr auto to_backend_type [[deprecated("Remove in v4.1. Use zeek::Broker::detail::to_backend_type.")]] = zeek::Broker::detail::to_backend_type;
	constexpr auto to_backend_options [[deprecated("Remove in v4.1. Use zeek::Broker::detail::to_backend_options.")]] = zeek::Broker::detail::to_backend_options;

} // namespace bro_broker
