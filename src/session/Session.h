// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>

#include "zeek/Hash.h"
#include "zeek/Obj.h"
#include "zeek/EventHandler.h"
#include "zeek/Timer.h"
#include "zeek/session/Key.h"

namespace zeek {

class RecordVal;
using RecordValPtr = IntrusivePtr<RecordVal>;

namespace analyzer { class Analyzer; }

namespace session {
namespace detail { class Timer; }

class Session;
typedef void (Session::*timer_func)(double t);

class Session : public Obj {
public:

	/**
	 * Construct a new session.
	 *
	 * @param t The timestamp for the start and end of the session when it's initially
	 * created. The end time will be updated as later packets are processed.
	 * @param timeout_event The event that will be emitted when the session times out.
	 * @param status_update_event The event that will be emitted for session status
	 * updates. This can be set to null to disable status updates. This event also
	 * won't be emitted unless the EnableStatusUpdateTimer() method is called on the
	 * session, and the interval is set to a non-zero value.
	 * @param status_update_interval The interval in seconds for the status update
	 * event to be emitted. Setting this to zero disables the status update timer.
	 */
	Session(double t, EventHandlerPtr timeout_event,
	        EventHandlerPtr status_update_event = nullptr,
	        double status_update_interval = 0);

	virtual ~Session() {}

	/**
	 * Invoked when the session is about to be removed. Use Ref(this)
	 * inside Done to keep the session object around, though it'll
	 * no longer be accessible from the SessionManager.
	 */
	virtual void Done() = 0;

	/**
	 * Returns a key for the session. This is used as the key for storing
	 * the session in SessionManager.
	 *
	 * @param copy Flag to indicate that the key returned must have a copy of the
	 * key data instead of just a pointer to it.
	 */
	virtual detail::Key SessionKey(bool copy) const = 0;

	/**
	 * Set whether this session is in the session table.
	 */
	void SetInSessionTable(bool in_table)	{ in_session_table = in_table; }

	/**
	 * Return whether this session is in the session table.
	 */
	bool IsInSessionTable() const 	{ return in_session_table; }

	double StartTime() const		{ return start_time; }
	void SetStartTime(double t)		{ start_time = t; }
	double LastTime() const			{ return last_time; }
	void SetLastTime(double t) 		{ last_time = t; }

	// True if we should record subsequent packets (either headers or
	// in their entirety, depending on record_contents).  We still
	// record subsequent SYN/FIN/RST, regardless of how this is set.
	bool RecordPackets() const		{ return record_packets; }
	void SetRecordPackets(bool do_record)	{ record_packets = do_record ? 1 : 0; }

	// True if we should record full packets for this session,
	// false if we should just record headers.
	bool RecordContents() const		{ return record_contents; }
	void SetRecordContents(bool do_record)	{ record_contents = do_record ? 1 : 0; }

	// Set whether to record *current* packet header/full.
	void SetRecordCurrentPacket(bool do_record)
		{ record_current_packet = do_record ? 1 : 0; }
	void SetRecordCurrentContent(bool do_record)
		{ record_current_content = do_record ? 1 : 0; }

	/**
	 * Returns the associated "session" record.
	 */
	virtual const RecordValPtr& GetVal() = 0;

	[[deprecated("Remove in v5.1. Use GetVal().")]]
	const RecordValPtr& ConnVal() { return GetVal(); }

	/**
	 * Return the memory allocation required by the session record. This requires at
	 * least one call to Get() first in order to setup the record object.
	 */
	[[deprecated("Remove in v5.1. MemoryAllocation() is deprecated and will be removed. See GHI-572.")]]
	virtual unsigned int MemoryAllocationVal() const = 0;

	[[deprecated("Remove in v5.1. Use MemoryAllocationVal().")]]
	unsigned int MemoryAllocationConnVal() const
		{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
		return MemoryAllocationVal();
#pragma GCC diagnostic pop
		}

	/**
	 * A lower-bound calculation of how much memory a session object is using.
	 */
	[[deprecated("Remove in v5.1. MemoryAllocation() is deprecated and will be removed. See GHI-572.")]]
	virtual unsigned int MemoryAllocation() const;

	/**
	 * Generates session removal event(s). Must be overridden by child classes to
	 * provide specific removal events.
	 */
	virtual void RemovalEvent() = 0;

	/**
	 * Generate an event for this session.
	 *
	 * @param f The handler for the event to be generated. If the handler doesn't
	 * exist, this method doesn't generate anything.
	 * @param analyzer
	 * @param name If given, this will be passed as the first argument to the
	 * handler, followed by the session value. If null, then the event's first
	 * argument is the session value.
	 */
	void Event(EventHandlerPtr f, analyzer::Analyzer* analyzer = nullptr,
	           const char* name = nullptr);

	/**
	 * Enqueues an event associated with this session and given analyzer.
	 */
	void EnqueueEvent(EventHandlerPtr f, analyzer::Analyzer* analyzer, Args args);

	/**
	 * A version of EnqueueEvent() taking a variable number of arguments.
	 */
	template <class... Args>
	std::enable_if_t<
		std::is_convertible_v<
			std::tuple_element_t<0, std::tuple<Args...>>, ValPtr>>
	EnqueueEvent(EventHandlerPtr h, analyzer::Analyzer* analyzer, Args&&... args)
		{ return EnqueueEvent(h, analyzer, zeek::Args{std::forward<Args>(args)...}); }

	virtual	void Describe(ODesc* d) const override;

	/**
	 * Sets the session to expire after a given amount of time.
	 *
	 * @param lifetime The amount of time in seconds from the current network time.
	 */
	void SetLifetime(double lifetime);

	/**
	 * Sets the inactivity timeout for this session.
	 *
	 * @param timeout The number of seconds of inactivity allowed for this session
	 * before it times out.
	 */
	void SetInactivityTimeout(double timeout);

	/**
	 * Returns the inactivity timeout for the session.
	 */
	double InactivityTimeout() const	{ return inactivity_timeout; }

	/**
	 * Activates the timer for the status update event.
	 */
	void EnableStatusUpdateTimer();

	/**
	 * Cancels all timers associated with this session.
	 */
	void CancelTimers();

	/**
	 * Called when the lifetime of the session expires. Fires a timeout event and
	 * removes the session from the manager.
	 * TODO: This function has a terrible name considering there's an AddTimer() and
	 * a RemoveTimer() method in this class as well.
	 *
	 * @param t This argument is ignored.
	 */
	void DeleteTimer(double t);

	/**
	 * Returns a string representation of the transport protocol referenced by the
	 * session. This is used by SessionManager for statistics.
	 */
	virtual std::string TransportIdentifier() const = 0;

protected:

	friend class detail::Timer;

	/**
	 * Add a given timer to expire at a specific time.
	 *
	 * @param timer A pointer to a method that will be called when the timer expires.
	 * @param t The time when the timer expires. This is an absolute time, not a time
	 * relative to the current network time.
	 * @param do_expire If set to true, the timer is also evaluated when Zeek
	 * terminates.
	 * @param type The type of timer being added.
	 */
	void AddTimer(timer_func timer, double t, bool do_expire,
	              zeek::detail::TimerType type);

	/**
	 * Remove a specific timer from firing.
	 */
	void RemoveTimer(zeek::detail::Timer* t);

	/**
	 * The handler method for inactivity timers.
	 */
	void InactivityTimer(double t);

	/**
	 * The handler method for status update timers.
	 */
	void StatusUpdateTimer(double t);

	// TODO: is this method used by anyone?
	void RemoveConnectionTimer(double t);

	double start_time, last_time;
	TimerPList timers;
	double inactivity_timeout;

	EventHandlerPtr session_timeout_event;
	EventHandlerPtr session_status_update_event;
	double session_status_update_interval;

	unsigned int installed_status_timer:1;
	unsigned int timers_canceled:1;
	unsigned int is_active:1;
	unsigned int record_packets:1, record_contents:1;
	unsigned int record_current_packet:1, record_current_content:1;
	bool in_session_table;
};

namespace detail {

class Timer final : public zeek::detail::Timer {
public:
	Timer(Session* arg_session, timer_func arg_timer,
	             double arg_t, bool arg_do_expire,
	             zeek::detail::TimerType arg_type)
		: zeek::detail::Timer(arg_t, arg_type)
		{ Init(arg_session, arg_timer, arg_do_expire); }
	~Timer() override;

	void Dispatch(double t, bool is_expire) override;

protected:

	void Init(Session* session, timer_func timer, bool do_expire);

	Session* session;
	timer_func timer;
	bool do_expire;
};

} // namespace detail
} // namespace session
} // namespace zeek

#define ADD_TIMER(timer, t, do_expire, type) \
	AddTimer(timer_func(timer), (t), (do_expire), (type))
