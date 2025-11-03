// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <map>

#include "zeek/EventHandler.h"
#include "zeek/Hash.h"
#include "zeek/Obj.h"
#include "zeek/Tag.h"
#include "zeek/Timer.h"
#include "zeek/session/Key.h"

namespace zeek {

class RecordVal;
using RecordValPtr = IntrusivePtr<RecordVal>;

namespace analyzer {
class Analyzer;
}

namespace session {
namespace detail {
class Timer;

constexpr uint32_t HIST_UNKNOWN_PKT = 0x400; // Initially for exceeded_tunnel_max_depth.
} // namespace detail

class Session;
using timer_func = void (Session::*)(double t);

enum class AnalyzerConfirmationState : uint8_t { UNKNOWN, VIOLATED, CONFIRMED };

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
    Session(double t, EventHandlerPtr timeout_event, EventHandlerPtr status_update_event = nullptr,
            double status_update_interval = 0);

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
    void SetInSessionTable(bool in_table) { in_session_table = in_table; }

    /**
     * Return whether this session is in the session table.
     */
    bool IsInSessionTable() const { return in_session_table; }

    double StartTime() const { return start_time; }
    void SetStartTime(double t) { start_time = t; }
    double LastTime() const { return last_time; }
    void SetLastTime(double t) { last_time = t; }

    // True if we should record subsequent packets (either headers or
    // in their entirety, depending on record_contents).  We still
    // record subsequent SYN/FIN/RST, regardless of how this is set.
    bool RecordPackets() const { return record_packets; }
    void SetRecordPackets(bool do_record) { record_packets = do_record ? 1 : 0; }

    // True if we should record full packets for this session,
    // false if we should just record headers.
    bool RecordContents() const { return record_contents; }
    void SetRecordContents(bool do_record) { record_contents = do_record ? 1 : 0; }

    // Set whether to record *current* packet header/full.
    void SetRecordCurrentPacket(bool do_record) { record_current_packet = do_record ? 1 : 0; }
    void SetRecordCurrentContent(bool do_record) { record_current_content = do_record ? 1 : 0; }

    /**
     * Returns the associated "session" record.
     */
    virtual const RecordValPtr& GetVal() = 0;

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
    void Event(EventHandlerPtr f, analyzer::Analyzer* analyzer = nullptr, const char* name = nullptr);

    /**
     * Enqueues an event associated with this session and given analyzer.
     */
    void EnqueueEvent(EventHandlerPtr f, analyzer::Analyzer* analyzer, Args args);

    /**
     * A version of EnqueueEvent() taking a variable number of arguments.
     */
    template<class... Args>
        requires std::is_convertible_v<std::tuple_element_t<0, std::tuple<Args...>>, ValPtr>
    void EnqueueEvent(EventHandlerPtr h, analyzer::Analyzer* analyzer, Args&&... args) {
        return EnqueueEvent(h, analyzer, zeek::Args{std::forward<Args>(args)...});
    }

    void Describe(ODesc* d) const override;

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
    double InactivityTimeout() const { return inactivity_timeout; }

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

    AnalyzerConfirmationState AnalyzerState(const zeek::Tag& tag) const;
    void SetAnalyzerState(const zeek::Tag& tag, AnalyzerConfirmationState);

    /**
     * Add \a code to history unless already seen.
     *
     * @param mask Bitmask used for the given code character.
     * @param code The character to add to the history.
     *
     * @return True if the given \a code was already seen (mask set),
     * otherwise false after adding it.
     */
    bool CheckHistory(uint32_t mask, char code) {
        if ( (hist_seen & mask) == 0 ) {
            hist_seen |= mask;
            AddHistory(code);
            return false;
        }

        return true;
    }

    /**
     * Increments the passed counter and adds it as a history
     * code if it has crossed the next scaling threshold.  Scaling
     * is done in terms of powers of the third argument.
     *
     * @param code The history code.
     * @param counter Reference to counter for this code.
     * @param scaling_threshold The next threshold, updated to next threshold if crossed.
     * @param scaling_base Base to compute the next scaling_threshold.
     *
     * @return True if the threshold was crossed, false otherwise.
     */
    bool ScaledHistoryEntry(char code, uint32_t& counter, uint32_t& scaling_threshold, uint32_t scaling_base = 10);

    /**
     *  Helper to enqueue a history threshold event \a e with the Connection object of this session.
     *
     * @param e The event to enqueue
     * @param is_orig True if this is the originator of the session.
     * @param threshold Crossed threshold to use as event argument.
     */
    void HistoryThresholdEvent(EventHandlerPtr e, bool is_orig, uint32_t threshold);

    /**
     * Add \a code to the history.
     *
     * @param code Code to add
     */
    void AddHistory(char code) { history += code; }

    /**
     * @return The current history value.
     */
    const std::string& GetHistory() const { return history; }

    /**
     * Replace the history of this session with a new one.
     *
     * @param new_h The new history.
     */
    void ReplaceHistory(std::string new_h) { history = std::move(new_h); }

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
    void AddTimer(timer_func timer, double t, bool do_expire, zeek::detail::TimerType type);

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

    unsigned int installed_status_timer : 1;
    unsigned int timers_canceled : 1;
    unsigned int is_active : 1;
    unsigned int record_packets : 1, record_contents : 1;
    unsigned int record_current_packet : 1, record_current_content : 1;
    bool in_session_table;

    std::map<zeek::Tag, AnalyzerConfirmationState> analyzer_confirmations;

    uint32_t hist_seen;
    std::string history;
};

namespace detail {

class Timer final : public zeek::detail::Timer {
public:
    Timer(Session* arg_session, timer_func arg_timer, double arg_t, bool arg_do_expire,
          zeek::detail::TimerType arg_type)
        : zeek::detail::Timer(arg_t, arg_type) {
        Init(arg_session, arg_timer, arg_do_expire);
    }
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

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define ADD_TIMER(timer, t, do_expire, type) AddTimer(timer_func(timer), (t), (do_expire), (type))
