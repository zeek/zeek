#pragma once

#include <list>
#include <utility>

#include "zeek/Timer.h"
#include "zeek/threading/MsgThread.h"

namespace zeek
	{
namespace threading
	{
namespace detail
	{

class HeartbeatTimer final : public zeek::detail::Timer
	{
public:
	HeartbeatTimer(double t) : zeek::detail::Timer(t, zeek::detail::TIMER_THREAD_HEARTBEAT) { }
	virtual ~HeartbeatTimer() { }

	void Dispatch(double t, bool is_expire) override;

protected:
	void Init();
	};

	} // namespace detail

/**
 * The thread manager coordinates all child threads. Once a BasicThread is
 * instantitated, it gets added to the manager, which will delete it later
 * once it has terminated.
 *
 * In addition to basic threads, the manager also provides additional
 * functionality specific to MsgThread instances. In particular, it polls
 * their outgoing message queue on a regular basis and feeds data sent into
 * the rest of Zeek. It also triggers the regular heartbeats.
 */
class Manager
	{
public:
	/**
	 * Constructor. Only a single instance of the manager must be
	 * created.
	 */
	Manager();

	/**
	 * Destructor.
	 */
	~Manager();

	/**
	 * Terminates the manager's processor. The method signals all threads
	 * to terminates and wait for them to do so. It then joins them and
	 * returns to the caller. Afterwards, no more thread instances may be
	 * created.
	 */
	void Terminate();

	/**
	 * Returns True if we are currently in Terminate() waiting for
	 * threads to exit.
	 */
	bool Terminating() const { return terminating; }

	using msg_stats_list = std::list<std::pair<std::string, MsgThread::Stats>>;

	/**
	 * Returns statistics from all current MsgThread instances.
	 *
	 * @return A list of statistics, with one entry for each MsgThread.
	 * Each entry is a tuple of thread name and statistics. The list
	 * reference remains valid until the next call to this method (or
	 * termination of the manager).
	 */
	const msg_stats_list& GetMsgThreadStats();

	/**
	 * Returns the number of currently active threads. This counts all
	 * threads that are not yet joined, including any potentially in
	 * Terminating() state.
	 */
	int NumThreads() const { return all_threads.size(); }

	/**
	 * Signals a specific threads to terminate immediately.
	 */
	void KillThread(BasicThread* thread);

	/**
	 * Signals all threads to terminate immediately.
	 */
	void KillThreads();

	/**
	 * Allows threads to directly send Zeek events. The num_vals and vals must be
	 * the same the named event expects. Takes ownership of threading::Value fields.
	 *
	 * @param thread Thread raising the event
	 * @param name Name of event being raised
	 * @param num_vals Number of values passed to the event
	 * @param vals Values passed to the event
	 * @returns True on success false on failure.
	 */
	bool SendEvent(MsgThread* thread, const std::string& name, const int num_vals,
	               Value** vals) const;

protected:
	friend class BasicThread;
	friend class MsgThread;
	friend class detail::HeartbeatTimer;

	/**
	 * Registers a new basic thread with the manager. This is
	 * automatically called by the thread's constructor.
	 *
	 * @param thread The thread.
	 */
	void AddThread(BasicThread* thread);

	/**
	 * Registers a new message thread with the manager. This is
	 * automatically called by the thread's constructor. This must be
	 * called \a in \a addition to AddThread(BasicThread* thread). The
	 * MsgThread constructor makes sure to do so.
	 *
	 * @param thread The thread.
	 */
	void AddMsgThread(MsgThread* thread);

	void Flush();

	/**
	 * Sends heartbeat messages to all active message threads.
	 */
	void SendHeartbeats();

	/**
	 * Sets up a timer to periodically send heartbeat messages to all threads.
	 */
	void StartHeartbeatTimer();

private:
	using all_thread_list = std::list<BasicThread*>;
	all_thread_list all_threads;

	using msg_thread_list = std::list<MsgThread*>;
	msg_thread_list msg_threads;

	bool did_process; // True if the last Process() found some work to do.
	double next_beat; // Timestamp when the next heartbeat will be sent.
	bool terminating; // True if we are in Terminate().

	msg_stats_list stats;

	bool heartbeat_timer_running = false;
	};

	} // namespace threading

/**
 * A singleton instance of the thread manager. All methods must only be
 * called from Zeek's main thread.
 */
extern threading::Manager* thread_mgr;

	} // namespace zeek
