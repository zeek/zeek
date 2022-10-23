#pragma once

#include <atomic>

#include "zeek/DebugLogger.h"
#include "zeek/Flare.h"
#include "zeek/iosource/IOSource.h"
#include "zeek/threading/BasicThread.h"
#include "zeek/threading/Queue.h"

namespace zeek::detail
	{
class Location;
	}

namespace zeek::threading
	{

struct Value;
struct Field;
class BasicInputMessage;
class BasicOutputMessage;

namespace detail
	{

// These classes are marked as friends later so they need to be forward declared.
class HeartbeatMessage;
class FinishMessage;
class FinishedMessage;
class KillMeMessage;

	}

/**
 * A specialized thread that provides bi-directional message passing between
 * Zeek's main thread and the child thread. Messages are instances of
 * BasicInputMessage and BasicOutputMessage for message sent \a to the child
 * thread and received \a from the child thread, respectively.
 *
 * The thread's Run() method implements main loop that processes incoming
 * messages until Terminating() indicates that execution should stop. Once
 * that happens, the thread stops accepting any new messages, finishes
 * processes all remaining ones still in the queue, and then exits.
 */
class MsgThread : public BasicThread, public iosource::IOSource
	{
public:
	/**
	 * Constructor. It automatically registers the thread with the
	 * threading::Manager.
	 *
	 * Only Zeek's main thread may instantiate a new thread.
	 */
	MsgThread();

	/**
	 * Destructor.
	 */
	virtual ~MsgThread();

	/**
	 * Sends a message to the child thread. The message will be proceesed
	 * once the thread has retrieved it from its incoming queue.
	 *
	 * Only the main thread may call this method.
	 *
	 * @param msg The message.
	 */
	void SendIn(BasicInputMessage* msg) { return SendIn(msg, false); }

	/**
	 * Sends a message from the child thread to the main thread.
	 *
	 * Only the child thread may call this method.
	 *
	 * @param msg The message.
	 */
	void SendOut(BasicOutputMessage* msg) { return SendOut(msg, false); }

	/**
	 * Allows the child thread to send a specified Zeek event. The given Vals
	 * must match the values expected by the event.
	 *
	 * @param name name of the Zeek event to send
	 *
	 * @param num_vals number of entries in \a vals
	 *
	 * @param vals the values to be given to the event
	 */
	void SendEvent(const char* name, const int num_vals, Value** vals);

	/**
	 * Reports an informational message from the child thread. The main
	 * thread will pass this to the Reporter once received.
	 *
	 * Only the child thread may call this method.
	 *
	 * @param msg  The message. It will be prefixed with the thread's name.
	 */
	virtual void Info(const char* msg);

	/**
	 * Reports a warning from the child thread that may indicate a
	 * problem. The main thread will pass this to the Reporter once
	 * received.
	 *
	 * Only the child thread may call this method.
	 *
	 * Can be overridden in derived classed to hook into the error handling
	 * but must should generally also call the parent implementation. Note
	 * that this method is always called by the child thread and must not access
	 * data or datastructures of the main thread directly.
	 *
	 * @param msg  The message. It will be prefixed with the thread's name.
	 */
	virtual void Warning(const char* msg);

	/**
	 * Reports a non-fatal error from the child thread. The main thread
	 * will pass this to the Reporter once received. Processing proceeds
	 * normally after the error has been reported.
	 *
	 * Only the child thread may call this method.
	 *
	 * Can be overridden in derived classed to hook into the error handling
	 * but must should generally also call the parent implementation. Note
	 * that this method is always called by the child thread and must not access
	 * data or datastructures of the main thread directly.
	 *
	 * @param msg  The message. It will be prefixed with the thread's name.
	 */
	virtual void Error(const char* msg);

	/**
	 * Reports a fatal error from the child thread. The main thread will
	 * pass this to the Reporter once received. Zeek will terminate after
	 * the message has been reported.
	 *
	 * Only the child thread may call this method.
	 *
	 * @param msg  The message. It will be prefixed with the thread's name.
	 */
	void FatalError(const char* msg);

	/**
	 * Reports a fatal error from the child thread. The main thread will
	 * pass this to the Reporter once received. Zeek will terminate with a
	 * core dump after the message has been reported.
	 *
	 * Only the child thread may call this method.
	 *
	 * @param msg  The message. It will be prefixed with the thread's name.
	 */
	void FatalErrorWithCore(const char* msg);

	/**
	 * Reports a potential internal problem from the child thread. The
	 * main thread will pass this to the Reporter once received. Zeek will
	 * continue normally.
	 *
	 * Only the child thread may call this method.
	 *
	 * @param msg  The message. It will be prefixed with the thread's name.
	 */
	void InternalWarning(const char* msg);

	/**
	 * Reports an internal program error from the child thread. The main
	 * thread will pass this to the Reporter once received. Zeek will
	 * terminate with a core dump after the message has been reported.
	 *
	 * Only the child thread may call this method.
	 *
	 * @param msg  The message. It will be prefixed with the thread's name.
	 */
	[[noreturn]] void InternalError(const char* msg);

#ifdef DEBUG
	/**
	 * Records a debug message for the given stream from the child
	 * thread. The main thread will pass this to the DebugLogger once
	 * received.
	 *
	 * Only the child thread may call this method.
	 *
	 * @param msg  The message. It will be prefixed with the thread's name.
	 */
	void Debug(DebugStream stream, const char* msg);
#endif

	/**
	 * Statistics about inter-thread communication.
	 */
	struct Stats
		{
		uint64_t sent_in; //! Number of messages sent to the child thread.
		uint64_t sent_out; //! Number of messages sent from the child thread to the main thread
		uint64_t pending_in; //! Number of messages sent to the child but not yet processed.
		uint64_t pending_out; //! Number of messages sent from the child but not yet processed by
		                      //! the main thread.

		/// Statistics from our queues.
		Queue<BasicInputMessage*>::Stats queue_in_stats;
		Queue<BasicOutputMessage*>::Stats queue_out_stats;
		};

	/**
	 * Returns statistics about the inter-thread communication.
	 *
	 * @param stats A pointer to a structure that will be filled with
	 * current numbers.
	 */
	void GetStats(Stats* stats);

	/**
	 * Overridden from iosource::IOSource.
	 */
	void Process() override;
	const char* Tag() override { return Name(); }
	double GetNextTimeout() override { return -1; }

protected:
	friend class Manager;
	friend class detail::HeartbeatMessage;
	friend class detail::FinishMessage;
	friend class detail::FinishedMessage;
	friend class detail::KillMeMessage;

	/**
	 * Pops a message sent by the child from the child-to-main queue.
	 *
	 * This is method is called regularly by the threading::Manager.
	 *
	 * @return The message, wth ownership passed to caller. Returns null
	 * if the queue is empty.
	 */
	BasicOutputMessage* RetrieveOut();

	/**
	 * Triggers a heartbeat message being sent to the client thread.
	 *
	 * This is method is called regularly by the threading::Manager.
	 *
	 * Can be overridden in derived classed to hook into the heart beat
	 * sending, but must call the parent implementation. Note that this
	 * method is always called by the main thread and must not access
	 * data of the child thread directly. Implement OnHeartbeat() if you
	 * want to do something on the child-side.
	 */
	virtual void Heartbeat();

	/** Returns true if a child command has reported a failure. In that case, we'll
	 * be in the process of killing this thread and no further activity
	 * should carried out. To be called only from this child thread.
	 */
	bool Failed() const { return failed; }

	/**
	 * Regulatly triggered for execution in the child thread.
	 *
	 * network_time: The network_time when the heartbeat was trigger by
	 * the main thread.
	 *
	 * current_time: Wall clock when the heartbeat was trigger by the
	 * main thread.
	 */
	virtual bool OnHeartbeat(double network_time, double current_time) = 0;

	/** Triggered for execution in the child thread just before shutting threads down.
	 *  The child thread should finish its operations.
	 */
	virtual bool OnFinish(double network_time) = 0;

	/**
	 * Overridden from BasicThread.
	 */
	void Run() override;
	void OnWaitForStop() override;
	void OnSignalStop() override;
	void OnKill() override;

	/**
	 * Method for child classes to override to provide file location
	 * information in log messages. This is primarily used by the input
	 * framework's ReaderBackend classes to give more descriptive error
	 * messages.
	 *
	 * @return A Location pointer containing the file location information,
	 * or nullptr if nothing is available.
	 */
	virtual const zeek::detail::Location* GetLocationInfo() const { return nullptr; }

private:
	/**
	 * Pops a message sent by the main thread from the main-to-chold
	 * queue.
	 *
	 * Must only be called by the child thread.
	 *
	 * @return The message, wth ownership passed to caller. Returns null
	 * if the queue is empty.
	 */
	BasicInputMessage* RetrieveIn();

	/**
	 * Queues a message for the child.
	 *
	 * Must only be called by the main thread.
	 *
	 * @param msg  The message.
	 *
	 * @param force: If true, the message will be queued even when we're already
	 * Terminating(). Normally, the message would be discarded in that
	 * case.
	 */
	void SendIn(BasicInputMessage* msg, bool force);

	/**
	 * Queues a message for the main thread.
	 *
	 * Must only be called by the child thread.
	 *
	 * @param msg  The message.
	 *
	 * @param force: If true, the message will be queued even when we're already
	 * Terminating(). Normally, the message would be discarded in that
	 * case.
	 */
	void SendOut(BasicOutputMessage* msg, bool force);

	/**
	 * Returns true if there's at least one message pending for the child
	 * thread.
	 */
	bool HasIn() { return queue_in.Ready(); }

	/**
	 * Returns true if there's at least one message pending for the main
	 * thread.
	 */
	bool HasOut() { return queue_out.Ready(); }

	/**
	 * Returns true if there might be at least one message pending for
	 * the main thread. This function may occasionally return a value not
	 * indicating the actual state, but won't do so very often.
	 */
	bool MightHaveOut() { return queue_out.MaybeReady(); }

	/** Sends a message to the main thread signaling that the child process
	 *  has finished processing. Called from child.
	 */
	void Finished();

	std::string BuildMsgWithLocation(const char* msg);

	Queue<BasicInputMessage*> queue_in;
	Queue<BasicOutputMessage*> queue_out;

	std::atomic<uint64_t> cnt_sent_in; // Counts message sent to child.
	std::atomic<uint64_t> cnt_sent_out; // Counts message sent by child.

	bool main_finished; // Main thread is finished, meaning child_finished propagated back through
	                    // message queue.
	bool child_finished; // Child thread is finished.
	bool child_sent_finish; // Child thread asked to be finished.
	bool failed; // Set to true when a command failed.

	zeek::detail::Flare flare;
	};

/**
 * Base class for all message between Zeek's main process and a MsgThread.
 */
class Message
	{
public:
	/**
	 * Destructor.
	 */
	virtual ~Message();

	/**
	 * Returns a descriptive name for the message's general type. This is
	 * what's passed into the constructor and used mainly for debugging
	 * purposes.
	 */
	const char* Name() const { return name; }

	/**
	 * Callback that must be overridden for processing a message.
	 */
	virtual bool Process() = 0; // Thread will be terminated if returngin false.

protected:
	/**
	 * Constructor.
	 *
	 * @param arg_name A descriptive name for the type of message. Used
	 * mainly for debugging purposes.
	 */
	explicit Message(const char* arg_name) { name = util::copy_string(arg_name); }

private:
	const char* name;
	};

/**
 * Base class for messages sent from Zeek's main thread to a child MsgThread.
 */
class BasicInputMessage : public Message
	{
protected:
	/**
	 * Constructor.
	 *
	 * @param name A descriptive name for the type of message. Used
	 * mainly for debugging purposes.
	 */
	explicit BasicInputMessage(const char* name) : Message(name) { }
	};

/**
 * Base class for messages sent from a child MsgThread to Zeek's main thread.
 */
class BasicOutputMessage : public Message
	{
protected:
	/**
	 * Constructor.
	 *
	 * @param name A descriptive name for the type of message. Used
	 * mainly for debugging purposes.
	 */
	explicit BasicOutputMessage(const char* name) : Message(name) { }
	};

/**
 * A parameterized InputMessage that stores a pointer to an argument object.
 * Normally, the objects will be used from the Process() callback.
 */
template <typename O> class InputMessage : public BasicInputMessage
	{
public:
	/**
	 * Returns the objects passed to the constructor.
	 */
	O* Object() const { return object; }

protected:
	/**
	 * Constructor.
	 *
	 * @param name: A descriptive name for the type of message. Used
	 * mainly for debugging purposes.
	 *
	 * @param arg_object: An object to store with the message.
	 */
	InputMessage(const char* name, O* arg_object) : BasicInputMessage(name) { object = arg_object; }

private:
	O* object;
	};

/**
 * A parameterized OutputMessage that stores a pointer to an argument object.
 * Normally, the objects will be used from the Process() callback.
 */
template <typename O> class OutputMessage : public BasicOutputMessage
	{
public:
	/**
	 * Returns the objects passed to the constructor.
	 */
	O* Object() const { return object; }

protected:
	/**
	 * Constructor.
	 *
	 * @param name A descriptive name for the type of message. Used
	 * mainly for debugging purposes.
	 *
	 * @param arg_object An object to store with the message.
	 */
	OutputMessage(const char* name, O* arg_object) : BasicOutputMessage(name)
		{
		object = arg_object;
		}

private:
	O* object;
	};

	} // namespace zeek::threading
