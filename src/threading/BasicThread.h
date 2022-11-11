
#pragma once

#include "zeek/zeek-config.h"

#include <atomic>
#include <cstdint>
#include <iosfwd>
#include <thread>

namespace zeek::threading
	{

class Manager;

/**
 * Base class for all threads.
 *
 * This class encapsulates all the OS-level thread handling. All thread
 * instances are automatically added to the threading::Manager for management. The
 * manager also takes care of deleting them (which must not be done
 * manually).
 */
class BasicThread
	{
public:
	/**
	 * Creates a new thread object. Instantiating the object does however
	 * not yet start the actual OS thread, that requires calling Start().
	 *
	 * Only Zeek's main thread may create new thread instances.
	 *
	 * @param name A descriptive name for thread the thread. This may
	 * show up in messages to the user.
	 */
	BasicThread();

	BasicThread(BasicThread const&) = delete;
	BasicThread& operator=(BasicThread const&) = delete;

	/**
	 * Returns a descriptive name for the thread. If not set via
	 * SetName(), a default name is chosen automatically.
	 *
	 * This method is safe to call from any thread.
	 */
	const char* Name() const { return name; }

	/**
	 * Sets a descriptive name for the thread. This should be a string
	 * that's useful in output presented to the user and uniquely
	 * identifies the thread.
	 *
	 * This method must be called only from main thread at initialization
	 * time.
	 */
	void SetName(const char* name);

	/**
	 * Set the name shown by the OS as the thread's description. Not
	 * supported on all OSs.
	 *
	 * Must be called only from the child thread.
	 */
	void SetOSName(const char* name);

	/**
	 * Starts the thread. Calling this methods will spawn a new OS thread
	 * executing Run(). Note that one can't restart a thread after a
	 * Stop(), doing so will be ignored.
	 *
	 * Only Zeek's main thread must call this method.
	 */
	void Start();

	/**
	 * Signals the thread to prepare for stopping, but doesn't block to
	 * wait for that to happen. Use WaitForStop() for that.
	 *
	 * The method lets Terminating() now return true, it does however not
	 * force the thread to terminate. It's up to the Run() method to to
	 * query Terminating() and exit eventually.
	 *
	 * Calling this method has no effect if Start() hasn't been executed
	 * yet.
	 *
	 * Only Zeek's main thread must call this method.
	 */
	void SignalStop();

	/**
	 * Waits until a thread has stopped after receiving SignalStop().
	 *
	 * Calling this method has no effect if Start() hasn't been executed
	 * yet. If this is executed without calling SignalStop() first,
	 * results are undefined.
	 *
	 * Only Zeek's main thread must call this method.
	 */
	void WaitForStop();

	/**
	 * Returns true if WaitForStop() has been called and finished.
	 *
	 * This method is safe to call from any thread.
	 */
	bool Terminating() const { return terminating; }

	/**
	 * Returns true if Kill() has been called.
	 *
	 * This method is safe to call from any thread.
	 */
	bool Killed() const { return killed; }

	/**
	 * A version of zeek::util::fmt() that the thread can safely use.
	 *
	 * This is safe to call from Run() but must not be used from any
	 * other thread than the current one.
	 */
	const char* Fmt(const char* format, ...) __attribute__((format(printf, 2, 3)));
	;

	/**
	 * A version of strerror() that the thread can safely use. This is
	 * essentially a wrapper around strerror_r(). Note that it keeps a
	 * single buffer per thread internally so the result remains valid
	 * only until the next call.
	 */
	const char* Strerror(int err);

protected:
	friend class Manager;

	/**
	 * Entry point for the thread. This must be overridden by derived
	 * classes and will execute in a separate thread once Start() is
	 * called. The thread will not terminate before this method finishes.
	 * An implementation should regularly check Terminating() to see if
	 * exiting has been requested.
	 */
	virtual void Run() = 0;

	/**
	 * Executed with Start(). This is a hook into starting the thread. It
	 * will be called from Zeek's main thread after the OS thread has been
	 * started.
	 */
	virtual void OnStart() { }

	/**
	 * Executed with SignalStop(). This is a hook into preparing the
	 * thread for stopping. It will be called from Zeek's main thread
	 * before the thread has been signaled to stop.
	 */
	virtual void OnSignalStop() { }

	/**
	 * Executed with WaitForStop(). This is a hook into waiting for the
	 * thread to stop. It must be overridden by derived classes and only
	 * return once the thread has indeed finished processing. The method
	 * will be called from Zeek's main thread.
	 */
	virtual void OnWaitForStop() = 0;

	/**
	 * Executed with Kill(). This is a hook into killing the thread.
	 */
	virtual void OnKill() { }

	/**
	 * Destructor. This will be called by the manager.
	 *
	 * Only Zeek's main thread may delete thread instances.
	 *
	 */
	virtual ~BasicThread();

	/**
	 * Waits until the thread's Run() method has finished and then joins
	 * it. This is called from the threading::Manager.
	 */
	void Join();

	/**
	 * Kills the thread immediately. One still needs to call Join()
	 * afterwards.
	 *
	 * This is called from the threading::Manager and safe to execute
	 * during a signal handler.
	 */
	void Kill();

	/** Called by child thread's launcher when it's done processing. */
	ZEEK_DISABLE_TSAN void Done();

private:
	// thread entry function.
	static void* launcher(void* arg);

	const char* name;
	std::thread thread;
	bool started; // Set to to true once running.
	std::atomic_bool terminating; // Set to to true to signal termination.
	std::atomic_bool killed; // Set to true once forcefully killed.

	// For implementing Fmt().
	uint32_t buf_len;
	char* buf;

	// For implementing Strerror().
	char* strerr_buffer;

	static uint64_t thread_counter;
	};

	} // namespace zeek::threading
