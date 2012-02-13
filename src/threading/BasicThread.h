
#ifndef THREADING_BASICTHREAD_H
#define THREADING_BASICTHREAD_H

#include <pthread.h>
#include <semaphore.h>

#include "Queue.h"
#include "util.h"

using namespace std;

namespace threading {

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
	 * Only Bro's main thread may create new thread instances.
	 *
	 * @param name A descriptive name for thread the thread. This may
	 * show up in messages to the user.
	 */
	BasicThread();

	/**
	 * Returns a descriptive name for the thread. If not set via
	 * SetName(). If not set, a default name is choosen automatically.
	 *
	 * This method is safe to call from any thread.
	 */
	const string& Name() const { return name; }

	/**
	* Sets a descriptive name for the thread. This should be a string
	* that's useful in output presented to the user and uniquely
	* identifies the thread.
	*
	* This method must be called only from the thread itself.
	*/
	void SetName(const string& name);

	/**
	 * Set the name shown by the OS as the thread's description. Not
	 * supported on all OSs.
	 */
	void SetOSName(const string& name);

	/**
	 * Starts the thread. Calling this methods will spawn a new OS thread
	 * executing Run(). Note that one can't restart a thread after a
	 * Stop(), doing so will be ignored.
	 *
	 * Only Bro's main thread must call this method.
	 */
	void Start();

	/**
	 * Signals the thread to stop. The method lets Terminating() now
	 * return true. It does however not force the thread to terminate.
	 * It's up to the Run() method to to query Terminating() and exit
	 * eventually.
	 *
	 * Calling this method has no effect if Start() hasn't been executed
	 * yet.
	 *
	 * Only Bro's main thread must call this method.
	 */
	void Stop();

	/**
	 * Returns true if Stop() has been called.
	 *
	 * This method is safe to call from any thread.
	 */
	bool Terminating()  const { return terminating; }

	/**
	 * A version of fmt() that the thread can safely use.
	 *
	 * This is safe to call from Run() but must not be used from any
	 * other thread than the current one.
	 */
	const char* Fmt(const char* format, ...);

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
	 * will be called from Bro's main thread after the OS thread has been
	 * started.
	 */
	virtual void OnStart()	{}

	/**
	 * Executed with Stop(). This is a hook into stopping the thread. It
	 * will be called from Bro's main thread after the thread has been
	 * signaled to stop.
	 */
	virtual void OnStop()	{}

	/**
	 * Destructor. This will be called by the manager.
	 *
	 * Only Bro's main thread may delete thread instances.
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

private:
	// pthread entry function.
	static void* launcher(void *arg);

	string name;
	pthread_t pthread;
	bool started; 		// Set to to true once running.
	bool terminating;	// Set to to true to signal termination.

	// Used as a semaphore to tell the pthread thread when it may
	// terminate.
	pthread_mutex_t terminate;

	// For implementing Fmt().
	char* buf;
	unsigned int buf_len;

	static uint64_t thread_counter;
};

}

#endif
