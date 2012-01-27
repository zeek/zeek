
#ifndef THREADING_BASICTHREAD_H
#define THREADING_BASICTHREAD_H

#include <pthread.h>
#include <semaphore.h>

#include "Queue.h"
#include "util.h"

using namespace std;

namespace threading {

class Manager;

class BasicThread
{
public:
	BasicThread(const string& name); // Managed by manager, must not delete otherwise.
	virtual ~BasicThread();

	const string& Name() const { return name; }

	void Start(); // Spawns the thread and enters Run().
	void Stop();  // Signals the thread to terminate.

	bool Terminating()  const { return terminating; }

	// A thread-safe version of fmt().
	const char* Fmt(const char* format, ...);

protected:
	virtual void Run() = 0;

	virtual void OnStart()	{}
	virtual void OnStop()	{}

private:
	friend class Manager;

	static void* launcher(void *arg);

	// Used from the ThreadMgr.
	void Join();	// Waits until the thread has terminated and then joins it.

	bool started; 		// Set to to true once running.
	bool terminating;	// Set to to true to signal termination.
	string name;

	pthread_t pthread;
	sem_t terminate;

	// For implementing Fmt().
	char* buf;
	unsigned int buf_len;
};

}

extern threading::Manager* thread_mgr;

#endif
