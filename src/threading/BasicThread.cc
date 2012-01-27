
#include <sys/signal.h>
#include <signal.h>

#include "BasicThread.h"
#include "Manager.h"

using namespace threading;

BasicThread::BasicThread(const string& arg_name)
	{
	started = false;
	terminating = false;
	pthread = 0;

	buf = 0;
	buf_len = 1024;

	char tmp[128];
	snprintf(tmp, sizeof(tmp), "%s@%p", arg_name.c_str(), this);
	name = string(tmp);

	thread_mgr->AddThread(this);
	}

BasicThread::~BasicThread()
	{
	}

const char* BasicThread::Fmt(const char* format, ...)
	{
	if ( ! buf )
		buf = (char*) malloc(buf_len);

	va_list al;
	va_start(al, format);
	int n = safe_vsnprintf(buf, buf_len, format, al);
	va_end(al);

	if ( (unsigned int) n >= buf_len )
		{ // Not enough room, grow the buffer.
		buf_len = n + 32;
		buf = (char*) realloc(buf, buf_len);

		// Is it portable to restart?
		va_start(al, format);
		n = safe_vsnprintf(buf, buf_len, format, al);
		va_end(al);
		}

	return buf;
	}

void BasicThread::Start()
	{
	if ( sem_init(&terminate, 0, 0) != 0  )
		reporter->FatalError("Cannot create terminate semaphore for thread %s", name.c_str());

	if ( pthread_create(&pthread, 0, BasicThread::launcher, this) != 0 )
		reporter->FatalError("Cannot create thread %s", name.c_str());

	DBG_LOG(DBG_THREADING, "Started thread %s", name.c_str());

	started = true;

	OnStart();
	}

void BasicThread::Stop()
	{
	if ( ! started )
		return;

	if ( terminating )
		return;

	DBG_LOG(DBG_THREADING, "Signaling thread %s to terminate ...", name.c_str());

	// Signal that it's ok for the thread to exit now.
	if ( sem_post(&terminate) != 0 )
		reporter->FatalError("Failure flagging terminate condition for thread %s", name.c_str());

	terminating = true;

	OnStop();
	}

void BasicThread::Join()
	{
	if ( ! started )
		return;

	if ( ! terminating )
		Stop();

	DBG_LOG(DBG_THREADING, "Joining thread %s ...", name.c_str());

	if ( pthread_join(pthread, 0) != 0  )
		reporter->FatalError("Failure joining thread %s", name.c_str());

	sem_destroy(&terminate);

	DBG_LOG(DBG_THREADING, "Done with thread %s", name.c_str());

	pthread = 0;
	}

void* BasicThread::launcher(void *arg)
	{
	BasicThread* thread = (BasicThread *)arg;

	// Block signals in thread. We handle signals only in the main
	// process.
	sigset_t mask_set;
	sigfillset(&mask_set);
	int res = pthread_sigmask(SIG_BLOCK, &mask_set, 0);
	assert(res == 0);  //

	// Run thread's main function.
	thread->Run();

	// Wait until somebody actually wants us to terminate.

	if ( sem_wait(&thread->terminate) != 0 )
		reporter->FatalError("Failure flagging terminate condition for thread %s", thread->Name().c_str());

	return 0;
	}

