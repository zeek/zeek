
#include <sys/signal.h>
#include <signal.h>

#include "config.h"
#include "BasicThread.h"
#include "Manager.h"

#ifdef HAVE_LINUX
#include <sys/prctl.h>
#endif

using namespace threading;

uint64_t BasicThread::thread_counter = 0;

BasicThread::BasicThread()
	{
	started = false;
	terminating = false;
	pthread = 0;

	buf_len = 2048;
	buf = (char*) malloc(buf_len);

	name = Fmt("thread-%d", ++thread_counter);

	thread_mgr->AddThread(this);
	}

BasicThread::~BasicThread()
	{
        if ( buf )
		free(buf);
	}

void BasicThread::SetName(const string& arg_name)
	{
	// Slight race condition here with reader threads, but shouldn't matter.
	name = arg_name;
	}

void BasicThread::SetOSName(const string& name)
	{
#ifdef HAVE_LINUX
	prctl(PR_SET_NAME, name.c_str(), 0, 0, 0);
#endif

#ifdef __APPLE__
	pthread_setname_np(name.c_str());
#endif

#ifdef FREEBSD
	pthread_set_name_np(pthread_self(), name, name.c_str());
#endif
	}

const char* BasicThread::Fmt(const char* format, ...)
	{
	va_list al;
	va_start(al, format);
	int n = safe_vsnprintf(buf, buf_len, format, al);
	va_end(al);

	if ( (unsigned int) n >= buf_len )
		{ // Not enough room, grow the buffer.
		int tmp_len = n + 32;
		char* tmp = (char*) malloc(tmp_len);

		// Is it portable to restart?
		va_start(al, format);
		n = safe_vsnprintf(tmp, tmp_len, format, al);
		va_end(al);

		free(tmp);
		}

	return buf;
	}

const char* BasicThread::Strerror(int err)
	{
	static char buf[128] = "<not set>";
	strerror_r(err, buf, sizeof(buf));
	return buf;
	}

void BasicThread::Start()
	{
	if ( started )
		return;

	started = true;

	int err = pthread_create(&pthread, 0, BasicThread::launcher, this);
	if ( err != 0 )
		reporter->FatalError("Cannot create thread %s:%s", name.c_str(), Strerror(err));

	DBG_LOG(DBG_THREADING, "Started thread %s", name.c_str());

	OnStart();
	}

void BasicThread::Stop()
	{
	if ( ! started )
		return;

	if ( terminating )
		return;

	DBG_LOG(DBG_THREADING, "Signaling thread %s to terminate ...", name.c_str());

	terminating = true;

	OnStop();
	}

void BasicThread::Join()
	{
	if ( ! started )
		return;

	assert(terminating);

	DBG_LOG(DBG_THREADING, "Joining thread %s ...", name.c_str());

	if ( pthread && pthread_join(pthread, 0) != 0  )
		reporter->FatalError("Failure joining thread %s", name.c_str());

	DBG_LOG(DBG_THREADING, "Done with thread %s", name.c_str());

	pthread = 0;
	}

void BasicThread::Kill()
	{
	terminating = true;

	if ( ! (started && pthread) )
		return;

	pthread = 0;
	pthread_kill(pthread, SIGTERM);
	}

void* BasicThread::launcher(void *arg)
	{
	BasicThread* thread = (BasicThread *)arg;

	// Block signals in thread. We handle signals only in the main
	// process.
	sigset_t mask_set;
	sigfillset(&mask_set);

	// Unblock the signals where according to POSIX the result is undefined if they are blocked
	// in a thread and received by that thread. If those are not unblocked, threads will just
	// hang when they crash without the user being notified.
	sigdelset(&mask_set, SIGFPE);
	sigdelset(&mask_set, SIGILL);
	sigdelset(&mask_set, SIGSEGV);
	sigdelset(&mask_set, SIGBUS);
	int res = pthread_sigmask(SIG_BLOCK, &mask_set, 0);
	assert(res == 0);  //

	// Run thread's main function.
	thread->Run();

	return 0;
	}

