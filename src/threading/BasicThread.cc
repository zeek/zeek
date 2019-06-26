
#include <signal.h>

#include "zeek-config.h"
#include "BasicThread.h"
#include "Manager.h"
#include "pthread.h"

#ifdef HAVE_LINUX
#include <sys/prctl.h>
#endif

#ifdef __FreeBSD__
#include <pthread_np.h>
#endif

using namespace threading;

static const int STD_FMT_BUF_LEN = 2048;

uint64_t BasicThread::thread_counter = 0;

BasicThread::BasicThread()
	{
	started = false;
	terminating = false;
	killed = false;

	buf_len = STD_FMT_BUF_LEN;
	buf = (char*) safe_malloc(buf_len);

	strerr_buffer = 0;

	name = copy_string(fmt("thread-%" PRIu64, ++thread_counter));

	thread_mgr->AddThread(this);
	}

BasicThread::~BasicThread()
	{
	if ( buf )
		free(buf);

	delete [] name;
	delete [] strerr_buffer;
	}

void BasicThread::SetName(const char* arg_name)
	{
	delete [] name;
	name = copy_string(arg_name);
	}

void BasicThread::SetOSName(const char* arg_name)
	{
	static_assert(std::is_same<std::thread::native_handle_type, pthread_t>::value, "libstdc++ doesn't use pthread_t");

#ifdef HAVE_LINUX
	prctl(PR_SET_NAME, arg_name, 0, 0, 0);
#endif

#ifdef __APPLE__
	pthread_setname_np(arg_name);
#endif

#ifdef __FreeBSD__
	pthread_set_name_np(thread.native_handle(), arg_name);
#endif
	}

const char* BasicThread::Fmt(const char* format, ...)
	{
	if ( buf_len > 10 * STD_FMT_BUF_LEN )
		{
		// Shrink back to normal.
		buf = (char*) safe_realloc(buf, STD_FMT_BUF_LEN);
		buf_len = STD_FMT_BUF_LEN;
		}

	va_list al;
	va_start(al, format);
	int n = safe_vsnprintf(buf, buf_len, format, al);
	va_end(al);

	if ( (unsigned int) n >= buf_len )
		{ // Not enough room, grow the buffer.
		buf_len = n + 32;
		buf = (char*) safe_realloc(buf, buf_len);

		// Is it portable to restart?
		va_start(al, format);
		n = safe_vsnprintf(buf, buf_len, format, al);
		va_end(al);
		}

	return buf;
	}

const char* BasicThread::Strerror(int err)
	{
	if ( ! strerr_buffer )
		strerr_buffer = new char[256];

	bro_strerror_r(err, strerr_buffer, 256);
	return strerr_buffer;
	}

void BasicThread::Start()
	{
	if ( started )
		return;

	started = true;

	thread = std::thread(&BasicThread::launcher, this);

	DBG_LOG(DBG_THREADING, "Started thread %s", name);

	OnStart();
	}

void BasicThread::SignalStop()
	{
	if ( ! started )
		return;

	if ( terminating )
		return;

	DBG_LOG(DBG_THREADING, "Signaling thread %s to terminate ...", name);

	OnSignalStop();
	}

void BasicThread::WaitForStop()
	{
	if ( ! started )
		return;

	DBG_LOG(DBG_THREADING, "Waiting for thread %s to terminate and process last queue items...", name);

	OnWaitForStop();

	terminating = true;
	}

void BasicThread::Join()
	{
	if ( ! started )
		return;

	if ( ! thread.joinable() )
		return;

	assert(terminating);

	try
		{
		thread.join();
		}
	catch ( const std::system_error& e )
		{
		reporter->FatalError("Failure joining thread %s with error %s", name, e.what());
		}

	DBG_LOG(DBG_THREADING, "Joined with thread %s", name);
	}

void BasicThread::Kill()
	{
	// We don't *really* kill the thread here because that leads to race
	// conditions. Instead we set a flag that parts of the the code need
	// to check and get out of any loops they might be in.
	terminating = true;
	killed = true;
	OnKill();
	}

void BasicThread::Done()
	{
	DBG_LOG(DBG_THREADING, "Thread %s has finished", name);

	terminating = true;
	killed = true;
	}

void* BasicThread::launcher(void *arg)
	{
	static_assert(std::is_same<std::thread::native_handle_type, pthread_t>::value, "libstdc++ doesn't use pthread_t");
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
	assert(res == 0);

	// Run thread's main function.
	thread->Run();

	thread->Done();

	return 0;
	}
