
#include <sys/wait.h>
#include <signal.h>

#include "Supervisor.h"
#include "Reporter.h"
#include "DebugLogger.h"
#include "zeek-config.h"
#include "util.h"

extern "C" {
#include "setsignal.h"
}

static RETSIGTYPE supervisor_sig_handler(int signo)
	{
	DBG_LOG(DBG_SUPERVISOR, "received SIGCHLD signal: %d", signo);
	zeek::supervisor->ObserveChildSignal();
	return RETSIGVAL;
	}

zeek::Supervisor::Supervisor(zeek::Supervisor::Config cfg,
							 std::unique_ptr<bro::Pipe> pipe,
                             pid_t arg_stem_pid)
	: config(std::move(cfg)), stem_pid(arg_stem_pid), stem_pipe(std::move(pipe))
	{
	DBG_LOG(DBG_SUPERVISOR, "forked stem process %d", stem_pid);
	DBG_LOG(DBG_SUPERVISOR, "using %d workers", config.num_workers);
	setsignal(SIGCHLD, supervisor_sig_handler);
	SetIdle(true);
	}

void zeek::Supervisor::ObserveChildSignal()
	{
	signal_flare.Fire();
	}

zeek::Supervisor::~Supervisor()
	{
	if ( ! stem_pid )
		{
		DBG_LOG(DBG_SUPERVISOR, "shutdown, stem process already exited");
		return;
		}

	DBG_LOG(DBG_SUPERVISOR, "shutdown, killing stem process %d", stem_pid);

	// TODO: is signal the best way to trigger shutdown of decendent processes?
	auto kill_res = kill(stem_pid, SIGTERM);

	if ( kill_res == -1 )
		{
		char tmp[256];
		bro_strerror_r(errno, tmp, sizeof(tmp));
		reporter->Error("Failed to send SIGTERM to stem process: %s", tmp);
		}
	else
		{
		int status;
		auto wait_res = waitpid(stem_pid, &status, 0);

		if ( wait_res == -1 )
			{
			char tmp[256];
			bro_strerror_r(errno, tmp, sizeof(tmp));
			reporter->Error("Failed to wait for stem process to exit: %s", tmp);
			}
		}
	}

void zeek::Supervisor::GetFds(iosource::FD_Set* read, iosource::FD_Set* write,
                              iosource::FD_Set* except)
	{
	read->Insert(signal_flare.FD());
	read->Insert(stem_pipe->ReadFD());
	}

double zeek::Supervisor::NextTimestamp(double* local_network_time)
	{
	// We're only asked for a timestamp if either (1) a FD was ready
	// or (2) we're not idle (and we go idle if when Process is no-op),
	// so there's no case where returning -1 to signify a skip will help.
	return timer_mgr->Time();
	}

void zeek::Supervisor::Process()
	{
	auto child_signals = signal_flare.Extinguish();

	DBG_LOG(DBG_SUPERVISOR, "process: child_signals %d, stem_pid %d",
		    child_signals, stem_pid);

	if ( child_signals && stem_pid )
		{
		DBG_LOG(DBG_SUPERVISOR, "handle child signal, wait for %d", stem_pid);
		int status;
		auto res = waitpid(stem_pid, &status, WNOHANG);

		if ( res == 0 )
			{
			DBG_LOG(DBG_SUPERVISOR, "false alarm, stem process still lives");
			}
		else if ( res == -1 )
			{
			char tmp[256];
			bro_strerror_r(errno, tmp, sizeof(tmp));
			reporter->Error("Supervisor failed to get exit status"
			                " of stem process: %s", tmp);
			}
		else if ( WIFEXITED(status) )
			{
			DBG_LOG(DBG_SUPERVISOR, "stem process exited with status %d",
			        WEXITSTATUS(status));
			stem_pid = 0;
			}
		else if ( WIFSIGNALED(status) )
			{
			DBG_LOG(DBG_SUPERVISOR, "stem process terminated by signal %d",
			        WTERMSIG(status));
			stem_pid = 0;
			}
		else
			{
			reporter->Error("Supervisor failed to get exit status"
			                " of stem process for unknown reason");
			}

		// TODO: add proper handling of stem process exiting
		// In wait cases is it ok for the stem process to terminate and
		// in what cases do we need to automatically re-recreate it ?
		// And how do we re-create it?  It would be too late to fork() again
		// because we've potentially already changed so much global state by the
		// time we get there, so guess we exec() and start over completely ?.
		}
	}
