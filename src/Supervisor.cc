
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>

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

void zeek::Supervisor::ObserveChildSignal()
	{
	signal_flare.Fire();
	}

void zeek::Supervisor::HandleChildSignal()
	{
	if ( ! stem_pid )
		return;

	auto child_signals = signal_flare.Extinguish();

	if ( ! child_signals )
		return;

	DBG_LOG(DBG_SUPERVISOR, "handle %d child signals, wait for stem pid %d",
	        child_signals, stem_pid);

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
		reporter->Error("Supervisor failed to get exit status"
			            " of stem process for unknown reason");

	if ( ! stem_pid )
		{
		// Revive the Stem process
		stem_pid = fork();

		if ( stem_pid == -1 )
			{
			char tmp[256];
			bro_strerror_r(errno, tmp, sizeof(tmp));
			reporter->Error("failed to fork Zeek supervisor stem process: %s\n", tmp);
			signal_flare.Fire();
			// Sleep to avoid spining too fast in a revival-fail loop.
			sleep(1);
			}
		else if ( stem_pid == 0 )
			{
			char stem_env[256];
			safe_snprintf(stem_env, sizeof(stem_env), "ZEEK_STEM=%d,%d",
			              stem_pipe->ReadFD(), stem_pipe->WriteFD());
			char* env[] = { stem_env, (char*)0 };
			stem_pipe->UnsetFlags(FD_CLOEXEC);
			auto res = execle(config.zeek_exe_path.data(),
			                  config.zeek_exe_path.data(),
			                  (char*)0, env);

			char tmp[256];
			bro_strerror_r(errno, tmp, sizeof(tmp));
			fprintf(stderr, "failed to exec Zeek supervisor stem process: %s\n", tmp);
			exit(1);
			}
		else
			{
			DBG_LOG(DBG_SUPERVISOR, "stem process revived, new pid: %d", stem_pid);
			}
		}

	// TODO: Stem process needs a way to inform Supervisor not to revive
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
	HandleChildSignal();

	char buf[256];
	int bytes_read = read(stem_pipe->ReadFD(), buf, 256);

	if ( bytes_read > 0 )
		{
		DBG_LOG(DBG_SUPERVISOR, "read msg from Stem: %.*s", bytes_read, buf);
		}
	}

void zeek::Supervisor::RunStem(std::unique_ptr<bro::Pipe> pipe)
	{
	zeek::set_thread_name("zeek-stem");
	// TODO: changing the process group here so that SIGINT to the
	// supervisor doesn't also get passed to the children.  i.e. supervisor
	// should be in charge of initiating orderly shutdown.  But calling
	// just setpgid() like this is technically a race-condition -- need
	// to do more work of blocking SIGINT before fork(), unblocking after,
	// then also calling setpgid() from parent.  And just not doing that
	// until more is known whether that's the right SIGINT behavior in
	// the first place.
	auto res = setpgid(0, 0);

	if ( res == -1 )
		fprintf(stderr, "failed to set stem process group: %s\n",
				strerror(errno));

	for ( ; ; )
		{
		// TODO: make a proper I/O loop w/ message processing via pipe
		// TODO: better way to detect loss of parent than polling

		if ( getppid() == 1 )
			exit(0);

		sleep(5);
		printf("Stem wakeup\n");
		write(pipe->WriteFD(), "hi", 2);
		}
	}
