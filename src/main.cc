// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/zeek-config.h"

#include <unistd.h>

#include "zeek/RunState.h"
#include "zeek/iosource/Manager.h"
#include "zeek/supervisor/Supervisor.h"
#include "zeek/zeek-setup.h"

#ifdef _MSC_VER
#include <fcntl.h> // For _O_BINARY.

// By default, Windows only looks in the System32 directory for dlls. Npcap installs
// into System32\Npcap, so we have to add that path to the search path for DLLs or
// the process won't find it. This is annoying, but it's how the Npcap project
// recommends we do it. See https://npcap.com/guide/npcap-devguide.html#npcap-feature-native
// for further info.
static void init_npcap_dll_path()
	{
#ifdef HAVE_WPCAP
	BOOL(WINAPI * SetDllDirectory)(LPCTSTR);
	char sysdir_name[512];
	int len;

	SetDllDirectory = (BOOL(WINAPI*)(LPCTSTR))GetProcAddress(GetModuleHandle("kernel32.dll"),
	                                                         "SetDllDirectoryA");
	if ( SetDllDirectory == NULL )
		{
		fprintf(stderr, "Error in SetDllDirectory");
		}
	else
		{
		len = GetSystemDirectory(sysdir_name, 480); //	be safe
		if ( ! len )
			fprintf(stderr, "Error in GetSystemDirectory (%d)", GetLastError());
		strcat(sysdir_name, "\\Npcap");
		if ( SetDllDirectory(sysdir_name) == 0 )
			fprintf(stderr, "Error in SetDllDirectory(\"System32\\Npcap\")");
		}
#endif
	}

#endif

int main(int argc, char** argv)
	{
#ifdef _MSC_VER
	_setmode(_fileno(stdout), _O_BINARY);
	_setmode(_fileno(stderr), _O_BINARY);

	init_npcap_dll_path();
#endif

	auto time_start = zeek::util::current_time(true);
	auto setup_result = zeek::detail::setup(argc, argv);

	if ( setup_result.code )
		return setup_result.code;

	auto& options = setup_result.options;
	auto do_run_loop = zeek::iosource_mgr->Size() > 0 ||
	                   zeek::run_state::detail::have_pending_timers ||
	                   zeek::BifConst::exit_only_after_terminate;

	if ( do_run_loop )
		{
		if ( zeek::detail::profiling_logger )
			zeek::detail::profiling_logger->Log();

#ifdef USE_PERFTOOLS_DEBUG
		if ( options.perftools_check_leaks )
			heap_checker = new HeapLeakChecker("net_run");

		if ( options.perftools_profile )
			{
			HeapProfilerStart("heap");
			HeapProfilerDump("pre net_run");
			}

#endif

		if ( zeek::Supervisor::ThisNode() )
			zeek::detail::timer_mgr->Add(new zeek::detail::ParentProcessCheckTimer(1, 1));

		double time_net_start = zeek::util::current_time(true);

		uint64_t mem_net_start_total;
		uint64_t mem_net_start_malloced;

		if ( options.print_execution_time )
			{
			zeek::util::get_memory_usage(&mem_net_start_total, &mem_net_start_malloced);

			fprintf(stderr, "# initialization %.6f\n", time_net_start - time_start);

			fprintf(stderr, "# initialization %" PRIu64 "M/%" PRIu64 "M\n",
			        mem_net_start_total / 1024 / 1024, mem_net_start_malloced / 1024 / 1024);
			}

		zeek::run_state::detail::run_loop();

		double time_net_done = zeek::util::current_time(true);

		uint64_t mem_net_done_total;
		uint64_t mem_net_done_malloced;

		if ( options.print_execution_time )
			{
			zeek::util::get_memory_usage(&mem_net_done_total, &mem_net_done_malloced);

			fprintf(stderr, "# total time %.6f, processing %.6f\n", time_net_done - time_start,
			        time_net_done - time_net_start);

			fprintf(stderr,
			        "# total mem %" PRId64 "M/%" PRId64 "M, processing %" PRId64 "M/%" PRId64 "M\n",
			        mem_net_done_total / 1024 / 1024, mem_net_done_malloced / 1024 / 1024,
			        (mem_net_done_total - mem_net_start_total) / 1024 / 1024,
			        (mem_net_done_malloced - mem_net_start_malloced) / 1024 / 1024);
			}
		}

	return zeek::detail::cleanup(do_run_loop);
	}
