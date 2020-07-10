// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"
#include "zeek-setup.h"

#include "iosource/Manager.h"
#include "supervisor/Supervisor.h"
#include "Net.h"

int main(int argc, char** argv)
	{
	auto time_start = current_time(true);
	auto setup_result = zeek::detail::setup(argc, argv);

	if ( setup_result.code )
		return setup_result.code;

	auto& options = setup_result.options;
	auto do_net_run = iosource_mgr->Size() > 0 ||
	                  have_pending_timers ||
	                  zeek::BifConst::exit_only_after_terminate;

	if ( do_net_run )
		{
		if ( profiling_logger )
			profiling_logger->Log();

#ifdef USE_PERFTOOLS_DEBUG
		if ( perftools_leaks )
			heap_checker = new HeapLeakChecker("net_run");

		if ( perftools_profile )
			{
			HeapProfilerStart("heap");
			HeapProfilerDump("pre net_run");
			}

#endif

		if ( zeek::Supervisor::ThisNode() )
			timer_mgr->Add(new zeek::detail::ParentProcessCheckTimer(1, 1));

		double time_net_start = current_time(true);;

		uint64_t mem_net_start_total;
		uint64_t mem_net_start_malloced;

		if ( options.print_execution_time )
			{
			get_memory_usage(&mem_net_start_total, &mem_net_start_malloced);

			fprintf(stderr, "# initialization %.6f\n", time_net_start - time_start);

			fprintf(stderr, "# initialization %" PRIu64 "M/%" PRIu64 "M\n",
				mem_net_start_total / 1024 / 1024,
				mem_net_start_malloced / 1024 / 1024);
			}

		net_run();

		double time_net_done = current_time(true);;

		uint64_t mem_net_done_total;
		uint64_t mem_net_done_malloced;

		if ( options.print_execution_time )
			{
			get_memory_usage(&mem_net_done_total, &mem_net_done_malloced);

			fprintf(stderr, "# total time %.6f, processing %.6f\n",
				time_net_done - time_start, time_net_done - time_net_start);

			fprintf(stderr, "# total mem %" PRId64 "M/%" PRId64 "M, processing %" PRId64 "M/%" PRId64 "M\n",
				mem_net_done_total / 1024 / 1024,
				mem_net_done_malloced / 1024 / 1024,
				(mem_net_done_total - mem_net_start_total) / 1024 / 1024,
				(mem_net_done_malloced - mem_net_start_malloced) / 1024 / 1024);
			}
		}

	return zeek::detail::cleanup(do_net_run);
	}
