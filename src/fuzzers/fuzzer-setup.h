#pragma once

#include <unistd.h>
#include <cstdlib>

#include "zeek/Event.h"
#include "zeek/broker/Manager.h"
#include "zeek/file_analysis/Manager.h"
#include "zeek/session/Manager.h"
#include "zeek/zeek-setup.h"

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
	{
	auto zeekpath = getenv("ZEEKPATH");

	if ( ! zeekpath )
		{
		// Set up an expected script search path for use with OSS-Fuzz
		auto constexpr oss_fuzz_scripts = "oss-fuzz-zeek-scripts";
		auto fuzzer_path = zeek::util::detail::get_exe_path(*argv[0]);
		auto fuzzer_dir = zeek::util::SafeDirname(fuzzer_path).result;
		std::string fs = zeek::util::fmt("%s/%s", fuzzer_dir.data(), oss_fuzz_scripts);
		auto p = fs.data();
		auto oss_fuzz_zeekpath = zeek::util::fmt(".:%s:%s/policy:%s/site", p, p, p);

		if ( setenv("ZEEKPATH", oss_fuzz_zeekpath, true) == -1 )
			abort();
		}

	zeek::Options options;
	options.scripts_to_load.emplace_back("local.zeek");
	options.script_options_to_set.emplace_back("Site::local_nets={10.0.0.0/8}");
	options.script_options_to_set.emplace_back("Log::default_writer=Log::WRITER_NONE");
	options.script_options_to_set.emplace_back("Reporter::info_to_stderr=F");
	options.script_options_to_set.emplace_back("Reporter::warnings_to_stderr=F");
	options.script_options_to_set.emplace_back("Reporter::errors_to_stderr=F");
	options.deterministic_mode = true;
	options.ignore_checksums = true;
	options.abort_on_scripting_errors = true;

	if ( zeek::detail::setup(*argc, *argv, &options).code )
		abort();

	return 0;
	}

namespace zeek::detail
	{

void fuzzer_cleanup_one_input()
	{
	run_state::terminating = true;
	broker_mgr->ClearStores();
	file_mgr->Terminate();
	timer_mgr->Expire();

	zeek::event_mgr.Drain();
	zeek::session_mgr->Drain();
	zeek::event_mgr.Drain();
	zeek::session_mgr->Clear();
	run_state::terminating = false;
	}

	} // namespace zeek::detail
