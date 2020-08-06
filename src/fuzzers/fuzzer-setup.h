#pragma once

#include <unistd.h>
#include <cstdlib>

#include "zeek-setup.h"

#include "Event.h"
#include "Sessions.h"
#include "broker/Manager.h"
#include "file_analysis/Manager.h"

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
	{
	auto zeekpath = getenv("ZEEKPATH");

	if ( ! zeekpath )
		{
		// Set up an expected script search path for use with OSS-Fuzz
		auto constexpr oss_fuzz_scripts = "oss-fuzz-zeek-scripts";
		auto fuzzer_path = get_exe_path(*argv[0]);
		auto fuzzer_dir = SafeDirname(fuzzer_path).result;
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

namespace zeek { namespace detail {

void fuzzer_cleanup_one_input()
	{
	terminating = true;
	broker_mgr->ClearStores();
	file_mgr->Terminate();
	timer_mgr->Expire();

	zeek::event_mgr.Drain();
	sessions->Drain();
	zeek::event_mgr.Drain();
	sessions->Clear();
	terminating = false;
	}

}} // namespace zeek::detail
