// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <unistd.h>
#include <cstdlib>

#include "zeek/Event.h"
#include "zeek/EventRegistry.h"
#include "zeek/Options.h"
#include "zeek/broker/Manager.h"
#include "zeek/file_analysis/Manager.h"
#include "zeek/session/Manager.h"
#include "zeek/zeek-setup.h"

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv) {
    auto zeekpath = getenv("ZEEKPATH");

    if ( ! zeekpath ) {
        // Set up an expected script search path for use with OSS-Fuzz
        auto constexpr oss_fuzz_scripts = "oss-fuzz-zeek-scripts";
        auto fuzzer_path = zeek::util::detail::get_exe_path(*argv[0]);
        auto fuzzer_dir = zeek::util::SafeDirname(fuzzer_path).result;
        std::string fs = zeek::util::fmt("%s/%s", fuzzer_dir.data(), oss_fuzz_scripts);
        auto p = fs.data();
        auto oss_fuzz_zeekpath = zeek::util::fmt(".:%s:%s/policy:%s/site:%s/builtin-plugins", p, p, p, p);

        if ( setenv("ZEEKPATH", oss_fuzz_zeekpath, true) == -1 )
            abort();
    }

    int zeek_args = 0;
    char** zeek_argv = &((*argv)[*argc]);

    // If the inputs given to the fuzzer executable contain "--", consider all
    // following arguments to be part of Zeek's command-line and forward them to
    // zeek::parse_cmdline().
    //
    // This allows to load more scripts and set or overwrite options without
    // the need to recompile the fuzzer.
    for ( int i = 0; i < *argc; i++ ) {
        if ( ! strcmp((*argv)[i], "--") ) {
            zeek_args = *argc - i;
            (*argv)[i] = (*argv)[0]; // Fake argv[0] for parse_cmdline() with the original argv[0]
            zeek_argv = &(*argv)[i];
        }
    }

    // Propagate change in argc upwards.
    *argc = *argc - zeek_args;

    zeek::Options options = zeek_args > 0 ? zeek::parse_cmdline(zeek_args, zeek_argv) : zeek::Options{};

    std::vector<std::string> default_script_options_to_set = {
        "Site::local_nets={10.0.0.0/8}",  "Log::default_writer=Log::WRITER_NONE", "Reporter::info_to_stderr=F",
        "Reporter::warnings_to_stderr=F", "Reporter::errors_to_stderr=F",
    };

    // Prepend default options.
    options.script_options_to_set.insert(options.script_options_to_set.begin(), default_script_options_to_set.begin(),
                                         default_script_options_to_set.end());
    options.scripts_to_load.emplace_back("local.zeek");
    options.deterministic_mode = true;
    options.ignore_checksums = true;
    options.abort_on_scripting_errors = true;
    options.dns_mode = zeek::detail::DNS_MgrMode::DNS_FAKE;

    if ( zeek::detail::setup(*argc, *argv, &options).code )
        abort();

    // We have to trick the event handlers into returning true that they exist here
    // even if they don't, because otherwise we lose a bit of coverage where if
    // statements return false that would otherwise not.
    zeek::event_registry->ActivateAllHandlers();
    zeek::event_registry->Lookup("new_event")->SetGenerateAlways(false);

    return 0;
}

namespace zeek::detail {

void fuzzer_cleanup_one_input() {
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
