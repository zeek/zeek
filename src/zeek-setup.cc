// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/zeek-setup.h"

#include "zeek/zeek-config.h"

#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <sys/types.h>
#include <unistd.h>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <list>
#include <optional>

#ifdef USE_SQLITE
#include "zeek/3rdparty/sqlite3.h"
#endif

#define DOCTEST_CONFIG_IMPLEMENT

#include "zeek/3rdparty/doctest.h"
#include "zeek/Anon.h"
#include "zeek/DFA.h"
#include "zeek/DNS_Mgr.h"
#include "zeek/Debug.h"
#include "zeek/Desc.h"
#include "zeek/Event.h"
#include "zeek/EventRegistry.h"
#include "zeek/EventTrace.h"
#include "zeek/File.h"
#include "zeek/Frag.h"
#include "zeek/Frame.h"
#include "zeek/Func.h"
#include "zeek/Hash.h"
#include "zeek/NetVar.h"
#include "zeek/Options.h"
#include "zeek/Reporter.h"
#include "zeek/RuleMatcher.h"
#include "zeek/RunState.h"
#include "zeek/ScannedFile.h"
#include "zeek/Scope.h"
#include "zeek/ScriptCoverageManager.h"
#include "zeek/Stats.h"
#include "zeek/Stmt.h"
#include "zeek/Tag.h"
#include "zeek/Timer.h"
#include "zeek/Traverse.h"
#include "zeek/Trigger.h"
#include "zeek/Var.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/binpac_zeek.h"
#include "zeek/broker/Manager.h"
#include "zeek/file_analysis/Manager.h"
#include "zeek/input.h"
#include "zeek/input/Manager.h"
#include "zeek/input/readers/raw/Raw.h"
#include "zeek/iosource/Manager.h"
#include "zeek/logging/Manager.h"
#include "zeek/module_util.h"
#include "zeek/packet_analysis/Manager.h"
#include "zeek/plugin/Manager.h"
#include "zeek/script_opt/ScriptOpt.h"
#include "zeek/session/Manager.h"
#ifdef HAVE_SPICY
#include "zeek/spicy/manager.h"
#endif
#include "zeek/supervisor/Supervisor.h"
#include "zeek/telemetry/Manager.h"
#include "zeek/threading/Manager.h"
#include "zeek/zeekygen/Manager.h"

extern "C" {
#include "zeek/3rdparty/setsignal.h"
};

zeek::detail::ScriptCoverageManager zeek::detail::script_coverage_mgr;

#ifndef HAVE_STRSEP
extern "C" {
char* strsep(char**, const char*);
};
#endif

#ifdef USE_PERFTOOLS_DEBUG
HeapLeakChecker* heap_checker = 0;
int perftools_leaks = 0;
int perftools_profile = 0;
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
struct CRYPTO_dynlock_value {
    std::mutex mtx;
};

namespace {

std::unique_ptr<std::mutex[]> ssl_mtx_tbl;

void ssl_lock_fn(int mode, int n, const char*, int) {
    if ( mode & CRYPTO_LOCK )
        ssl_mtx_tbl[static_cast<size_t>(n)].lock();
    else
        ssl_mtx_tbl[static_cast<size_t>(n)].unlock();
}

CRYPTO_dynlock_value* ssl_dynlock_create(const char*, int) { return new CRYPTO_dynlock_value; }

void ssl_dynlock_lock(int mode, CRYPTO_dynlock_value* ptr, const char*, int) {
    if ( mode & CRYPTO_LOCK )
        ptr->mtx.lock();
    else
        ptr->mtx.unlock();
}

void ssl_dynlock_destroy(CRYPTO_dynlock_value* ptr, const char*, int) { delete ptr; }

void do_ssl_init() {
    ERR_load_crypto_strings();
    OPENSSL_add_all_algorithms_conf();
    SSL_library_init();
    SSL_load_error_strings();
    ssl_mtx_tbl.reset(new std::mutex[CRYPTO_num_locks()]);
    CRYPTO_set_locking_callback(ssl_lock_fn);
    CRYPTO_set_dynlock_create_callback(ssl_dynlock_create);
    CRYPTO_set_dynlock_lock_callback(ssl_dynlock_lock);
    CRYPTO_set_dynlock_destroy_callback(ssl_dynlock_destroy);
}

void do_ssl_deinit() {
    ERR_free_strings();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    CRYPTO_set_locking_callback(nullptr);
    CRYPTO_set_dynlock_create_callback(nullptr);
    CRYPTO_set_dynlock_lock_callback(nullptr);
    CRYPTO_set_dynlock_destroy_callback(nullptr);
    ssl_mtx_tbl.reset();
}

} // namespace
#else
namespace {

void do_ssl_init() { OPENSSL_init_ssl(0, nullptr); }

void do_ssl_deinit() {
    ERR_free_strings();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
}

} // namespace
#endif

zeek::ValManager* zeek::val_mgr = nullptr;
zeek::packet_analysis::Manager* zeek::packet_mgr = nullptr;
zeek::analyzer::Manager* zeek::analyzer_mgr = nullptr;
zeek::plugin::Manager* zeek::plugin_mgr = nullptr;

zeek::detail::RuleMatcher* zeek::detail::rule_matcher = nullptr;
zeek::detail::DNS_Mgr* zeek::detail::dns_mgr = nullptr;
zeek::detail::TimerMgr* zeek::detail::timer_mgr = nullptr;

zeek::logging::Manager* zeek::log_mgr = nullptr;
zeek::threading::Manager* zeek::thread_mgr = nullptr;
zeek::input::Manager* zeek::input_mgr = nullptr;
zeek::file_analysis::Manager* zeek::file_mgr = nullptr;
zeek::zeekygen::detail::Manager* zeek::detail::zeekygen_mgr = nullptr;
zeek::iosource::Manager* zeek::iosource_mgr = nullptr;
zeek::Broker::Manager* zeek::broker_mgr = nullptr;
zeek::telemetry::Manager* zeek::telemetry_mgr = nullptr;
zeek::Supervisor* zeek::supervisor_mgr = nullptr;
zeek::detail::trigger::Manager* zeek::detail::trigger_mgr = nullptr;
#ifdef HAVE_SPICY
zeek::spicy::Manager* zeek::spicy_mgr = nullptr;
#endif

std::vector<std::string> zeek::detail::zeek_script_prefixes;
zeek::detail::Stmt* zeek::detail::stmts = nullptr;
zeek::EventRegistry* zeek::event_registry = nullptr;
std::shared_ptr<zeek::detail::ProfileLogger> zeek::detail::profiling_logger;

zeek::detail::FragmentManager* zeek::detail::fragment_mgr = nullptr;

int signal_val = 0;
extern "C" char version[];
extern "C" const char zeek_build_info[];

const char* zeek::detail::command_line_policy = nullptr;
vector<string> zeek::detail::params;
set<string> requested_plugins;
const char* proc_status_file = nullptr;

zeek::OpaqueTypePtr md5_type;
zeek::OpaqueTypePtr sha1_type;
zeek::OpaqueTypePtr sha256_type;
zeek::OpaqueTypePtr entropy_type;
zeek::OpaqueTypePtr cardinality_type;
zeek::OpaqueTypePtr topk_type;
zeek::OpaqueTypePtr bloomfilter_type;
zeek::OpaqueTypePtr x509_opaque_type;
zeek::OpaqueTypePtr ocsp_resp_opaque_type;
zeek::OpaqueTypePtr paraglob_type;
zeek::OpaqueTypePtr int_counter_metric_type;
zeek::OpaqueTypePtr int_counter_metric_family_type;
zeek::OpaqueTypePtr dbl_counter_metric_type;
zeek::OpaqueTypePtr dbl_counter_metric_family_type;
zeek::OpaqueTypePtr int_gauge_metric_type;
zeek::OpaqueTypePtr int_gauge_metric_family_type;
zeek::OpaqueTypePtr dbl_gauge_metric_type;
zeek::OpaqueTypePtr dbl_gauge_metric_family_type;
zeek::OpaqueTypePtr int_histogram_metric_type;
zeek::OpaqueTypePtr int_histogram_metric_family_type;
zeek::OpaqueTypePtr dbl_histogram_metric_type;
zeek::OpaqueTypePtr dbl_histogram_metric_family_type;

// Keep copy of command line
int zeek::detail::zeek_argc;
char** zeek::detail::zeek_argv;

namespace zeek {

const char* zeek_version() {
#ifdef DEBUG
    static char* debug_version = nullptr;

    if ( ! debug_version ) {
        int n = strlen(version) + sizeof("-debug") + 1;
        debug_version = new char[n];
        snprintf(debug_version, n, "%s%s", version, "-debug");
    }

    return debug_version;
#else
    return version;
#endif
}

namespace detail {

zeek::OpaqueTypePtr log_delay_token_type;

static std::vector<const char*> to_cargs(const std::vector<std::string>& args) {
    std::vector<const char*> rval;
    rval.reserve(args.size());

    for ( const auto& arg : args )
        rval.emplace_back(arg.data());

    return rval;
}

static bool show_plugins(int level) {
    plugin::Manager::plugin_list plugins = plugin_mgr->ActivePlugins();

    if ( ! plugins.size() ) {
        printf("No plugins registered, not even any built-ins. This is probably a bug.\n");
        return false;
    }

    ODesc d;

    if ( level == 1 )
        d.SetShort();

    int count = 0;

    for ( plugin::Manager::plugin_list::const_iterator i = plugins.begin(); i != plugins.end(); i++ ) {
        if ( requested_plugins.size() && requested_plugins.find((*i)->Name()) == requested_plugins.end() )
            continue;

        (*i)->Describe(&d);

        if ( ! d.IsShort() )
            d.Add("\n");

        ++count;
    }

    printf("%s", d.Description());

    plugin::Manager::inactive_plugin_list inactives = plugin_mgr->InactivePlugins();

    if ( inactives.size() && ! requested_plugins.size() ) {
        printf("\nInactive dynamic plugins:\n");

        for ( plugin::Manager::inactive_plugin_list::const_iterator i = inactives.begin(); i != inactives.end(); i++ ) {
            string name = (*i).first;
            string path = (*i).second;
            printf("  %s (%s)\n", name.c_str(), path.c_str());
        }
    }

    return count != 0;
}

static void done_with_network() {
    util::detail::set_processing_status("TERMINATING", "done_with_network");

    // Cancel any pending alarms (watchdog, in particular).
    (void)alarm(0);

    if ( net_done ) {
        event_mgr.Drain();
        // Don't propagate this event to remote clients.
        event_mgr.Dispatch(new Event(net_done, {make_intrusive<TimeVal>(timer_mgr->Time())}), true);
    }

    if ( profiling_logger )
        profiling_logger->Log();

    run_state::terminating = true;

    packet_mgr->Done();
    analyzer_mgr->Done();
    timer_mgr->Expire();
    dns_mgr->Flush();
    event_mgr.Drain();
    event_mgr.Drain();

    run_state::detail::finish_run(1);

#ifdef USE_PERFTOOLS_DEBUG

    if ( perftools_profile ) {
        HeapProfilerDump("post net_run");
        HeapProfilerStop();
    }

    if ( heap_checker && ! heap_checker->NoLeaks() ) {
        fprintf(stderr, "Memory leaks - aborting.\n");
        abort();
    }
#endif

    ZEEK_LSAN_DISABLE();
}

static void terminate_zeek() {
    util::detail::set_processing_status("TERMINATING", "terminate_zeek");

    run_state::terminating = true;

    iosource_mgr->Wakeup("terminate_zeek");

    // File analysis termination may produce events, so do it early on in
    // the termination process.
    file_mgr->Terminate();

    if ( zeek_done )
        event_mgr.Enqueue(zeek_done, Args{});

    timer_mgr->Expire();

    // Drain() limits how many "generations" of newly created events
    // it will process.  When we're terminating, however, we're okay
    // with long chains of events, and this makes the workings of
    // event-tracing simpler.
    //
    // That said, we also need to ensure that it runs at least once,
    // as it has side effects such as tickling triggers.
    event_mgr.Drain();

    while ( event_mgr.HasEvents() )
        event_mgr.Drain();

    if ( profiling_logger ) {
        // FIXME: There are some occasional crashes in the memory
        // allocation code when killing Zeek.  Disabling this for now.
        if ( ! (signal_val == SIGTERM || signal_val == SIGINT) )
            profiling_logger->Log();
    }

    event_mgr.Drain();

    notifier::detail::registry.Terminate();
    log_mgr->Terminate();
    input_mgr->Terminate();
    thread_mgr->Terminate();
    broker_mgr->Terminate();

    event_mgr.Drain();

    session_mgr->Clear();
    plugin_mgr->FinishPlugins();

    finish_script_execution();

    script_coverage_mgr.WriteStats();

    delete zeekygen_mgr;
    delete packet_mgr;
    delete analyzer_mgr;
    delete file_mgr;
    // broker_mgr, timer_mgr, supervisor, and dns_mgr are deleted via iosource_mgr
    delete iosource_mgr;
    delete event_registry;
    delete log_mgr;
    delete reporter;
    delete plugin_mgr;
    delete val_mgr;
    delete session_mgr;
    delete fragment_mgr;
    delete telemetry_mgr;
#ifdef HAVE_SPICY
    delete spicy_mgr;
#endif

    // free the global scope
    pop_scope();

    reporter = nullptr;
}

RETSIGTYPE sig_handler(int signo) {
    util::detail::set_processing_status("TERMINATING", "sig_handler");
    signal_val = signo;

    if ( ! run_state::terminating )
        iosource_mgr->Wakeup("sig_handler");

    return RETSIGVAL;
}

static void atexit_handler() { util::detail::set_processing_status("TERMINATED", "atexit"); }

static void zeek_new_handler() { out_of_memory("new"); }

static std::vector<std::string> get_script_signature_files() {
    std::vector<std::string> rval;

    // Parse rule files defined on the script level.
    auto script_signature_files = id::find_val("signature_files")->AsStringVal()->ToStdString();

    char* tmp = script_signature_files.data();
    char* s;
    while ( (s = strsep(&tmp, " \t")) )
        if ( *s )
            rval.emplace_back(s);

    return rval;
}

// Helper for masking/unmasking the set of signals that apply to our signal
// handlers: sig_handler() in this file, as well as stem_signal_handler() and
// supervisor_signal_handler() in the Supervisor.
static void set_signal_mask(bool do_block) {
    sigset_t mask_set;

    sigemptyset(&mask_set);
    sigaddset(&mask_set, SIGCHLD);
    sigaddset(&mask_set, SIGTERM);
    sigaddset(&mask_set, SIGINT);

    int res = pthread_sigmask(do_block ? SIG_BLOCK : SIG_UNBLOCK, &mask_set, 0);
    assert(res == 0);
}

SetupResult setup(int argc, char** argv, Options* zopts) {
    ZEEK_LSAN_DISABLE();
    std::set_new_handler(zeek_new_handler);

    auto zeek_exe_path = util::detail::get_exe_path(argv[0]);

    if ( zeek_exe_path.empty() ) {
        fprintf(stderr, "failed to get path to executable '%s'", argv[0]);
        exit(1);
    }

    zeek_argc = argc;
    zeek_argv = new char*[argc];

    for ( int i = 0; i < argc; i++ )
        zeek_argv[i] = util::copy_string(argv[i]);

    auto options = zopts ? *zopts : parse_cmdline(argc, argv);

    run_state::detail::bare_mode = options.bare_mode;

    // Set up the global that facilitates access to analysis/optimization
    // options from deep within some modules.
    analysis_options = options.analysis_options;

    if ( options.print_version ) {
        fprintf(stdout, "%s version %s\n", argv[0], zeek_version());
        exit(0);
    }

    if ( options.print_build_info ) {
        fprintf(stdout, "%s", zeek_build_info);
        exit(0);
    }

    if ( options.run_unit_tests )
        options.deterministic_mode = true;

    auto stem = Supervisor::CreateStem(options.supervisor_mode);

    if ( Supervisor::ThisNode() ) {
        // If we get here, we're a supervised node that just returned
        // from CreateStem() after being forked from the stem.
        Supervisor::ThisNode()->Init(&options);
    }

    script_coverage_mgr.ReadStats();

    auto dns_type = options.dns_mode;

    if ( dns_type == DNS_DEFAULT && fake_dns() )
        dns_type = DNS_FAKE;

    dns_mgr = new DNS_Mgr(dns_type);

    RETSIGTYPE (*oldhandler)(int);

    zeek_script_prefixes = options.script_prefixes;
    auto zeek_prefixes = getenv("ZEEK_PREFIXES");

    if ( zeek_prefixes )
        util::tokenize_string(zeek_prefixes, ":", &zeek_script_prefixes);

    run_state::pseudo_realtime = options.pseudo_realtime;

#ifdef USE_PERFTOOLS_DEBUG
    perftools_leaks = options.perftools_check_leaks;
    perftools_profile = options.perftools_profile;
#endif

    if ( options.debug_scripts ) {
        g_policy_debug = options.debug_scripts;
        fprintf(stderr, "Zeek script debugging ON.\n");
    }

    if ( options.script_code_to_exec )
        command_line_policy = options.script_code_to_exec->data();

    if ( options.debug_script_tracing_file ) {
        g_trace_state.SetTraceFile(options.debug_script_tracing_file->data());
        g_trace_state.TraceOn();
    }

    if ( options.process_status_file )
        proc_status_file = util::copy_string(options.process_status_file->data());

    atexit(atexit_handler);
    util::detail::set_processing_status("INITIALIZING", "main");

    run_state::zeek_start_time = util::current_time(true);

    val_mgr = new ValManager();
    reporter = new Reporter(options.abort_on_scripting_errors);
    thread_mgr = new threading::Manager();
    plugin_mgr = new plugin::Manager();
    fragment_mgr = new detail::FragmentManager();

    if ( options.no_unused_warnings && options.analysis_options.usage_issues > 0 )
        reporter->FatalError("-u incompatible with --no-unused-warnings");

#ifdef DEBUG
    if ( options.debug_log_streams ) {
        debug_logger.EnableStreams(options.debug_log_streams->data());

        if ( getenv("ZEEK_DEBUG_LOG_STDERR") )
            debug_logger.OpenDebugLog(nullptr);
        else
            debug_logger.OpenDebugLog("debug");
    }
#endif

    // Mask signals relevant for our signal handlers here. We unmask them
    // again further down, when all components that launch threads have done
    // so, and intermittently during parsing. The launched threads inherit
    // the active signal mask and thus prevent our signal handlers from
    // running in unintended threads.
    set_signal_mask(true);

    if ( options.supervisor_mode ) {
        Supervisor::Config cfg = {};
        cfg.zeek_exe_path = zeek_exe_path;
        options.filter_supervisor_options();
        supervisor_mgr = new Supervisor(std::move(cfg), std::move(*stem));
    }

    std::string seed_string;
    if ( const auto* seed_env = getenv("ZEEK_SEED_VALUES") )
        seed_string = seed_env;

    const char* seed_load_file = getenv("ZEEK_SEED_FILE");

    if ( options.random_seed_input_file )
        seed_load_file = options.random_seed_input_file->data();

    if ( seed_load_file && *seed_load_file && ! seed_string.empty() )
        reporter->FatalError("can't use ZEEK_SEED_VALUES together with ZEEK_SEED_FILE or -G");

    util::detail::init_random_seed((seed_load_file && *seed_load_file ? seed_load_file : nullptr),
                                   options.random_seed_output_file ? options.random_seed_output_file->data() : nullptr,
                                   options.deterministic_mode, seed_string);
    // DEBUG_MSG("HMAC key: %s\n", md5_digest_print(shared_hmac_md5_key));
    init_hash_function();

    do_ssl_init();

    // FIXME: On systems that don't provide /dev/urandom, OpenSSL doesn't
    // seed the PRNG. We should do this here (but at least Linux, FreeBSD
    // and Solaris provide /dev/urandom).
#ifdef USE_SQLITE
    int r = sqlite3_initialize();

    if ( r != SQLITE_OK )
        reporter->Error("Failed to initialize sqlite3: %s", sqlite3_errstr(r));
#endif

    timer_mgr = new TimerMgr();

    auto zeekygen_cfg = options.zeekygen_config_file.value_or("");
    zeekygen_mgr = new zeekygen::detail::Manager(zeekygen_cfg, zeek_argv[0]);

    add_essential_input_file("base/init-bare.zeek");
    add_essential_input_file("builtin-plugins/__preload__.zeek");
    add_essential_input_file("base/init-frameworks-and-bifs.zeek");

    if ( ! options.bare_mode ) {
        // The supervisor only needs to load a limited set of
        // scripts, since it won't be doing traffic processing.
        if ( options.supervisor_mode )
            add_input_file("base/init-supervisor.zeek");
        else
            add_input_file("base/init-default.zeek");
    }

    add_input_file("builtin-plugins/__load__.zeek");

    plugin_mgr->SearchDynamicPlugins(util::zeek_plugin_path());

    if ( options.plugins_to_load.empty() && options.scripts_to_load.empty() && options.script_options_to_set.empty() &&
         ! options.pcap_file && ! options.interface && ! options.identifier_to_print && ! command_line_policy &&
         ! options.print_plugins && ! options.supervisor_mode && ! Supervisor::ThisNode() && ! options.run_unit_tests )
        add_input_file("-");

    for ( const auto& script_option : options.script_options_to_set )
        params.push_back(script_option);

    for ( const auto& plugin : options.plugins_to_load )
        requested_plugins.insert(plugin);

    for ( const auto& script : options.scripts_to_load )
        add_input_file(script.data());

    if ( options.pcap_filter )
        add_input_file("base/frameworks/packet-filter/main.zeek");

    push_scope(nullptr, nullptr);

    // It would nice if this were configurable.  This is similar to the
    // chicken and the egg problem.  It would be configurable by parsing
    // policy, but we can't parse policy without DNS resolution.
    dns_mgr->SetDir(".state");

    telemetry_mgr = new telemetry::Manager;
    iosource_mgr = new iosource::Manager();
    event_registry = new EventRegistry();
    packet_mgr = new packet_analysis::Manager();
    analyzer_mgr = new analyzer::Manager();
    log_mgr = new logging::Manager();
    input_mgr = new input::Manager();
    file_mgr = new file_analysis::Manager();
    auto broker_real_time = ! options.pcap_file && ! options.deterministic_mode;
    broker_mgr = new Broker::Manager(broker_real_time);
    trigger_mgr = new trigger::Manager();
#ifdef HAVE_SPICY
    spicy_mgr = new spicy::Manager(); // registers as plugin with the plugin manager
#endif

    plugin_mgr->InitPreScript();
    file_mgr->InitPreScript();
    zeekygen_mgr->InitPreScript();

    // This has to happen before ActivateDynamicPlugin() below or the list of plugins in the
    // manager will be missing the plugins we want to try to add to the path.
    plugin_mgr->ExtendZeekPathForPlugins();

    for ( const auto& x : requested_plugins )
        plugin_mgr->ActivateDynamicPlugin(std::move(x));

    plugin_mgr->ActivateDynamicPlugins(! options.bare_mode);

    // Print usage after plugins load so that any path extensions are properly shown.
    if ( options.print_usage )
        usage(argv[0], 0);

    init_event_handlers();

    md5_type = make_intrusive<OpaqueType>("md5");
    sha1_type = make_intrusive<OpaqueType>("sha1");
    sha256_type = make_intrusive<OpaqueType>("sha256");
    entropy_type = make_intrusive<OpaqueType>("entropy");
    cardinality_type = make_intrusive<OpaqueType>("cardinality");
    topk_type = make_intrusive<OpaqueType>("topk");
    bloomfilter_type = make_intrusive<OpaqueType>("bloomfilter");
    x509_opaque_type = make_intrusive<OpaqueType>("x509");
    ocsp_resp_opaque_type = make_intrusive<OpaqueType>("ocsp_resp");
    paraglob_type = make_intrusive<OpaqueType>("paraglob");
    int_counter_metric_type = make_intrusive<OpaqueType>("int_counter_metric");
    int_counter_metric_family_type = make_intrusive<OpaqueType>("int_counter_metric_family");
    dbl_counter_metric_type = make_intrusive<OpaqueType>("dbl_counter_metric");
    dbl_counter_metric_family_type = make_intrusive<OpaqueType>("dbl_counter_metric_family");
    int_gauge_metric_type = make_intrusive<OpaqueType>("int_gauge_metric");
    int_gauge_metric_family_type = make_intrusive<OpaqueType>("int_gauge_metric_family");
    dbl_gauge_metric_type = make_intrusive<OpaqueType>("dbl_gauge_metric");
    dbl_gauge_metric_family_type = make_intrusive<OpaqueType>("dbl_gauge_metric_family");
    int_histogram_metric_type = make_intrusive<OpaqueType>("int_histogram_metric");
    int_histogram_metric_family_type = make_intrusive<OpaqueType>("int_histogram_metric_family");
    dbl_histogram_metric_type = make_intrusive<OpaqueType>("dbl_histogram_metric");
    dbl_histogram_metric_family_type = make_intrusive<OpaqueType>("dbl_histogram_metric_family");
    log_delay_token_type = make_intrusive<OpaqueType>("LogDelayToken");

    // After spinning up Broker, we have background threads running now. If
    // we exit early, we need to shut down at least Broker to get a clean
    // program exit. Otherwise, we may run into undefined behavior, e.g., if
    // Broker is still accessing OpenSSL but OpenSSL has already cleaned up
    // its state due to calling exit(). This needs to be defined here before
    // potential USE_PERFTOOLS_DEBUG scope below or the definition gets lost
    // when that variable is defined.
    auto early_shutdown = [] {
        broker_mgr->Terminate();
        delete iosource_mgr;
        delete telemetry_mgr;
    };

    // The leak-checker tends to produce some false
    // positives (memory which had already been
    // allocated before we start the checking is
    // nevertheless reported; see perftools docs), thus
    // we suppress some messages here.

#ifdef USE_PERFTOOLS_DEBUG
    {
        HeapLeakChecker::Disabler disabler;
#endif

        auto ipbid = install_ID("__init_primary_bifs", GLOBAL_MODULE_NAME, true, true);
        auto ipbft =
            make_intrusive<FuncType>(make_intrusive<RecordType>(nullptr), base_type(TYPE_BOOL), FUNC_FLAVOR_FUNCTION);
        ipbid->SetType(std::move(ipbft));
        auto init_bifs = [](Frame* frame, const Args* args) -> ValPtr {
            init_primary_bifs();
            return val_mgr->True();
        };
        auto ipbb = make_intrusive<BuiltinFunc>(init_bifs, ipbid->Name(), false);

        if ( options.event_trace_file )
            etm = make_unique<EventTraceMgr>(*options.event_trace_file);

        // Parsing involves reading input files, including any input
        // interactively provided by the user at the console. Temporarily
        // undo the signal mask to allow ctrl-c. Ideally we'd do this only
        // when we actually end up reading interactively from stdin.
        set_signal_mask(false);
        run_state::is_parsing = true;
        int yyparse_result = yyparse();
        run_state::is_parsing = false;
        set_signal_mask(true);

        RecordVal::DoneParsing();
        TableVal::DoneParsing();

        if ( yyparse_result != 0 || zeek::reporter->Errors() > 0 )
            exit(1);

        init_general_global_var();
        init_net_var();
        run_bif_initializers();

        // Delay the unit test until here so that plugins and script
        // types have been fully loaded.
        if ( options.run_unit_tests ) {
            set_signal_mask(false); // Allow ctrl-c to abort the tests early
            doctest::Context context;
            auto dargs = to_cargs(options.doctest_args);
            context.applyCommandLine(dargs.size(), dargs.data());
            ZEEK_LSAN_ENABLE();
            exit(context.run());
        }

        // Assign the script_args for command line processing in Zeek scripts.
        if ( ! options.script_args.empty() ) {
            auto script_args_val = id::find_val<VectorVal>("zeek_script_args");
            for ( const string& script_arg : options.script_args ) {
                script_args_val->Assign(script_args_val->Size(), make_intrusive<StringVal>(script_arg));
            }
        }

        // Must come after plugin activation (and also after hash
        // initialization).
        binpac::FlowBuffer::Policy flowbuffer_policy;
        flowbuffer_policy.max_capacity = global_scope()->Find("BinPAC::flowbuffer_capacity_max")->GetVal()->AsCount();
        flowbuffer_policy.min_capacity = global_scope()->Find("BinPAC::flowbuffer_capacity_min")->GetVal()->AsCount();
        flowbuffer_policy.contract_threshold =
            global_scope()->Find("BinPAC::flowbuffer_contract_threshold")->GetVal()->AsCount();
        binpac::init(&flowbuffer_policy);

        plugin_mgr->InitBifs();

        if ( reporter->Errors() > 0 )
            exit(1);

        RecordType::InitPostScript();

        telemetry_mgr->InitPostScript();
        iosource_mgr->InitPostScript();
        log_mgr->InitPostScript();
        plugin_mgr->InitPostScript();
        zeekygen_mgr->InitPostScript();
        broker_mgr->InitPostScript();
        timer_mgr->InitPostScript();
        event_mgr.InitPostScript();

        if ( supervisor_mgr )
            supervisor_mgr->InitPostScript();

        if ( options.print_plugins ) {
            early_shutdown();
            bool success = show_plugins(options.print_plugins);
            exit(success ? 0 : 1);
        }

#ifdef DEBUG
        // Check debug streams. Specifically that all plugin-
        // streams are valid now that the active plugins are known.
        std::set<std::string> active_plugins;
        for ( const auto p : plugin_mgr->ActivePlugins() )
            active_plugins.insert(p->Name());

        if ( ! debug_logger.CheckStreams(active_plugins) ) {
            early_shutdown();
            exit(1);
        }
#endif

        packet_mgr->InitPostScript(options.unprocessed_output_file.value_or(""));
        analyzer_mgr->InitPostScript();
        file_mgr->InitPostScript();
        dns_mgr->InitPostScript();
        trigger_mgr->InitPostScript();

#ifdef USE_PERFTOOLS_DEBUG
    }
#endif
    set_signal_mask(false);

    if ( reporter->Errors() > 0 ) {
        early_shutdown();
        exit(1);
    }

    reporter->InitOptions();
    KeyedHash::InitOptions();
    zeekygen_mgr->GenerateDocs();

    if ( options.pcap_filter ) {
        const auto& id = global_scope()->Find("cmd_line_bpf_filter");

        if ( ! id )
            reporter->InternalError("global cmd_line_bpf_filter not defined");

        id->SetVal(make_intrusive<StringVal>(*options.pcap_filter));
    }

    std::vector<SignatureFile> all_signature_files;

    // Append signature files given on the command line
    for ( const auto& sf : options.signature_files )
        all_signature_files.emplace_back(sf);

    // Append signature files defined in "signature_files" script option
    for ( auto&& sf : get_script_signature_files() )
        all_signature_files.emplace_back(std::move(sf));

    // Append signature files defined in @load-sigs
    for ( const auto& sf : zeek::detail::sig_files )
        all_signature_files.emplace_back(sf);

    if ( ! all_signature_files.empty() ) {
        rule_matcher = new RuleMatcher(options.signature_re_level);
        if ( ! rule_matcher->ReadFiles(all_signature_files) || zeek::reporter->Errors() > 0 ) {
            early_shutdown();
            exit(1);
        }

        if ( options.print_signature_debug_info )
            rule_matcher->PrintDebug();

        file_mgr->InitMagic();
    }

    if ( g_policy_debug )
        // ### Add support for debug command file.
        dbg_init_debugger(nullptr);

    if ( ! options.pcap_file && ! options.interface ) {
        const auto& interfaces_val = id::find_val("interfaces");
        if ( interfaces_val ) {
            char* interfaces_str = interfaces_val->AsString()->Render();

            if ( interfaces_str[0] != '\0' )
                options.interface = interfaces_str;

            delete[] interfaces_str;
        }
    }

    if ( options.parse_only ) {
        if ( analysis_options.usage_issues > 0 )
            analyze_scripts(options.no_unused_warnings);

        early_shutdown();
        exit(reporter->Errors() != 0);
    }

    if ( stmts )
        analyze_global_stmts(stmts);

    analyze_scripts(options.no_unused_warnings);

    if ( analysis_options.report_recursive ) {
        // This option is report-and-exit.
        early_shutdown();
        exit(0);
    }

    if ( dns_type != DNS_PRIME )
        run_state::detail::init_run(options.interface, options.pcap_file, options.pcap_output_file,
                                    options.use_watchdog);

    if ( ! g_policy_debug ) {
        (void)setsignal(SIGTERM, sig_handler);
        (void)setsignal(SIGINT, sig_handler);
        (void)setsignal(SIGPIPE, SIG_IGN);
    }

    // Cooperate with nohup(1).
    if ( (oldhandler = setsignal(SIGHUP, sig_handler)) != SIG_DFL )
        (void)setsignal(SIGHUP, oldhandler);

    // If we were priming the DNS cache (i.e. -P was passed as an argument), flush anything
    // remaining to be resolved and save the cache to disk. We can just exit now because
    // we've done everything we need to do. The run loop isn't started in this case, so
    // nothing else should be happening.
    if ( dns_type == DNS_PRIME ) {
        dns_mgr->Resolve();

        if ( ! dns_mgr->Save() )
            reporter->FatalError("can't update DNS cache");

        event_mgr.Drain();
        early_shutdown();
        exit(0);
    }

    if ( options.ignore_checksums ) {
        const auto& id = global_scope()->Find("ignore_checksums");

        if ( ! id )
            reporter->InternalError("global ignore_checksums not defined");

        id->SetVal(zeek::val_mgr->True());
        ignore_checksums = 1;
    }

    // Print the ID.
    if ( options.identifier_to_print ) {
        const auto& id = global_scope()->Find(*options.identifier_to_print);
        if ( ! id )
            reporter->FatalError("No such ID: %s\n", options.identifier_to_print->data());

        ODesc desc;
        desc.SetQuotes(true);
        desc.SetIncludeStats(true);
        id->DescribeExtended(&desc);

        fprintf(stdout, "%s\n", desc.Description());
        early_shutdown();
        exit(0);
    }

    if ( profiling_interval > 0 ) {
        const auto& profiling_file = id::find_val("profiling_file");
        profiling_logger = std::make_shared<ProfileLogger>(profiling_file->AsFile(), profiling_interval);
    }

    if ( ! run_state::reading_live && ! run_state::reading_traces &&
         id::find_const("allow_network_time_forward")->AsBool() )
        // Set up network_time to track real-time, since
        // we don't have any other source for it.
        run_state::detail::update_network_time(util::current_time());

    if ( CPP_activation_hook )
        (*CPP_activation_hook)();

    if ( zeek_init )
        event_mgr.Enqueue(zeek_init, Args{});

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    EventRegistry::string_list dead_handlers = event_registry->UnusedHandlers();
#pragma GCC diagnostic pop

    if ( ! dead_handlers.empty() && check_for_unused_event_handlers ) {
        for ( const string& handler : dead_handlers )
            reporter->Warning("event handler never invoked: %s", handler.c_str());
    }

    // Enable LeakSanitizer before zeek_init() and even before executing
    // top-level statements.  Even though it's not bad if a leak happens only
    // once at initialization, we have to assume that script-layer code causing
    // such a leak can be placed in any arbitrary event handler and potentially
    // cause more severe problems.
    ZEEK_LSAN_ENABLE();

    if ( stmts ) {
        auto [body, scope] = get_global_stmts();
        StmtFlowType flow;
        Frame f(scope->Length(), nullptr, nullptr);
        g_frame_stack.push_back(&f);

        try {
            body->Exec(&f, flow);
        } catch ( InterpreterException& ) {
            reporter->FatalError("failed to execute script statements at top-level scope");
        }

        g_frame_stack.pop_back();
    }

    clear_script_analysis();

    if ( zeek_script_loaded ) {
        // Queue events reporting loaded scripts.
        for ( const auto& file : zeek::detail::files_scanned ) {
            if ( file.skipped )
                continue;

            event_mgr.Enqueue(zeek_script_loaded, make_intrusive<StringVal>(file.name.c_str()),
                              val_mgr->Count(file.include_level));
        }
    }

    reporter->ReportViaEvents(true);

    // Drain the event queue here to support the protocols framework configuring DPM
    event_mgr.Drain();

    if ( reporter->Errors() > 0 && ! getenv("ZEEK_ALLOW_INIT_ERRORS") )
        reporter->FatalError("errors occurred while initializing");

    run_state::detail::zeek_init_done = true;
    packet_mgr->DumpDebug();
    analyzer_mgr->DumpDebug();

    run_state::detail::have_pending_timers = ! run_state::reading_traces && timer_mgr->Size() > 0;

    return {0, std::move(options)};
}

int cleanup(bool did_run_loop) {
    if ( did_run_loop )
        done_with_network();

    run_state::detail::delete_run();
    terminate_zeek();

#ifdef USE_SQLITE
    sqlite3_shutdown();
#endif

    do_ssl_deinit();

    // Close files after net_delete(), because net_delete()
    // might write to connection content files.
    File::CloseOpenFiles();

    delete rule_matcher;

    return 0;
}

} // namespace detail

namespace run_state::detail {

void zeek_terminate_loop(const char* reason) {
    util::detail::set_processing_status("TERMINATING", reason);
    reporter->Info("%s", reason);

    get_final_stats();
    zeek::detail::done_with_network();
    delete_run();

    zeek::detail::terminate_zeek();

    // Close files after net_delete(), because net_delete()
    // might write to connection content files.
    File::CloseOpenFiles();

    delete zeek::detail::rule_matcher;

    exit(0);
}

} // namespace run_state::detail
} // namespace zeek
