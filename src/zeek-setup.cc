// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/zeek-config.h"
#include "zeek/zeek-setup.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <list>
#include <optional>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "zeek/3rdparty/sqlite3.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include "zeek/3rdparty/doctest.h"

#include "zeek/Options.h"
#include "zeek/input.h"
#include "zeek/DNS_Mgr.h"
#include "zeek/Frame.h"
#include "zeek/Scope.h"
#include "zeek/Event.h"
#include "zeek/File.h"
#include "zeek/Reporter.h"
#include "zeek/RunState.h"
#include "zeek/NetVar.h"
#include "zeek/Var.h"
#include "zeek/Timer.h"
#include "zeek/Stmt.h"
#include "zeek/Desc.h"
#include "zeek/Debug.h"
#include "zeek/DFA.h"
#include "zeek/RuleMatcher.h"
#include "zeek/Anon.h"
#include "zeek/EventRegistry.h"
#include "zeek/Stats.h"
#include "zeek/ScriptCoverageManager.h"
#include "zeek/Traverse.h"
#include "zeek/Trigger.h"
#include "zeek/Hash.h"
#include "zeek/Func.h"
#include "zeek/ScannedFile.h"
#include "zeek/Frag.h"

#include "zeek/script_opt/ScriptOpt.h"

#include "zeek/supervisor/Supervisor.h"
#include "zeek/threading/Manager.h"
#include "zeek/input/Manager.h"
#include "zeek/logging/Manager.h"
#include "zeek/input/readers/raw/Raw.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/Tag.h"
#include "zeek/packet_analysis/Manager.h"
#include "zeek/plugin/Manager.h"
#include "zeek/file_analysis/Manager.h"
#include "zeek/zeekygen/Manager.h"
#include "zeek/iosource/Manager.h"
#include "zeek/broker/Manager.h"
#include "zeek/telemetry/Manager.h"
#include "zeek/session/Manager.h"

#include "zeek/binpac_zeek.h"
#include "zeek/module_util.h"

extern "C" {
#include "zeek/setsignal.h"
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

std::vector<std::string> zeek::detail::zeek_script_prefixes;
zeek::detail::Stmt* zeek::detail::stmts = nullptr;
zeek::EventRegistry* zeek::event_registry = nullptr;
zeek::detail::ProfileLogger* zeek::detail::profiling_logger = nullptr;
zeek::detail::ProfileLogger* zeek::detail::segment_logger = nullptr;
zeek::detail::SampleLogger* zeek::detail::sample_logger = nullptr;

zeek::detail::FragmentManager* zeek::detail::fragment_mgr = nullptr;

int signal_val = 0;
extern char version[];
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

const char* zeek_version()
	{
#ifdef DEBUG
	static char* debug_version = nullptr;

	if ( ! debug_version )
		{
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

static std::vector<const char*> to_cargs(const std::vector<std::string>& args)
	{
	std::vector<const char*> rval;
	rval.reserve(args.size());

	for ( const auto& arg : args )
		rval.emplace_back(arg.data());

	return rval;
	}

static bool show_plugins(int level)
	{
	plugin::Manager::plugin_list plugins = plugin_mgr->ActivePlugins();

	if ( ! plugins.size() )
		{
		printf("No plugins registered, not even any built-ins. This is probably a bug.\n");
		return false;
		}

	ODesc d;

	if ( level == 1 )
		d.SetShort();

	int count = 0;

	for ( plugin::Manager::plugin_list::const_iterator i = plugins.begin(); i != plugins.end(); i++ )
		{
		if ( requested_plugins.size()
		     && requested_plugins.find((*i)->Name()) == requested_plugins.end() )
			continue;

		(*i)->Describe(&d);

		if ( ! d.IsShort() )
			d.Add("\n");

		++count;
		}

	printf("%s", d.Description());

	plugin::Manager::inactive_plugin_list inactives = plugin_mgr->InactivePlugins();

	if ( inactives.size() && ! requested_plugins.size() )
		{
		printf("\nInactive dynamic plugins:\n");

		for ( plugin::Manager::inactive_plugin_list::const_iterator i = inactives.begin(); i != inactives.end(); i++ )
			{
			string name = (*i).first;
			string path = (*i).second;
			printf("  %s (%s)\n", name.c_str(), path.c_str());
			}
		}

	return count != 0;
	}

static void done_with_network()
	{
	util::detail::set_processing_status("TERMINATING", "done_with_network");

	// Cancel any pending alarms (watchdog, in particular).
	(void) alarm(0);

	if ( net_done )
		{
		event_mgr.Drain();
		// Don't propagate this event to remote clients.
		event_mgr.Dispatch(
			new Event(net_done, {make_intrusive<TimeVal>(timer_mgr->Time())}),
			true);
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

	if ( perftools_profile )
		{
		HeapProfilerDump("post net_run");
		HeapProfilerStop();
		}

	if ( heap_checker && ! heap_checker->NoLeaks() )
		{
		fprintf(stderr, "Memory leaks - aborting.\n");
		abort();
		}
#endif

	ZEEK_LSAN_DISABLE();
	}

static void terminate_bro()
	{
	util::detail::set_processing_status("TERMINATING", "terminate_bro");

	run_state::terminating = true;

	iosource_mgr->Wakeup("terminate_bro");

	// File analysis termination may produce events, so do it early on in
	// the termination process.
	file_mgr->Terminate();

	script_coverage_mgr.WriteStats();

	if ( zeek_done )
		event_mgr.Enqueue(zeek_done, Args{});

	timer_mgr->Expire();
	event_mgr.Drain();

	if ( profiling_logger )
		{
		// FIXME: There are some occasional crashes in the memory
		// allocation code when killing Bro.  Disabling this for now.
		if ( ! (signal_val == SIGTERM || signal_val == SIGINT) )
			profiling_logger->Log();

		delete profiling_logger;
		}

	event_mgr.Drain();

	notifier::detail::registry.Terminate();
	log_mgr->Terminate();
	input_mgr->Terminate();
	thread_mgr->Terminate();
	broker_mgr->Terminate();
	dns_mgr->Terminate();

	event_mgr.Drain();

	plugin_mgr->FinishPlugins();

	delete zeekygen_mgr;
	delete packet_mgr;
	delete analyzer_mgr;
	delete file_mgr;
	// broker_mgr, timer_mgr, and supervisor are deleted via iosource_mgr
	delete iosource_mgr;
	delete event_registry;
	delete log_mgr;
	delete reporter;
	delete plugin_mgr;
	delete val_mgr;
	delete session_mgr;
	delete fragment_mgr;
	delete telemetry_mgr;

	// free the global scope
	pop_scope();

	reporter = nullptr;
	}

RETSIGTYPE sig_handler(int signo)
	{
	util::detail::set_processing_status("TERMINATING", "sig_handler");
	signal_val = signo;

	if ( ! run_state::terminating )
		iosource_mgr->Wakeup("sig_handler");

	return RETSIGVAL;
	}

static void atexit_handler()
	{
	util::detail::set_processing_status("TERMINATED", "atexit");
	}

static void bro_new_handler()
	{
	out_of_memory("new");
	}

static std::vector<std::string> get_script_signature_files()
	{
	std::vector<std::string> rval;

	// Parse rule files defined on the script level.
	char* script_signature_files =
		util::copy_string(id::find_val("signature_files")->AsString()->CheckString());

	char* tmp = script_signature_files;
	char* s;
	while ( (s = strsep(&tmp, " \t")) )
		if ( *s )
			rval.emplace_back(s);

	delete [] script_signature_files;
	return rval;
	}

SetupResult setup(int argc, char** argv, Options* zopts)
	{
	ZEEK_LSAN_DISABLE();
	std::set_new_handler(bro_new_handler);

	auto zeek_exe_path = util::detail::get_exe_path(argv[0]);

	if ( zeek_exe_path.empty() )
		{
		fprintf(stderr, "failed to get path to executable '%s'", argv[0]);
		exit(1);
		}

	zeek_argc = argc;
	zeek_argv = new char* [argc];

	for ( int i = 0; i < argc; i++ )
		zeek_argv[i] = util::copy_string(argv[i]);

	auto options = zopts ? *zopts : parse_cmdline(argc, argv);

	// Set up the global that facilitates access to analysis/optimization
	// options from deep within some modules.
	analysis_options = options.analysis_options;

	if ( options.print_version )
		{
		fprintf(stdout, "%s version %s\n", argv[0], zeek_version());
		exit(0);
		}

	if ( options.run_unit_tests )
		{
		doctest::Context context;
		auto dargs = to_cargs(options.doctest_args);
		context.applyCommandLine(dargs.size(), dargs.data());
		ZEEK_LSAN_ENABLE();
		exit(context.run());
		}

	auto stem = Supervisor::CreateStem(options.supervisor_mode);

	if ( Supervisor::ThisNode() )
		Supervisor::ThisNode()->Init(&options);

	script_coverage_mgr.ReadStats();

	auto dns_type = options.dns_mode;

	if ( dns_type == DNS_DEFAULT && fake_dns() )
		dns_type = DNS_FAKE;

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

	if ( options.debug_scripts )
		{
		g_policy_debug = options.debug_scripts;
		fprintf(stderr, "Zeek script debugging ON.\n");
		}

	if ( options.script_code_to_exec )
		command_line_policy = options.script_code_to_exec->data();

	if ( options.debug_script_tracing_file )
		{
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

#ifdef DEBUG
	if ( options.debug_log_streams )
		{
		debug_logger.EnableStreams(options.debug_log_streams->data());

		if ( getenv("ZEEK_DEBUG_LOG_STDERR") )
			debug_logger.OpenDebugLog(nullptr);
		else
			debug_logger.OpenDebugLog("debug");
		}
#endif

	if ( options.supervisor_mode )
		{
		Supervisor::Config cfg = {};
		cfg.zeek_exe_path = zeek_exe_path;
		options.filter_supervisor_options();
		supervisor_mgr = new Supervisor(std::move(cfg), std::move(*stem));
		}

	const char* seed_load_file = getenv("ZEEK_SEED_FILE");

	if ( options.random_seed_input_file )
		seed_load_file = options.random_seed_input_file->data();

	util::detail::init_random_seed((seed_load_file && *seed_load_file ? seed_load_file : nullptr),
	                               options.random_seed_output_file ? options.random_seed_output_file->data() : nullptr,
	                               options.deterministic_mode);
	// DEBUG_MSG("HMAC key: %s\n", md5_digest_print(shared_hmac_md5_key));
	init_hash_function();

	ERR_load_crypto_strings();
	OPENSSL_add_all_algorithms_conf();
	SSL_library_init();
	SSL_load_error_strings();

	// FIXME: On systems that don't provide /dev/urandom, OpenSSL doesn't
	// seed the PRNG. We should do this here (but at least Linux, FreeBSD
	// and Solaris provide /dev/urandom).

	int r = sqlite3_initialize();

	if ( r != SQLITE_OK )
		reporter->Error("Failed to initialize sqlite3: %s", sqlite3_errstr(r));

	timer_mgr = new PQ_TimerMgr();

	auto zeekygen_cfg = options.zeekygen_config_file.value_or("");
	zeekygen_mgr = new zeekygen::detail::Manager(zeekygen_cfg, zeek_argv[0]);

	add_essential_input_file("base/init-bare.zeek");
	add_essential_input_file("base/init-frameworks-and-bifs.zeek");

	if ( ! options.bare_mode )
		{
		// The supervisor only needs to load a limited set of
		// scripts, since it won't be doing traffic processing.
		if ( options.supervisor_mode )
			add_input_file("base/init-supervisor.zeek");
		else
			add_input_file("base/init-default.zeek");
		}

	add_input_file("builtin-plugins/__preload__.zeek");
	add_input_file("builtin-plugins/__load__.zeek");

	plugin_mgr->SearchDynamicPlugins(util::zeek_plugin_path());

	if ( options.plugins_to_load.empty() && options.scripts_to_load.empty() &&
	     options.script_options_to_set.empty() &&
		 ! options.pcap_file && ! options.interface &&
	     ! options.identifier_to_print &&
	     ! command_line_policy && ! options.print_plugins &&
	     ! options.supervisor_mode && ! Supervisor::ThisNode() )
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

	dns_mgr = new DNS_Mgr(dns_type);

	// It would nice if this were configurable.  This is similar to the
	// chicken and the egg problem.  It would be configurable by parsing
	// policy, but we can't parse policy without DNS resolution.
	dns_mgr->SetDir(".state");

	iosource_mgr = new iosource::Manager();
	event_registry = new EventRegistry();
	packet_mgr = new packet_analysis::Manager();
	analyzer_mgr = new analyzer::Manager();
	log_mgr = new logging::Manager();
	input_mgr = new input::Manager();
	file_mgr = new file_analysis::Manager();
	auto broker_real_time = ! options.pcap_file && ! options.deterministic_mode;
	broker_mgr = new Broker::Manager(broker_real_time);
	telemetry_mgr = broker_mgr->NewTelemetryManager().release();
	trigger_mgr = new trigger::Manager();

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

	// The leak-checker tends to produce some false
	// positives (memory which had already been
	// allocated before we start the checking is
	// nevertheless reported; see perftools docs), thus
	// we suppress some messages here.

#ifdef USE_PERFTOOLS_DEBUG
	{
	HeapLeakChecker::Disabler disabler;
#endif

	auto ipbid = install_ID("__init_primary_bifs", GLOBAL_MODULE_NAME,
	                        true, true);
	auto ipbft = make_intrusive<FuncType>(make_intrusive<RecordType>(nullptr),
	                                      base_type(TYPE_BOOL),
	                                      FUNC_FLAVOR_FUNCTION);
	ipbid->SetType(std::move(ipbft));
	auto init_bifs = [](Frame* frame, const Args* args) -> BifReturnVal
		{
		init_primary_bifs();
		return val_mgr->True();
		};
	auto ipbb = make_intrusive<BuiltinFunc>(init_bifs, ipbid->Name(), false);

	run_state::is_parsing = true;
	yyparse();
	run_state::is_parsing = false;

	RecordVal::DoneParsing();
	TableVal::DoneParsing();

	init_general_global_var();
	init_net_var();
	run_bif_initializers();

	// Assign the script_args for command line processing in Zeek scripts.
	if ( ! options.script_args.empty() )
		{
		auto script_args_val = id::find_val<VectorVal>("zeek_script_args");
		for ( const string& script_arg : options.script_args )
			{
			script_args_val->Assign(script_args_val->Size(), make_intrusive<StringVal>(script_arg));
			}
		}

	// Must come after plugin activation (and also after hash
	// initialization).
	binpac::FlowBuffer::Policy flowbuffer_policy;
	flowbuffer_policy.max_capacity = global_scope()->Find(
		"BinPAC::flowbuffer_capacity_max")->GetVal()->AsCount();
	flowbuffer_policy.min_capacity = global_scope()->Find(
		"BinPAC::flowbuffer_capacity_min")->GetVal()->AsCount();
	flowbuffer_policy.contract_threshold = global_scope()->Find(
		"BinPAC::flowbuffer_contract_threshold")->GetVal()->AsCount();
	binpac::init(&flowbuffer_policy);

	plugin_mgr->InitBifs();

	if ( reporter->Errors() > 0 )
		exit(1);

	iosource_mgr->InitPostScript();
	log_mgr->InitPostScript();
	plugin_mgr->InitPostScript();
	zeekygen_mgr->InitPostScript();
	broker_mgr->InitPostScript();
	telemetry_mgr->InitPostScript();
	timer_mgr->InitPostScript();
	event_mgr.InitPostScript();

	if ( supervisor_mgr )
		supervisor_mgr->InitPostScript();

	if ( options.print_plugins )
		{
		bool success = show_plugins(options.print_plugins);
		exit(success ? 0 : 1);
		}

	packet_mgr->InitPostScript();
	analyzer_mgr->InitPostScript();
	file_mgr->InitPostScript();
	dns_mgr->InitPostScript();

#ifdef USE_PERFTOOLS_DEBUG
	}
#endif

	if ( reporter->Errors() > 0 )
		{
		delete dns_mgr;
		exit(1);
		}

	reporter->InitOptions();
	KeyedHash::InitOptions();
	zeekygen_mgr->GenerateDocs();

	if ( options.pcap_filter )
		{
		const auto& id = global_scope()->Find("cmd_line_bpf_filter");

		if ( ! id )
			reporter->InternalError("global cmd_line_bpf_filter not defined");

		id->SetVal(make_intrusive<StringVal>(*options.pcap_filter));
		}

	auto all_signature_files = options.signature_files;

	// Append signature files defined in "signature_files" script option
	for ( auto&& sf : get_script_signature_files() )
		all_signature_files.emplace_back(std::move(sf));

	// Append signature files defined in @load-sigs
	for ( const auto& sf : zeek::detail::sig_files )
		all_signature_files.emplace_back(sf);

	if ( ! all_signature_files.empty() )
		{
		rule_matcher = new RuleMatcher(options.signature_re_level);
		if ( ! rule_matcher->ReadFiles(all_signature_files) )
			{
			delete dns_mgr;
			exit(1);
			}

		if ( options.print_signature_debug_info )
			rule_matcher->PrintDebug();

		file_mgr->InitMagic();
		}

	if ( g_policy_debug )
		// ### Add support for debug command file.
		dbg_init_debugger(nullptr);

	if ( ! options.pcap_file && ! options.interface )
		{
		const auto& interfaces_val = id::find_val("interfaces");
		if ( interfaces_val )
			{
			char* interfaces_str =
				interfaces_val->AsString()->Render();

			if ( interfaces_str[0] != '\0' )
				options.interface = interfaces_str;

			delete [] interfaces_str;
			}
		}

	if ( options.parse_only )
		{
		if ( analysis_options.usage_issues > 0 )
			analyze_scripts();

		exit(reporter->Errors() != 0);
		}

	auto init_stmts = stmts ? analyze_global_stmts(stmts) : nullptr;

	analyze_scripts();

	if ( analysis_options.report_recursive )
		// This option is report-and-exit.
		exit(0);

	if ( dns_type != DNS_PRIME )
		run_state::detail::init_run(options.interface, options.pcap_file, options.pcap_output_file, options.use_watchdog);

	if ( ! g_policy_debug )
		{
		(void) setsignal(SIGTERM, sig_handler);
		(void) setsignal(SIGINT, sig_handler);
		(void) setsignal(SIGPIPE, SIG_IGN);
		}

	// Cooperate with nohup(1).
	if ( (oldhandler = setsignal(SIGHUP, sig_handler)) != SIG_DFL )
		(void) setsignal(SIGHUP, oldhandler);

	if ( dns_type == DNS_PRIME )
		{
		dns_mgr->Verify();
		dns_mgr->Resolve();

		if ( ! dns_mgr->Save() )
			reporter->FatalError("can't update DNS cache");

		event_mgr.Drain();
		delete dns_mgr;
		exit(0);
		}

	// Print the ID.
	if ( options.identifier_to_print )
		{
		const auto& id = global_scope()->Find(*options.identifier_to_print);
		if ( ! id )
			reporter->FatalError("No such ID: %s\n", options.identifier_to_print->data());

		ODesc desc;
		desc.SetQuotes(true);
		desc.SetIncludeStats(true);
		id->DescribeExtended(&desc);

		fprintf(stdout, "%s\n", desc.Description());
		exit(0);
		}

	if ( profiling_interval > 0 )
		{
		const auto& profiling_file = id::find_val("profiling_file");
		profiling_logger = new ProfileLogger(profiling_file->AsFile(),
		                                                   profiling_interval);

		if ( segment_profiling )
			segment_logger = profiling_logger;
		}

	if ( ! run_state::reading_live && ! run_state::reading_traces )
		// Set up network_time to track real-time, since
		// we don't have any other source for it.
		run_state::detail::update_network_time(util::current_time());

	if ( CPP_activation_hook )
		(*CPP_activation_hook)();

	if ( zeek_init )
		event_mgr.Enqueue(zeek_init, Args{});

	EventRegistry::string_list dead_handlers =
		event_registry->UnusedHandlers();

	if ( ! dead_handlers.empty() && check_for_unused_event_handlers )
		{
		for ( const string& handler : dead_handlers )
			reporter->Warning("event handler never invoked: %s", handler.c_str());
		}

	// Enable LeakSanitizer before zeek_init() and even before executing
	// top-level statements.  Even though it's not bad if a leak happens only
	// once at initialization, we have to assume that script-layer code causing
	// such a leak can be placed in any arbitrary event handler and potentially
	// cause more severe problems.
	ZEEK_LSAN_ENABLE();

	if ( init_stmts )
		{
		StmtFlowType flow;
		Frame f(init_stmts->Scope()->Length(), nullptr, nullptr);
		g_frame_stack.push_back(&f);

		try
			{
			init_stmts->Body()->Exec(&f, flow);
			}
		catch ( InterpreterException& )
			{
			reporter->FatalError("failed to execute script statements at top-level scope");
			}

		g_frame_stack.pop_back();
		}

	if ( options.ignore_checksums )
		ignore_checksums = 1;

	if ( zeek_script_loaded )
		{
		// Queue events reporting loaded scripts.
		for ( const auto& file : zeek::detail::files_scanned )
			{
			if ( file.skipped )
				continue;

			event_mgr.Enqueue(zeek_script_loaded,
			                  make_intrusive<StringVal>(file.name.c_str()),
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

int cleanup(bool did_run_loop )
	{
	if ( did_run_loop )
		done_with_network();

	run_state::detail::delete_run();
	terminate_bro();

	sqlite3_shutdown();

	ERR_free_strings();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();

	// Close files after net_delete(), because net_delete()
	// might write to connection content files.
	File::CloseOpenFiles();

	delete rule_matcher;

	return 0;
	}

} // namespace detail

namespace run_state::detail {

void zeek_terminate_loop(const char* reason)
	{
	util::detail::set_processing_status("TERMINATING", reason);
	reporter->Info("%s", reason);

	get_final_stats();
	zeek::detail::done_with_network();
	delete_run();

	zeek::detail::terminate_bro();

	// Close files after net_delete(), because net_delete()
	// might write to connection content files.
	File::CloseOpenFiles();

	delete zeek::detail::rule_matcher;

	exit(0);
	}

} // namespace run_state::detail
} // namespace zeek
