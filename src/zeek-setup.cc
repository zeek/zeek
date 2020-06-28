// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"
#include "zeek-setup.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <list>
#include <optional>

#ifdef USE_IDMEF
extern "C" {
#include <libidmef/idmefxml.h>
}
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "Options.h"
#include "input.h"
#include "DNS_Mgr.h"
#include "Frame.h"
#include "Scope.h"
#include "Event.h"
#include "File.h"
#include "Reporter.h"
#include "Net.h"
#include "NetVar.h"
#include "Var.h"
#include "Timer.h"
#include "Stmt.h"
#include "Desc.h"
#include "Debug.h"
#include "DFA.h"
#include "RuleMatcher.h"
#include "Anon.h"
#include "EventRegistry.h"
#include "Stats.h"
#include "Brofiler.h"
#include "Traverse.h"
#include "Trigger.h"
#include "Hash.h"
#include "Func.h"

#include "supervisor/Supervisor.h"
#include "threading/Manager.h"
#include "input/Manager.h"
#include "logging/Manager.h"
#include "input/readers/raw/Raw.h"
#include "analyzer/Manager.h"
#include "analyzer/Tag.h"
#include "plugin/Manager.h"
#include "file_analysis/Manager.h"
#include "zeekygen/Manager.h"
#include "iosource/Manager.h"
#include "broker/Manager.h"

#include "binpac_bro.h"

#include "3rdparty/sqlite3.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include "3rdparty/doctest.h"

Brofiler brofiler;

#ifndef HAVE_STRSEP
extern "C" {
char* strsep(char**, const char*);
};
#endif

extern "C" {
#include "setsignal.h"
};

#ifdef USE_PERFTOOLS_DEBUG
HeapLeakChecker* heap_checker = 0;
int perftools_leaks = 0;
int perftools_profile = 0;
#endif

DNS_Mgr* dns_mgr;
TimerMgr* timer_mgr;
zeek::ValManager* zeek::val_mgr = nullptr;
zeek::ValManager*& val_mgr = zeek::val_mgr;
logging::Manager* log_mgr = nullptr;
threading::Manager* thread_mgr = nullptr;
input::Manager* input_mgr = nullptr;
zeek::plugin::Manager* plugin_mgr = nullptr;
analyzer::Manager* analyzer_mgr = nullptr;
file_analysis::Manager* file_mgr = nullptr;
zeekygen::Manager* zeekygen_mgr = nullptr;
iosource::Manager* iosource_mgr = nullptr;
bro_broker::Manager* broker_mgr = nullptr;
zeek::Supervisor* zeek::supervisor_mgr = nullptr;
zeek::detail::trigger::Manager* trigger_mgr = nullptr;

std::vector<std::string> zeek_script_prefixes;
zeek::detail::Stmt* stmts;
RuleMatcher* rule_matcher = nullptr;
EventRegistry* event_registry = nullptr;
ProfileLogger* profiling_logger = nullptr;
ProfileLogger* segment_logger = nullptr;
SampleLogger* sample_logger = nullptr;
int signal_val = 0;
extern char version[];
const char* command_line_policy = nullptr;
vector<string> params;
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

// Keep copy of command line
int bro_argc;
char** bro_argv;

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

static std::vector<const char*> to_cargs(const std::vector<std::string>& args)
	{
	std::vector<const char*> rval;
	rval.reserve(args.size());

	for ( const auto& arg : args )
		rval.emplace_back(arg.data());

	return rval;
	}

bool show_plugins(int level)
	{
	zeek::plugin::Manager::plugin_list plugins = plugin_mgr->ActivePlugins();

	if ( ! plugins.size() )
		{
		printf("No plugins registered, not even any built-ins. This is probably a bug.\n");
		return false;
		}

	ODesc d;

	if ( level == 1 )
		d.SetShort();

	int count = 0;

	for ( zeek::plugin::Manager::plugin_list::const_iterator i = plugins.begin(); i != plugins.end(); i++ )
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

	zeek::plugin::Manager::inactive_plugin_list inactives = plugin_mgr->InactivePlugins();

	if ( inactives.size() && ! requested_plugins.size() )
		{
		printf("\nInactive dynamic plugins:\n");

		for ( zeek::plugin::Manager::inactive_plugin_list::const_iterator i = inactives.begin(); i != inactives.end(); i++ )
			{
			string name = (*i).first;
			string path = (*i).second;
			printf("  %s (%s)\n", name.c_str(), path.c_str());
			}
		}

	return count != 0;
	}

void done_with_network()
	{
	set_processing_status("TERMINATING", "done_with_network");

	// Cancel any pending alarms (watchdog, in particular).
	(void) alarm(0);

	if ( net_done )
		{
		mgr.Drain();
		// Don't propagate this event to remote clients.
		mgr.Dispatch(new Event(net_done,
		                       {zeek::make_intrusive<zeek::TimeVal>(timer_mgr->Time())}),
		             true);
		}

	if ( profiling_logger )
		profiling_logger->Log();

	terminating = true;

	analyzer_mgr->Done();
	timer_mgr->Expire();
	dns_mgr->Flush();
	mgr.Drain();
	mgr.Drain();

	net_finish(1);

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

void terminate_bro()
	{
	set_processing_status("TERMINATING", "terminate_bro");

	terminating = true;

	iosource_mgr->Wakeup("terminate_bro");

	// File analysis termination may produce events, so do it early on in
	// the termination process.
	file_mgr->Terminate();

	brofiler.WriteStats();

	if ( zeek_done )
		mgr.Enqueue(zeek_done, zeek::Args{});

	timer_mgr->Expire();
	mgr.Drain();

	if ( profiling_logger )
		{
		// FIXME: There are some occasional crashes in the memory
		// allocation code when killing Bro.  Disabling this for now.
		if ( ! (signal_val == SIGTERM || signal_val == SIGINT) )
			profiling_logger->Log();

		delete profiling_logger;
		}

	mgr.Drain();

	notifier::registry.Terminate();
	log_mgr->Terminate();
	input_mgr->Terminate();
	thread_mgr->Terminate();
	broker_mgr->Terminate();
	dns_mgr->Terminate();

	mgr.Drain();

	plugin_mgr->FinishPlugins();

	delete zeekygen_mgr;
	delete analyzer_mgr;
	delete file_mgr;
	// broker_mgr, timer_mgr, and supervisor are deleted via iosource_mgr
	delete iosource_mgr;
	delete event_registry;
	delete log_mgr;
	delete reporter;
	delete plugin_mgr;
	delete zeek::val_mgr;

	// free the global scope
	zeek::detail::pop_scope();

	reporter = nullptr;
	}

void zeek_terminate_loop(const char* reason)
	{
	set_processing_status("TERMINATING", reason);
	reporter->Info("%s", reason);

	net_get_final_stats();
	done_with_network();
	net_delete();

	terminate_bro();

	// Close files after net_delete(), because net_delete()
	// might write to connection content files.
	BroFile::CloseOpenFiles();

	delete rule_matcher;

	exit(0);
	}

RETSIGTYPE sig_handler(int signo)
	{
	set_processing_status("TERMINATING", "sig_handler");
	signal_val = signo;

	if ( ! terminating )
		iosource_mgr->Wakeup("sig_handler");

	return RETSIGVAL;
	}

static void atexit_handler()
	{
	set_processing_status("TERMINATED", "atexit");
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
		copy_string(zeek::id::find_val("signature_files")->AsString()->CheckString());

	char* tmp = script_signature_files;
	char* s;
	while ( (s = strsep(&tmp, " \t")) )
		if ( *s )
			rval.emplace_back(s);

	delete [] script_signature_files;
	return rval;
	}

zeek::detail::SetupResult zeek::detail::setup(int argc, char** argv,
                                              zeek::Options* zopts)
	{
	ZEEK_LSAN_DISABLE();
	std::set_new_handler(bro_new_handler);

	auto zeek_exe_path = get_exe_path(argv[0]);

	if ( zeek_exe_path.empty() )
		{
		fprintf(stderr, "failed to get path to executable '%s'", argv[0]);
		exit(1);
		}

	bro_argc = argc;
	bro_argv = new char* [argc];

	for ( int i = 0; i < argc; i++ )
		bro_argv[i] = copy_string(argv[i]);

	auto options = zopts ? *zopts : zeek::parse_cmdline(argc, argv);

	if ( options.print_usage )
		zeek::usage(argv[0], 0);

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

	auto stem = zeek::Supervisor::CreateStem(options.supervisor_mode);

	if ( zeek::Supervisor::ThisNode() )
		zeek::Supervisor::ThisNode()->Init(&options);

	brofiler.ReadStats();

	auto dns_type = options.dns_mode;

	if ( dns_type == DNS_DEFAULT && zeek::fake_dns() )
		dns_type = DNS_FAKE;

	RETSIGTYPE (*oldhandler)(int);

	zeek_script_prefixes = options.script_prefixes;
	auto zeek_prefixes = zeekenv("ZEEK_PREFIXES");

	if ( zeek_prefixes )
		tokenize_string(zeek_prefixes, ":", &zeek_script_prefixes);

	pseudo_realtime = options.pseudo_realtime;

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
		proc_status_file = copy_string(options.process_status_file->data());

	atexit(atexit_handler);
	set_processing_status("INITIALIZING", "main");

	bro_start_time = current_time(true);

	zeek::val_mgr = new ValManager();
	reporter = new Reporter(options.abort_on_scripting_errors);
	thread_mgr = new threading::Manager();
	plugin_mgr = new zeek::plugin::Manager();

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
		zeek::Supervisor::Config cfg = {};
		cfg.zeek_exe_path = zeek_exe_path;
		options.filter_supervisor_options();
		zeek::supervisor_mgr = new zeek::Supervisor(std::move(cfg), std::move(*stem));
		}

	const char* seed_load_file = zeekenv("ZEEK_SEED_FILE");

	if ( options.random_seed_input_file )
		seed_load_file = options.random_seed_input_file->data();

	init_random_seed((seed_load_file && *seed_load_file ? seed_load_file : nullptr),
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

#ifdef USE_IDMEF
	char* libidmef_dtd_path_cstr = new char[options.libidmef_dtd_file.size() + 1];
	safe_strncpy(libidmef_dtd_path_cstr, options.libidmef_dtd_file.data(),
	             options.libidmef_dtd_file.size());
	globalsInit(libidmef_dtd_path_cstr);	// Init LIBIDMEF globals
	createCurrentDoc("1.0");		// Set a global XML document
#endif

	timer_mgr = new PQ_TimerMgr();

	auto zeekygen_cfg = options.zeekygen_config_file.value_or("");
	zeekygen_mgr = new zeekygen::Manager(zeekygen_cfg, bro_argv[0]);

	add_essential_input_file("base/init-bare.zeek");
	add_essential_input_file("base/init-frameworks-and-bifs.zeek");

	if ( ! options.bare_mode )
		add_input_file("base/init-default.zeek");

	plugin_mgr->SearchDynamicPlugins(bro_plugin_path());

	if ( options.plugins_to_load.empty() && options.scripts_to_load.empty() &&
	     options.script_options_to_set.empty() &&
		 ! options.pcap_file && ! options.interface &&
	     ! options.identifier_to_print &&
	     ! command_line_policy && ! options.print_plugins &&
	     ! options.supervisor_mode && ! zeek::Supervisor::ThisNode() )
		add_input_file("-");

	for ( const auto& script_option : options.script_options_to_set )
		params.push_back(script_option);

	for ( const auto& plugin : options.plugins_to_load )
		requested_plugins.insert(plugin);

	for ( const auto& script : options.scripts_to_load )
		add_input_file(script.data());

	push_scope(nullptr, nullptr);

	dns_mgr = new DNS_Mgr(dns_type);

	// It would nice if this were configurable.  This is similar to the
	// chicken and the egg problem.  It would be configurable by parsing
	// policy, but we can't parse policy without DNS resolution.
	dns_mgr->SetDir(".state");

	iosource_mgr = new iosource::Manager();
	event_registry = new EventRegistry();
	analyzer_mgr = new analyzer::Manager();
	log_mgr = new logging::Manager();
	input_mgr = new input::Manager();
	file_mgr = new file_analysis::Manager();
	auto broker_real_time = ! options.pcap_file && ! options.deterministic_mode;
	broker_mgr = new bro_broker::Manager(broker_real_time);
	trigger_mgr = new zeek::detail::trigger::Manager();

	plugin_mgr->InitPreScript();
	analyzer_mgr->InitPreScript();
	file_mgr->InitPreScript();
	zeekygen_mgr->InitPreScript();

	bool missing_plugin = false;

	for ( set<string>::const_iterator i = requested_plugins.begin();
	      i != requested_plugins.end(); i++ )
		{
		if ( ! plugin_mgr->ActivateDynamicPlugin(*i) )
			missing_plugin = true;
		}

	if ( missing_plugin )
		reporter->FatalError("Failed to activate requested dynamic plugin(s).");

	plugin_mgr->ActivateDynamicPlugins(! options.bare_mode);

	init_event_handlers();

	md5_type = zeek::make_intrusive<zeek::OpaqueType>("md5");
	sha1_type = zeek::make_intrusive<zeek::OpaqueType>("sha1");
	sha256_type = zeek::make_intrusive<zeek::OpaqueType>("sha256");
	entropy_type = zeek::make_intrusive<zeek::OpaqueType>("entropy");
	cardinality_type = zeek::make_intrusive<zeek::OpaqueType>("cardinality");
	topk_type = zeek::make_intrusive<zeek::OpaqueType>("topk");
	bloomfilter_type = zeek::make_intrusive<zeek::OpaqueType>("bloomfilter");
	x509_opaque_type = zeek::make_intrusive<zeek::OpaqueType>("x509");
	ocsp_resp_opaque_type = zeek::make_intrusive<zeek::OpaqueType>("ocsp_resp");
	paraglob_type = zeek::make_intrusive<zeek::OpaqueType>("paraglob");

	// The leak-checker tends to produce some false
	// positives (memory which had already been
	// allocated before we start the checking is
	// nevertheless reported; see perftools docs), thus
	// we suppress some messages here.

#ifdef USE_PERFTOOLS_DEBUG
	{
	HeapLeakChecker::Disabler disabler;
#endif

	is_parsing = true;
	yyparse();
	is_parsing = false;

	RecordVal::DoneParsing();
	TableVal::DoneParsing();

	init_general_global_var();
	init_net_var();
	init_builtin_funcs_subdirs();

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
	timer_mgr->InitPostScript();
	mgr.InitPostScript();

	if ( zeek::supervisor_mgr )
		zeek::supervisor_mgr->InitPostScript();

	if ( options.print_plugins )
		{
		bool success = show_plugins(options.print_plugins);
		exit(success ? 0 : 1);
		}

	analyzer_mgr->InitPostScript();
	file_mgr->InitPostScript();
	dns_mgr->InitPostScript();

	if ( options.parse_only )
		{
		int rc = (reporter->Errors() > 0 ? 1 : 0);
		exit(rc);
		}

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

		id->SetVal(zeek::make_intrusive<zeek::StringVal>(*options.pcap_filter));
		}

	auto all_signature_files = options.signature_files;

	// Append signature files defined in "signature_files" script option
	for ( auto&& sf : get_script_signature_files() )
		all_signature_files.emplace_back(std::move(sf));

	// Append signature files defined in @load-sigs
	for ( const auto& sf : sig_files )
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
		const auto& interfaces_val = zeek::id::find_val("interfaces");
		if ( interfaces_val )
			{
			char* interfaces_str =
				interfaces_val->AsString()->Render();

			if ( interfaces_str[0] != '\0' )
				options.interface = interfaces_str;

			delete [] interfaces_str;
			}
		}

	if ( dns_type != DNS_PRIME )
		net_init(options.interface, options.pcap_file, options.pcap_output_file, options.use_watchdog);

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

		mgr.Drain();
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
		const auto& profiling_file = zeek::id::find_val("profiling_file");
		profiling_logger = new ProfileLogger(profiling_file->AsFile(),
			profiling_interval);

		if ( segment_profiling )
			segment_logger = profiling_logger;
		}

	if ( ! reading_live && ! reading_traces )
		// Set up network_time to track real-time, since
		// we don't have any other source for it.
		net_update_time(current_time());

	if ( zeek_init )
		mgr.Enqueue(zeek_init, zeek::Args{});

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

	if ( stmts )
		{
		stmt_flow_type flow;
		Frame f(current_scope()->Length(), nullptr, nullptr);
		g_frame_stack.push_back(&f);

		try
			{
			stmts->Exec(&f, flow);
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
		for ( std::list<ScannedFile>::iterator i = files_scanned.begin(); i != files_scanned.end(); i++ )
			{
			if ( i->skipped )
				continue;

			mgr.Enqueue(zeek_script_loaded,
			            zeek::make_intrusive<zeek::StringVal>(i->name.c_str()),
			            zeek::val_mgr->Count(i->include_level));
			}
		}

	reporter->ReportViaEvents(true);

	// Drain the event queue here to support the protocols framework configuring DPM
	mgr.Drain();

	if ( reporter->Errors() > 0 && ! zeekenv("ZEEK_ALLOW_INIT_ERRORS") )
		reporter->FatalError("errors occurred while initializing");

	broker_mgr->ZeekInitDone();
	reporter->ZeekInitDone();
	analyzer_mgr->DumpDebug();

	have_pending_timers = ! reading_traces && timer_mgr->Size() > 0;

	return {0, std::move(options)};
	}

int zeek::detail::cleanup(bool did_net_run)
	{
	if ( did_net_run )
		done_with_network();

	net_delete();
	terminate_bro();

	sqlite3_shutdown();

	ERR_free_strings();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();

	// Close files after net_delete(), because net_delete()
	// might write to connection content files.
	BroFile::CloseOpenFiles();

	delete rule_matcher;

	return 0;
	}
