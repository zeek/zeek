// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <list>
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#ifdef USE_CURL
#include <curl/curl.h>
#endif

#ifdef USE_IDMEF
extern "C" {
#include <libidmef/idmefxml.h>
}
#endif

#include <openssl/md5.h>

extern "C" void OPENSSL_add_all_algorithms_conf(void);

#include "bsd-getopt-long.h"
#include "input.h"
#include "ScriptAnaly.h"
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
#include "Debug.h"
#include "DFA.h"
#include "RuleMatcher.h"
#include "Anon.h"
#include "Serializer.h"
#include "RemoteSerializer.h"
#include "PersistenceSerializer.h"
#include "EventRegistry.h"
#include "Stats.h"
#include "Brofiler.h"

#include "threading/Manager.h"
#include "input/Manager.h"
#include "logging/Manager.h"
#include "logging/writers/Ascii.h"
#include "input/readers/Raw.h"
#include "analyzer/Manager.h"
#include "analyzer/Tag.h"
#include "plugin/Manager.h"
#include "file_analysis/Manager.h"
#include "broxygen/Manager.h"

#include "binpac_bro.h"

#include "3rdparty/sqlite3.h"

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

const char* prog;
char* writefile = 0;
name_list prefixes;
DNS_Mgr* dns_mgr;
TimerMgr* timer_mgr;
logging::Manager* log_mgr = 0;
threading::Manager* thread_mgr = 0;
input::Manager* input_mgr = 0;
plugin::Manager* plugin_mgr = 0;
analyzer::Manager* analyzer_mgr = 0;
file_analysis::Manager* file_mgr = 0;
broxygen::Manager* broxygen_mgr = 0;
Stmt* stmts;
EventHandlerPtr net_done = 0;
RuleMatcher* rule_matcher = 0;
PersistenceSerializer* persistence_serializer = 0;
FileSerializer* event_serializer = 0;
FileSerializer* state_serializer = 0;
RemoteSerializer* remote_serializer = 0;
EventPlayer* event_player = 0;
EventRegistry* event_registry = 0;
ProfileLogger* profiling_logger = 0;
ProfileLogger* segment_logger = 0;
SampleLogger* sample_logger = 0;
int signal_val = 0;
int optimize = 0;
int do_notice_analysis = 0;
int rule_bench = 0;
SecondaryPath* secondary_path = 0;
extern char version[];
char* command_line_policy = 0;
vector<string> params;
char* proc_status_file = 0;
int snaplen = 0;	// this gets set from the scripting-layer's value

OpaqueType* md5_type = 0;
OpaqueType* sha1_type = 0;
OpaqueType* sha256_type = 0;
OpaqueType* entropy_type = 0;
OpaqueType* cardinality_type = 0;
OpaqueType* topk_type = 0;
OpaqueType* bloomfilter_type = 0;
OpaqueType* x509_opaque_type = 0;

// Keep copy of command line
int bro_argc;
char** bro_argv;

const char* bro_version()
	{
#ifdef DEBUG
	static char* debug_version = 0;

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

const char* bro_dns_fake()
	{
	if ( ! getenv("BRO_DNS_FAKE") )
		return "off";
	else
		return "on";
	}

void usage()
	{
	fprintf(stderr, "bro version %s\n", bro_version());
	fprintf(stderr, "usage: %s [options] [file ...]\n", prog);
	fprintf(stderr, "    <file>                         | policy file, or read stdin\n");
	fprintf(stderr, "    -a|--parse-only                | exit immediately after parsing scripts\n");
	fprintf(stderr, "    -b|--bare-mode                 | don't load scripts from the base/ directory\n");
	fprintf(stderr, "    -d|--debug-policy              | activate policy file debugging\n");
	fprintf(stderr, "    -e|--exec <bro code>           | augment loaded policies by given code\n");
	fprintf(stderr, "    -f|--filter <filter>           | tcpdump filter\n");
	fprintf(stderr, "    -g|--dump-config               | dump current config into .state dir\n");
	fprintf(stderr, "    -h|--help|-?                   | command line help\n");
	fprintf(stderr, "    -i|--iface <interface>         | read from given interface\n");
	fprintf(stderr, "    -p|--prefix <prefix>           | add given prefix to policy file resolution\n");
	fprintf(stderr, "    -r|--readfile <readfile>       | read from given tcpdump file\n");
	fprintf(stderr, "    -y|--flowfile <file>[=<ident>] | read from given flow file\n");
	fprintf(stderr, "    -Y|--netflow <ip>:<prt>[=<id>] | read flow from socket\n");
	fprintf(stderr, "    -s|--rulefile <rulefile>       | read rules from given file\n");
	fprintf(stderr, "    -t|--tracefile <tracefile>     | activate execution tracing\n");
	fprintf(stderr, "    -w|--writefile <writefile>     | write to given tcpdump file\n");
	fprintf(stderr, "    -v|--version                   | print version and exit\n");
	fprintf(stderr, "    -x|--print-state <file.bst>    | print contents of state file\n");
	fprintf(stderr, "    -z|--analyze <analysis>        | run the specified policy file analysis\n");
#ifdef DEBUG
	fprintf(stderr, "    -B|--debug <dbgstreams>        | Enable debugging output for selected streams\n");
#endif
	fprintf(stderr, "    -C|--no-checksums              | ignore checksums\n");
	fprintf(stderr, "    -D|--dfa-size <size>           | DFA state cache size\n");
	fprintf(stderr, "    -F|--force-dns                 | force DNS\n");
	fprintf(stderr, "    -I|--print-id <ID name>        | print out given ID\n");
	fprintf(stderr, "    -K|--md5-hashkey <hashkey>     | set key for MD5-keyed hashing\n");
	fprintf(stderr, "    -L|--rule-benchmark            | benchmark for rules\n");
	fprintf(stderr, "    -N|--print-plugins             | print available plugins and exit (-NN for verbose)\n");
	fprintf(stderr, "    -O|--optimize                  | optimize policy script\n");
	fprintf(stderr, "    -P|--prime-dns                 | prime DNS\n");
	fprintf(stderr, "    -R|--replay <events.bst>       | replay events\n");
	fprintf(stderr, "    -S|--debug-rules               | enable rule debugging\n");
	fprintf(stderr, "    -T|--re-level <level>          | set 'RE_level' for rules\n");
	fprintf(stderr, "    -U|--status-file <file>        | Record process status in file\n");
	fprintf(stderr, "    -W|--watchdog                  | activate watchdog timer\n");
	fprintf(stderr, "    -X|--broxygen                  | generate documentation based on config file\n");

#ifdef USE_PERFTOOLS_DEBUG
	fprintf(stderr, "    -m|--mem-leaks                 | show leaks  [perftools]\n");
	fprintf(stderr, "    -M|--mem-profile               | record heap [perftools]\n");
#endif
#if 0 // Broken
	fprintf(stderr, "    -X <file.bst>                  | print contents of state file as XML\n");
#endif
	fprintf(stderr, "    --pseudo-realtime[=<speedup>]  | enable pseudo-realtime for performance evaluation (default 1)\n");
	fprintf(stderr, "    --load-seeds <file>            | load seeds from given file\n");
	fprintf(stderr, "    --save-seeds <file>            | save seeds to given file\n");

#ifdef USE_IDMEF
	fprintf(stderr, "    -n|--idmef-dtd <idmef-msg.dtd> | specify path to IDMEF DTD file\n");
#endif

	fprintf(stderr, "    $BROPATH                       | file search path (%s)\n", bro_path());
	fprintf(stderr, "    $BRO_PREFIXES                  | prefix list (%s)\n", bro_prefixes().c_str());
	fprintf(stderr, "    $BRO_DNS_FAKE                  | disable DNS lookups (%s)\n", bro_dns_fake());
	fprintf(stderr, "    $BRO_SEED_FILE                 | file to load seeds from (not set)\n");
	fprintf(stderr, "    $BRO_LOG_SUFFIX                | ASCII log file extension (.%s)\n", logging::writer::Ascii::LogExt().c_str());
	fprintf(stderr, "    $BRO_PROFILER_FILE             | Output file for script execution statistics (not set)\n");
	fprintf(stderr, "    $BRO_DISABLE_BROXYGEN          | Disable Broxygen documentation support (%s)\n", getenv("BRO_DISABLE_BROXYGEN") ? "set" : "not set");

	fprintf(stderr, "\n");
	fprintf(stderr, "    Supported log formats: ");

	bool first = true;
	list<string> fmts = logging::Manager::SupportedFormats();

	for ( list<string>::const_iterator i = fmts.begin(); i != fmts.end(); ++i )
		{
		if ( *i == "None" )
			// Skip, it's uninteresting.
			continue;

		if ( ! first )
			fprintf(stderr, ",");

		fprintf(stderr, "%s", (*i).c_str());
		first = false;
		}

	fprintf(stderr, "\n");

	exit(1);
	}

void show_plugins(int level)
	{
	plugin::Manager::plugin_list plugins = plugin_mgr->Plugins();

	if ( ! plugins.size() )
		{
		printf("No plugins registered, not even any built-ins. This is probably a bug.\n");
		return;
		}

	ODesc d;

	if ( level == 1 )
		d.SetShort();

	for ( plugin::Manager::plugin_list::const_iterator i = plugins.begin(); i != plugins.end(); i++ )
		{
		(*i)->Describe(&d);

		if ( ! d.IsShort() )
			d.Add("\n");
		}

	printf("%s", d.Description());
	}

void done_with_network()
	{
	set_processing_status("TERMINATING", "done_with_network");

	// Release the port, which is important for checkpointing Bro.
	if ( remote_serializer )
		remote_serializer->StopListening();

	// Cancel any pending alarms (watchdog, in particular).
	(void) alarm(0);

	if ( net_done )
		{
		val_list* args = new val_list;
		args->append(new Val(timer_mgr->Time(), TYPE_TIME));
		mgr.Drain();

		// Don't propagate this event to remote clients.
		mgr.Dispatch(new Event(net_done, args), true);
		}

	// Save state before expiring the remaining events/timers.
	persistence_serializer->WriteState(false);

	if ( profiling_logger )
		profiling_logger->Log();

	terminating = true;

	analyzer_mgr->Done();
	timer_mgr->Expire();
	dns_mgr->Flush();
	mgr.Drain();
	mgr.Drain();

	if ( remote_serializer )
		remote_serializer->Finish();

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
	}

void terminate_bro()
	{
	set_processing_status("TERMINATING", "terminate_bro");

	terminating = true;

	brofiler.WriteStats();

	EventHandlerPtr bro_done = internal_handler("bro_done");
	if ( bro_done )
		mgr.QueueEvent(bro_done, new val_list);

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

	if ( remote_serializer )
		remote_serializer->LogStats();

	mgr.Drain();

	file_mgr->Terminate();
	log_mgr->Terminate();
	input_mgr->Terminate();
	thread_mgr->Terminate();

	mgr.Drain();

	plugin_mgr->FinishPlugins();

	delete broxygen_mgr;
	delete timer_mgr;
	delete dns_mgr;
	delete persistence_serializer;
	delete event_player;
	delete event_serializer;
	delete state_serializer;
	delete event_registry;
	delete secondary_path;
	delete remote_serializer;
	delete analyzer_mgr;
	delete log_mgr;
	delete plugin_mgr;
	delete thread_mgr;
	delete file_mgr;
	delete reporter;

	reporter = 0;
	}

void termination_signal()
	{
	set_processing_status("TERMINATING", "termination_signal");

	Val sval(signal_val, TYPE_COUNT);
	reporter->Info("received termination signal");
	net_get_final_stats();
	done_with_network();
	net_delete();

	terminate_bro();

	// Close files after net_delete(), because net_delete()
	// might write to connection content files.
	BroFile::CloseCachedFiles();

	delete rule_matcher;

	exit(0);
	}

RETSIGTYPE sig_handler(int signo)
	{
	set_processing_status("TERMINATING", "sig_handler");
	signal_val = signo;

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

int main(int argc, char** argv)
	{
	std::set_new_handler(bro_new_handler);

	brofiler.ReadStats();

	bro_argc = argc;
	bro_argv = new char* [argc];

	for ( int i = 0; i < argc; i++ )
		bro_argv[i] = copy_string(argv[i]);

	name_list interfaces;
	name_list read_files;
	name_list netflows;
	name_list flow_files;
	name_list rule_files;
	char* bst_file = 0;
	char* id_name = 0;
	char* events_file = 0;
	char* seed_load_file = getenv("BRO_SEED_FILE");
	char* seed_save_file = 0;
	char* user_pcap_filter = 0;
	char* debug_streams = 0;
	int parse_only = false;
	int bare_mode = false;
	int seed = 0;
	int dump_cfg = false;
	int to_xml = 0;
	int do_watchdog = 0;
	int override_ignore_checksums = 0;
	int rule_debug = 0;
	int RE_level = 4;
	int print_plugins = 0;

	static struct option long_opts[] = {
		{"parse-only",	no_argument,		0,	'a'},
		{"bare-mode",	no_argument,		0,	'b'},
		{"debug-policy",	no_argument,		0,	'd'},
		{"dump-config",		no_argument,		0,	'g'},
		{"exec",		required_argument,	0,	'e'},
		{"filter",		required_argument,	0,	'f'},
		{"help",		no_argument,		0,	'h'},
		{"iface",		required_argument,	0,	'i'},
		{"broxygen",		required_argument,		0,	'X'},
		{"prefix",		required_argument,	0,	'p'},
		{"readfile",		required_argument,	0,	'r'},
		{"flowfile",		required_argument,	0,	'y'},
		{"netflow",		required_argument,	0,	'Y'},
		{"rulefile",		required_argument,	0,	's'},
		{"tracefile",		required_argument,	0,	't'},
		{"writefile",		required_argument,	0,	'w'},
		{"version",		no_argument,		0,	'v'},
		{"print-state",		required_argument,	0,	'x'},
		{"analyze",		required_argument,	0,	'z'},
		{"no-checksums",	no_argument,		0,	'C'},
		{"dfa-cache",		required_argument,	0,	'D'},
		{"force-dns",		no_argument,		0,	'F'},
		{"load-seeds",		required_argument,	0,	'G'},
		{"save-seeds",		required_argument,	0,	'H'},
		{"set-seed",		required_argument,	0,	'J'},
		{"md5-hashkey",		required_argument,	0,	'K'},
		{"rule-benchmark",	no_argument,		0,	'L'},
		{"print-plugins",	no_argument,		0,	'N'},
		{"optimize",		no_argument,		0,	'O'},
		{"prime-dns",		no_argument,		0,	'P'},
		{"replay",		required_argument,	0,	'R'},
		{"debug-rules",		no_argument,		0,	'S'},
		{"re-level",		required_argument,	0,	'R'},
		{"watchdog",		no_argument,		0,	'W'},
		{"print-id",		required_argument,	0,	'I'},
		{"status-file",		required_argument,	0,	'U'},

#ifdef	DEBUG
		{"debug",		required_argument,	0,	'B'},
#endif
#ifdef	USE_IDMEF
		{"idmef-dtd",		required_argument,	0,	'n'},
#endif
#ifdef	USE_PERFTOOLS_DEBUG
		{"mem-leaks",	no_argument,		0,	'm'},
		{"mem-profile",	no_argument,		0,	'M'},
#endif

		{"pseudo-realtime",	optional_argument, 0,	'E'},

		{0,			0,			0,	0},
	};

	enum DNS_MgrMode dns_type = DNS_DEFAULT;

	dns_type = getenv("BRO_DNS_FAKE") ? DNS_FAKE : DNS_DEFAULT;

	RETSIGTYPE (*oldhandler)(int);

	prog = argv[0];

	prefixes.append(strdup(""));	// "" = "no prefix"

	char* p = getenv("BRO_PREFIXES");
	if ( p )
		add_to_name_list(p, ':', prefixes);

	string broxygen_config;

#ifdef USE_IDMEF
	string libidmef_dtd_path = "idmef-message.dtd";
#endif

	extern char* optarg;
	extern int optind, opterr;

	int long_optsind;
	opterr = 0;

	char opts[256];
	safe_strncpy(opts, "B:D:e:f:I:i:K:l:n:p:R:r:s:T:t:U:w:x:X:y:Y:z:CFGLNOPSWabdghv",
		     sizeof(opts));

#ifdef USE_PERFTOOLS_DEBUG
	strncat(opts, "mM", 2);
#endif

	int op;
	while ( (op = getopt_long(argc, argv, opts, long_opts, &long_optsind)) != EOF )
		switch ( op ) {
		case 'a':
			parse_only = true;
			break;

		case 'b':
			bare_mode = true;
			break;

		case 'd':
			fprintf(stderr, "Policy file debugging ON.\n");
			g_policy_debug = true;
			break;

		case 'e':
			command_line_policy = optarg;
			break;

		case 'f':
			user_pcap_filter = optarg;
			break;

		case 'g':
			dump_cfg = true;
			break;

		case 'i':
			interfaces.append(optarg);
			break;

		case 'p':
			prefixes.append(optarg);
			break;

		case 'r':
			read_files.append(optarg);
			break;

		case 's':
			rule_files.append(optarg);
			break;

		case 't':
			g_trace_state.SetTraceFile(optarg);
			g_trace_state.TraceOn();
			break;

		case 'w':
			writefile = optarg;
			break;

		case 'y':
			flow_files.append(optarg);
			break;

		case 'z':
			if ( streq(optarg, "notice") )
				do_notice_analysis = 1;
			else
				{
				fprintf(stderr, "Unknown analysis type: %s\n", optarg);
				exit(1);
				}
			break;

		case 'C':
			override_ignore_checksums = 1;
			break;

		case 'D':
			dfa_state_cache_size = atoi(optarg);
			break;

		case 'E':
			pseudo_realtime = 1.0;
			if ( optarg )
				pseudo_realtime = atof(optarg);
			break;

		case 'F':
			if ( dns_type != DNS_DEFAULT )
				usage();
			dns_type = DNS_FORCE;
			break;

		case 'G':
			seed_load_file = optarg;
			break;

		case 'H':
			seed_save_file = optarg;
			break;

		case 'I':
			id_name = optarg;
			break;

		case 'J':
			seed = atoi(optarg);
			break;

		case 'K':
			MD5((const u_char*) optarg, strlen(optarg), shared_hmac_md5_key);
			hmac_key_set = 1;
			break;

		case 'L':
			++rule_bench;
			break;

		case 'N':
			++print_plugins;
			break;

		case 'O':
			optimize = 1;
			break;

		case 'P':
			if ( dns_type != DNS_DEFAULT )
				usage();
			dns_type = DNS_PRIME;
			break;

		case 'R':
			events_file = optarg;
			break;

		case 'S':
			rule_debug = 1;
			break;

		case 'T':
			RE_level = atoi(optarg);
			break;

		case 'U':
			proc_status_file = optarg;
			break;

		case 'W':
			do_watchdog = 1;
			break;

		case 'Y':
			netflows.append(optarg);
			break;

		case 'h':
			usage();
			break;

		case 'v':
			fprintf(stderr, "%s version %s\n", prog, bro_version());
			exit(0);
			break;

#ifdef USE_PERFTOOLS_DEBUG
		case 'm':
			perftools_leaks = 1;
			break;

		case 'M':
			perftools_profile = 1;
			break;
#endif

		case 'x':
			bst_file = optarg;
			break;
#if 0 // broken
		case 'X':
			bst_file = optarg;
			to_xml = 1;
			break;
#endif

		case 'X':
			broxygen_config = optarg;
			break;

#ifdef USE_IDMEF
		case 'n':
			fprintf(stderr, "Using IDMEF XML DTD from %s\n", optarg);
			libidmef_dtd_path = optarg;
			break;
#endif

		case 'B':
			debug_streams = optarg;
			break;

		case 0:
			// This happens for long options that don't have
			// a short-option equivalent.
			break;

		case '?':
		default:
			usage();
			break;
		}

	atexit(atexit_handler);
	set_processing_status("INITIALIZING", "main");

	bro_start_time = current_time(true);

	reporter = new Reporter();
	thread_mgr = new threading::Manager();

#ifdef DEBUG
	if ( debug_streams )
		debug_logger.EnableStreams(debug_streams);
#endif

	init_random_seed(seed, (seed_load_file && *seed_load_file ? seed_load_file : 0) , seed_save_file);
	// DEBUG_MSG("HMAC key: %s\n", md5_digest_print(shared_hmac_md5_key));
	init_hash_function();

	ERR_load_crypto_strings();
	OPENSSL_add_all_algorithms_conf();
	SSL_library_init();
	SSL_load_error_strings();

#ifdef USE_CURL
	curl_global_init(CURL_GLOBAL_ALL);
#endif

	int r = sqlite3_initialize();

	if ( r != SQLITE_OK )
		reporter->Error("Failed to initialize sqlite3: %s", sqlite3_errstr(r));

	// FIXME: On systems that don't provide /dev/urandom, OpenSSL doesn't
	// seed the PRNG. We should do this here (but at least Linux, FreeBSD
	// and Solaris provide /dev/urandom).

	if ( (interfaces.length() > 0 || netflows.length() > 0) &&
	     (read_files.length() > 0 || flow_files.length() > 0 ))
		usage();

#ifdef USE_IDMEF
	char* libidmef_dtd_path_cstr = new char[libidmef_dtd_path.length() + 1];
	safe_strncpy(libidmef_dtd_path_cstr, libidmef_dtd_path.c_str(),
		     libidmef_dtd_path.length());
	globalsInit(libidmef_dtd_path_cstr);	// Init LIBIDMEF globals
	createCurrentDoc("1.0");		// Set a global XML document
#endif

	timer_mgr = new PQ_TimerMgr("<GLOBAL>");
	// timer_mgr = new CQ_TimerMgr();

	broxygen_mgr = new broxygen::Manager(broxygen_config, bro_argv[0]);

	add_input_file("base/init-bare.bro");
	if ( ! bare_mode )
		add_input_file("base/init-default.bro");

	if ( optind == argc &&
	     read_files.length() == 0 && flow_files.length() == 0 &&
	     interfaces.length() == 0 &&
	     ! (id_name || bst_file) && ! command_line_policy && ! print_plugins )
		add_input_file("-");

	// Process remaining arguments.  X=Y arguments indicate script
	// variable/parameter assignments.  The remainder are treated
	// as scripts to load.
	while ( optind < argc )
		{
		if ( strchr(argv[optind], '=') )
			params.push_back(argv[optind++]);
		else
			add_input_file(argv[optind++]);
		}

	push_scope(0);

	dns_mgr = new DNS_Mgr(dns_type);

	// It would nice if this were configurable.  This is similar to the
	// chicken and the egg problem.  It would be configurable by parsing
	// policy, but we can't parse policy without DNS resolution.
	dns_mgr->SetDir(".state");

	persistence_serializer = new PersistenceSerializer();
	remote_serializer = new RemoteSerializer();
	event_registry = new EventRegistry();
	analyzer_mgr = new analyzer::Manager();
	log_mgr = new logging::Manager();
	input_mgr = new input::Manager();
	plugin_mgr = new plugin::Manager();
	file_mgr = new file_analysis::Manager();

	plugin_mgr->InitPreScript();
	analyzer_mgr->InitPreScript();
	file_mgr->InitPreScript();
	broxygen_mgr->InitPreScript();

	if ( events_file )
		event_player = new EventPlayer(events_file);

	init_event_handlers();

	input::reader::Raw::ClassInit();

	md5_type = new OpaqueType("md5");
	sha1_type = new OpaqueType("sha1");
	sha256_type = new OpaqueType("sha256");
	entropy_type = new OpaqueType("entropy");
	cardinality_type = new OpaqueType("cardinality");
	topk_type = new OpaqueType("topk");
	bloomfilter_type = new OpaqueType("bloomfilter");
	x509_opaque_type = new OpaqueType("x509");

	// The leak-checker tends to produce some false
	// positives (memory which had already been
	// allocated before we start the checking is
	// nevertheless reported; see perftools docs), thus
	// we suppress some messages here.

#ifdef USE_PERFTOOLS_DEBUG
	{
	HeapLeakChecker::Disabler disabler;
#endif

	yyparse();

	plugin_mgr->InitPostScript();
	analyzer_mgr->InitPostScript();
	file_mgr->InitPostScript();
	broxygen_mgr->InitPostScript();

	if ( print_plugins )
		{
		show_plugins(print_plugins);
		exit(1);
		}

	if ( parse_only )
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

	init_general_global_var();

	broxygen_mgr->GenerateDocs();

	if ( user_pcap_filter )
		{
		ID* id = global_scope()->Lookup("cmd_line_bpf_filter");

		if ( ! id )
			reporter->InternalError("global cmd_line_bpf_filter not defined");

		id->SetVal(new StringVal(user_pcap_filter));
		}

	// Parse rule files defined on the script level.
	char* script_rule_files =
		copy_string(internal_val("signature_files")->AsString()->CheckString());

	char* tmp = script_rule_files;
	char* s;
	while ( (s = strsep(&tmp, " \t")) )
		if ( *s )
			rule_files.append(s);

	// Append signature files defined in @load-sigs
	for ( size_t i = 0; i < sig_files.size(); ++i )
		rule_files.append(copy_string(sig_files[i].c_str()));

	if ( rule_files.length() > 0 )
		{
		rule_matcher = new RuleMatcher(RE_level);
		if ( ! rule_matcher->ReadFiles(rule_files) )
			{
			delete dns_mgr;
			exit(1);
			}

		if ( rule_debug )
			rule_matcher->PrintDebug();

		file_mgr->InitMagic();
		}

	delete [] script_rule_files;

	if ( g_policy_debug )
		// ### Add support for debug command file.
		dbg_init_debugger(0);

	if ( (flow_files.length() == 0 || read_files.length() == 0) &&
	     (netflows.length() == 0 || interfaces.length() == 0) )
		{
		Val* interfaces_val = internal_val("interfaces");
		if ( interfaces_val )
			{
			char* interfaces_str =
				interfaces_val->AsString()->Render();

			if ( interfaces_str[0] != '\0' )
				add_to_name_list(interfaces_str, ' ', interfaces);

			delete [] interfaces_str;
			}
		}

	snaplen = internal_val("snaplen")->AsCount();

	// Initialize the secondary path, if it's needed.
	secondary_path = new SecondaryPath();

	if ( dns_type != DNS_PRIME )
		net_init(interfaces, read_files, netflows, flow_files,
			writefile, "",
			secondary_path->Filter(), do_watchdog);

	BroFile::SetDefaultRotation(log_rotate_interval, log_max_size);

	net_done = internal_handler("net_done");

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

	// Just read state file from disk.
	if ( bst_file )
		{
		if ( to_xml )
			{
			BinarySerializationFormat* b =
				new BinarySerializationFormat();
			XMLSerializationFormat* x = new XMLSerializationFormat();
			ConversionSerializer s(b, x);
			s.Convert(bst_file, "/dev/stdout");
			}
		else
			{
			FileSerializer s;
			UnserialInfo info(&s);
			info.print = stdout;
			info.install_uniques = true;
			if ( ! s.Read(&info, bst_file) )
				reporter->Error("Failed to read events from %s\n", bst_file);
			}

		exit(0);
		}

	persistence_serializer->SetDir((const char *)state_dir->AsString()->CheckString());

	// Print the ID.
	if ( id_name )
		{
		persistence_serializer->ReadAll(true, false);

		ID* id = global_scope()->Lookup(id_name);
		if ( ! id )
			reporter->FatalError("No such ID: %s\n", id_name);

		ODesc desc;
		desc.SetQuotes(true);
		desc.SetIncludeStats(true);
		id->DescribeExtended(&desc);

		fprintf(stdout, "%s\n", desc.Description());
		exit(0);
		}

	persistence_serializer->ReadAll(true, true);

	if ( dump_cfg )
		{
		persistence_serializer->WriteConfig(false);
		exit(0);
		}

	if ( profiling_interval > 0 )
		{
		profiling_logger = new ProfileLogger(profiling_file->AsFile(),
			profiling_interval);

		if ( segment_profiling )
			segment_logger = profiling_logger;
		}

	if ( ! reading_live && ! reading_traces )
		// Set up network_time to track real-time, since
		// we don't have any other source for it.
		network_time = current_time();

	EventHandlerPtr bro_init = internal_handler("bro_init");
	if ( bro_init )	//### this should be a function
		mgr.QueueEvent(bro_init, new val_list);

	EventRegistry::string_list* dead_handlers =
		event_registry->UnusedHandlers();

	if ( dead_handlers->length() > 0 && check_for_unused_event_handlers )
		{
		for ( int i = 0; i < dead_handlers->length(); ++i )
			reporter->Warning("event handler never invoked: %s", (*dead_handlers)[i]);
		}

	delete dead_handlers;

	EventRegistry::string_list* alive_handlers =
		event_registry->UsedHandlers();

	if ( alive_handlers->length() > 0 && dump_used_event_handlers )
		{
		reporter->Info("invoked event handlers:");
		for ( int i = 0; i < alive_handlers->length(); ++i )
			reporter->Info("%s", (*alive_handlers)[i]);
		}

	delete alive_handlers;

	if ( do_notice_analysis )
		notice_analysis();

	if ( stmts )
		{
		stmt_flow_type flow;
		Frame f(current_scope()->Length(), 0, 0);
		g_frame_stack.push_back(&f);
		stmts->Exec(&f, flow);
		g_frame_stack.pop_back();
		}

	if ( override_ignore_checksums )
		ignore_checksums = 1;

	// Queue events reporting loaded scripts.
	for ( std::list<ScannedFile>::iterator i = files_scanned.begin(); i != files_scanned.end(); i++ )
		{
		if ( i->skipped )
			continue;

		val_list* vl = new val_list;
		vl->append(new StringVal(i->name.c_str()));
		vl->append(new Val(i->include_level, TYPE_COUNT));
		mgr.QueueEvent(bro_script_loaded, vl);
		}

	reporter->ReportViaEvents(true);

	// Drain the event queue here to support the protocols framework configuring DPM
	mgr.Drain();

	analyzer_mgr->DumpDebug();

	have_pending_timers = ! reading_traces && timer_mgr->Size() > 0;

	io_sources.Register(thread_mgr, true);

	if ( io_sources.Size() > 0 ||
	     have_pending_timers ||
	     BifConst::exit_only_after_terminate )
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

		net_run();
		done_with_network();
		net_delete();

#ifdef USE_CURL
		curl_global_cleanup();
#endif

		terminate_bro();

		sqlite3_shutdown();

		// Close files after net_delete(), because net_delete()
		// might write to connection content files.
		BroFile::CloseCachedFiles();
		}
	else
		{
		persistence_serializer->WriteState(false);
		terminate_bro();
		}

	delete rule_matcher;

	return 0;
	}
