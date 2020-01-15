// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <list>
#include <optional>
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#ifdef USE_IDMEF
extern "C" {
#include <libidmef/idmefxml.h>
}
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "bsd-getopt-long.h"
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
#include "Debug.h"
#include "DFA.h"
#include "RuleMatcher.h"
#include "Anon.h"
#include "EventRegistry.h"
#include "Stats.h"
#include "Brofiler.h"
#include "Traverse.h"

#include "Supervisor.h"
#include "threading/Manager.h"
#include "input/Manager.h"
#include "logging/Manager.h"
#include "logging/writers/ascii/Ascii.h"
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

#include "zeek-affinity.h"

#ifdef USE_PERFTOOLS_DEBUG
HeapLeakChecker* heap_checker = 0;
int perftools_leaks = 0;
int perftools_profile = 0;
#endif

DNS_Mgr* dns_mgr;
TimerMgr* timer_mgr;
ValManager* val_mgr = 0;
PortManager* port_mgr = 0;
logging::Manager* log_mgr = 0;
threading::Manager* thread_mgr = 0;
input::Manager* input_mgr = 0;
plugin::Manager* plugin_mgr = 0;
analyzer::Manager* analyzer_mgr = 0;
file_analysis::Manager* file_mgr = 0;
zeekygen::Manager* zeekygen_mgr = 0;
iosource::Manager* iosource_mgr = 0;
bro_broker::Manager* broker_mgr = 0;
zeek::Supervisor* zeek::supervisor = 0;
std::optional<zeek::Supervisor::NodeConfig> zeek::supervised_node;

std::vector<std::string> zeek_script_prefixes;
Stmt* stmts;
EventHandlerPtr net_done = 0;
RuleMatcher* rule_matcher = 0;
EventRegistry* event_registry = 0;
ProfileLogger* profiling_logger = 0;
ProfileLogger* segment_logger = 0;
SampleLogger* sample_logger = 0;
int signal_val = 0;
extern char version[];
const char* command_line_policy = 0;
vector<string> params;
set<string> requested_plugins;
const char* proc_status_file = 0;

OpaqueType* md5_type = 0;
OpaqueType* sha1_type = 0;
OpaqueType* sha256_type = 0;
OpaqueType* entropy_type = 0;
OpaqueType* cardinality_type = 0;
OpaqueType* topk_type = 0;
OpaqueType* bloomfilter_type = 0;
OpaqueType* x509_opaque_type = 0;
OpaqueType* ocsp_resp_opaque_type = 0;
OpaqueType* paraglob_type = 0;

// Keep copy of command line
int bro_argc;
char** bro_argv;

const char* zeek_version()
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

static bool zeek_dns_fake()
	{
	return zeekenv("ZEEK_DNS_FAKE");
	}

static void usage(const char* prog, int code = 1)
	{
	fprintf(stderr, "zeek version %s\n", zeek_version());

	fprintf(stderr, "usage: %s [options] [file ...]\n", prog);
	fprintf(stderr, "usage: %s --test [doctest-options] -- [options] [file ...]\n", prog);
	fprintf(stderr, "    <file>                         | Zeek script file, or read stdin\n");
	fprintf(stderr, "    -a|--parse-only                | exit immediately after parsing scripts\n");
	fprintf(stderr, "    -b|--bare-mode                 | don't load scripts from the base/ directory\n");
	fprintf(stderr, "    -d|--debug-script              | activate Zeek script debugging\n");
	fprintf(stderr, "    -e|--exec <zeek code>          | augment loaded scripts by given code\n");
	fprintf(stderr, "    -f|--filter <filter>           | tcpdump filter\n");
	fprintf(stderr, "    -h|--help                      | command line help\n");
	fprintf(stderr, "    -i|--iface <interface>         | read from given interface\n");
	fprintf(stderr, "    -p|--prefix <prefix>           | add given prefix to Zeek script file resolution\n");
	fprintf(stderr, "    -r|--readfile <readfile>       | read from given tcpdump file\n");
	fprintf(stderr, "    -s|--rulefile <rulefile>       | read rules from given file\n");
	fprintf(stderr, "    -t|--tracefile <tracefile>     | activate execution tracing\n");
	fprintf(stderr, "    -v|--version                   | print version and exit\n");
	fprintf(stderr, "    -w|--writefile <writefile>     | write to given tcpdump file\n");
#ifdef DEBUG
	fprintf(stderr, "    -B|--debug <dbgstreams>        | Enable debugging output for selected streams ('-B help' for help)\n");
#endif
	fprintf(stderr, "    -C|--no-checksums              | ignore checksums\n");
	fprintf(stderr, "    -F|--force-dns                 | force DNS\n");
	fprintf(stderr, "    -G|--load-seeds <file>         | load seeds from given file\n");
	fprintf(stderr, "    -H|--save-seeds <file>         | save seeds to given file\n");
	fprintf(stderr, "    -I|--print-id <ID name>        | print out given ID\n");
	fprintf(stderr, "    -N|--print-plugins             | print available plugins and exit (-NN for verbose)\n");
	fprintf(stderr, "    -P|--prime-dns                 | prime DNS\n");
	fprintf(stderr, "    -Q|--time                      | print execution time summary to stderr\n");
	fprintf(stderr, "    -S|--debug-rules               | enable rule debugging\n");
	fprintf(stderr, "    -T|--re-level <level>          | set 'RE_level' for rules\n");
	fprintf(stderr, "    -U|--status-file <file>        | Record process status in file\n");
	fprintf(stderr, "    -W|--watchdog                  | activate watchdog timer\n");
	fprintf(stderr, "    -X|--zeekygen <cfgfile>        | generate documentation based on config file\n");

#ifdef USE_PERFTOOLS_DEBUG
	fprintf(stderr, "    -m|--mem-leaks                 | show leaks  [perftools]\n");
	fprintf(stderr, "    -M|--mem-profile               | record heap [perftools]\n");
#endif
	fprintf(stderr, "    --pseudo-realtime[=<speedup>]  | enable pseudo-realtime for performance evaluation (default 1)\n");
	fprintf(stderr, "    -j|--jobs[=<worker count>]     | enable supervisor mode with N workers (default 1)\n");

#ifdef USE_IDMEF
	fprintf(stderr, "    -n|--idmef-dtd <idmef-msg.dtd> | specify path to IDMEF DTD file\n");
#endif

	fprintf(stderr, "    --test                         | run unit tests ('--test -h' for help, only when compiling with ENABLE_ZEEK_UNIT_TESTS)\n");
	fprintf(stderr, "    $ZEEKPATH                      | file search path (%s)\n", bro_path().c_str());
	fprintf(stderr, "    $ZEEK_PLUGIN_PATH              | plugin search path (%s)\n", bro_plugin_path());
	fprintf(stderr, "    $ZEEK_PLUGIN_ACTIVATE          | plugins to always activate (%s)\n", bro_plugin_activate());
	fprintf(stderr, "    $ZEEK_PREFIXES                 | prefix list (%s)\n", bro_prefixes().c_str());
	fprintf(stderr, "    $ZEEK_DNS_FAKE                 | disable DNS lookups (%s)\n", zeek_dns_fake() ? "on" : "off");
	fprintf(stderr, "    $ZEEK_SEED_FILE                | file to load seeds from (not set)\n");
	fprintf(stderr, "    $ZEEK_LOG_SUFFIX               | ASCII log file extension (.%s)\n", logging::writer::Ascii::LogExt().c_str());
	fprintf(stderr, "    $ZEEK_PROFILER_FILE            | Output file for script execution statistics (not set)\n");
	fprintf(stderr, "    $ZEEK_DISABLE_ZEEKYGEN         | Disable Zeekygen documentation support (%s)\n", zeekenv("ZEEK_DISABLE_ZEEKYGEN") ? "set" : "not set");
	fprintf(stderr, "    $ZEEK_DNS_RESOLVER             | IPv4/IPv6 address of DNS resolver to use (%s)\n", zeekenv("ZEEK_DNS_RESOLVER") ? zeekenv("ZEEK_DNS_RESOLVER") : "not set, will use first IPv4 address from /etc/resolv.conf");
	fprintf(stderr, "    $ZEEK_DEBUG_LOG_STDERR         | Use stderr for debug logs generated via the -B flag");

	fprintf(stderr, "\n");

	exit(code);
	}

struct zeek_options {
	bool print_version = false;
	bool print_usage = false;
	bool print_execution_time = false;
	bool print_signature_debug_info = false;
	int print_plugins = 0;

	std::optional<std::string> debug_log_streams;
	std::optional<std::string> debug_script_tracing_file;

	std::optional<std::string> identifier_to_print;
	std::optional<std::string> script_code_to_exec;
	std::vector<std::string> script_prefixes = { "" }; // "" = "no prefix"

	int signature_re_level = 4;
	bool ignore_checksums = false;
	bool use_watchdog = false;
	double pseudo_realtime = 0;
	DNS_MgrMode dns_mode = DNS_DEFAULT;

	bool supervisor_mode = false;
	bool parse_only = false;
	bool bare_mode = false;
	bool debug_scripts = false;
	bool perftools_check_leaks = false;
	bool perftools_profile = false;

	bool run_unit_tests = false;
	std::vector<std::string> doctest_args;

	std::optional<std::string> pcap_filter;
	std::vector<std::string> interfaces;
	std::vector<std::string> pcap_files;
	std::vector<std::string> signature_files;

	std::optional<std::string> pcap_output_file;
	std::optional<std::string> random_seed_input_file;
	std::optional<std::string> random_seed_output_file;
	std::optional<std::string> process_status_file;
	std::optional<std::string> zeekygen_config_file;
	std::string libidmef_dtd_file = "idmef-message.dtd";

	std::set<std::string> plugins_to_load;
	std::vector<std::string> scripts_to_load;
	std::vector<std::string> script_options_to_set;

	/**
	 * Unset options that aren't meant to be used by the supervisor, but may
	 * make sense for supervised nodes to inherit (as opposed to flagging
	 * as an error an exiting outright if used in supervisor-mode).
	 */
	void filter_supervisor_options()
		{
		pcap_filter = {};
		interfaces = {};
		pcap_files = {};
		signature_files = {};
		pcap_output_file = {};
		}

	/**
	 * Inherit certain options set in the original supervisor parent process
	 * and discard the rest.
	 */
	void filter_supervised_node_options()
		{
		auto og = *this;
		*this = {};

		debug_log_streams = og.debug_log_streams;
		debug_script_tracing_file = og.debug_script_tracing_file;
		script_code_to_exec = og.script_code_to_exec;
		script_prefixes = og.script_prefixes;

		signature_re_level = og.signature_re_level;
		ignore_checksums = og.ignore_checksums;
		use_watchdog = og.use_watchdog;
		pseudo_realtime = og.pseudo_realtime;
		dns_mode = og.dns_mode;

		bare_mode = og.bare_mode;
		perftools_check_leaks = og.perftools_check_leaks;
		perftools_profile = og.perftools_profile;

		pcap_filter = og.pcap_filter;
		signature_files = og.signature_files;

		// TODO: These are likely to be handled in a node-specific or
		// use-case-specific way.  e.g. interfaces is already handled for the
		// "cluster" use-case, but don't have supervised-pcap-reading
		// functionality yet.
		/* interfaces = og.interfaces; */
		/* pcap_files = og.pcap_files; */

		pcap_output_file = og.pcap_output_file;
		random_seed_input_file = og.random_seed_input_file;
		random_seed_output_file = og.random_seed_output_file;
		process_status_file = og.process_status_file;

		plugins_to_load = og.plugins_to_load;
		scripts_to_load = og.scripts_to_load;
		script_options_to_set = og.script_options_to_set;
		}
};

static void init_supervised_node(zeek_options* options)
	{
	const auto& node_name = zeek::supervised_node->name;

	if ( zeek::supervised_node->directory )
		{
		if ( chdir(zeek::supervised_node->directory->data()) )
			{
			fprintf(stderr, "node '%s' failed to chdir to %s: %s\n",
			        node_name.data(),
			        zeek::supervised_node->directory->data(),
			        strerror(errno));
			exit(1);
			}
		}

	if ( zeek::supervised_node->stderr_file )
		{
		auto fd = open(zeek::supervised_node->stderr_file->data(),
			           O_WRONLY | O_CREAT | O_TRUNC | O_APPEND | O_CLOEXEC,
			           0600);

		if ( fd == -1 || dup2(fd, STDERR_FILENO) == -1 )
			{
			fprintf(stderr, "node '%s' failed to create stderr file %s: %s\n",
			        node_name.data(),
			        zeek::supervised_node->stderr_file->data(),
			        strerror(errno));
			exit(1);
			}
		}

	if ( zeek::supervised_node->stdout_file )
		{
		auto fd = open(zeek::supervised_node->stdout_file->data(),
		               O_WRONLY | O_CREAT | O_TRUNC | O_APPEND | O_CLOEXEC,
		               0600);

		if ( fd == -1 || dup2(fd, STDOUT_FILENO) == -1 )
			{
			fprintf(stderr, "node '%s' failed to create stdout file %s: %s\n",
			        node_name.data(),
			        zeek::supervised_node->stdout_file->data(),
			        strerror(errno));
			exit(1);
			}
		}

	if ( zeek::supervised_node->cpu_affinity )
		{
		auto res = zeek::set_affinity(*zeek::supervised_node->cpu_affinity);

		if ( ! res )
			fprintf(stderr, "node '%s' failed to set CPU affinity: %s\n",
			        node_name.data(), strerror(errno));
		}

	options->filter_supervised_node_options();

	if ( zeek::supervised_node->interface )
		options->interfaces.emplace_back(*zeek::supervised_node->interface);

	if ( ! zeek::supervised_node->cluster.empty() )
		{
		if ( setenv("CLUSTER_NODE", node_name.data(), true) == -1 )
			{
			fprintf(stderr, "node '%s' failed to setenv: %s\n",
			        node_name.data(), strerror(errno));
			exit(1);
			}
		}

	for ( const auto& s : zeek::supervised_node->scripts )
		options->scripts_to_load.emplace_back(s);
	}

static std::vector<const char*> to_cargs(const std::vector<std::string>& args)
	{
	std::vector<const char*> rval;
	rval.reserve(args.size());

	for ( const auto& arg : args )
		rval.emplace_back(arg.data());

	return rval;
	}

static zeek_options parse_cmdline(int argc, char** argv)
	{
	zeek_options rval = {};

	// When running unit tests, the first argument on the command line must be
	// --test, followed by doctest options. Optionally, users can use "--" as
	// separator to pass Zeek options afterwards:
	//
	//     zeek --test [doctest-options] -- [zeek-options]

	// Just locally filtering out the args for Zeek usage from doctest args.
	std::vector<std::string> zeek_args;

	if ( argc > 1 && strcmp(argv[1], "--test") == 0 )
		{
		#ifdef DOCTEST_CONFIG_DISABLE
		fprintf(stderr, "ERROR: C++ unit tests are disabled for this build.\n"
		                "       Please re-compile with ENABLE_ZEEK_UNIT_TESTS "
		                       "to run the C++ unit tests.\n");
		usage(argv[0], 1);
		#endif

		auto is_separator = [](const char* cstr)
			{
			return strcmp(cstr, "--") == 0;
			};
		auto first = argv;
		auto last = argv + argc;
		auto separator = std::find_if(first, last, is_separator);
		zeek_args.emplace_back(argv[0]);

		if ( separator != last )
			{
			auto first_zeek_arg = std::next(separator);

			for ( auto i = first_zeek_arg; i != last; ++i )
				zeek_args.emplace_back(*i);
			}

		rval.run_unit_tests = true;

		for ( auto i = 0; i < std::distance(first, separator); ++i )
			rval.doctest_args.emplace_back(argv[i]);
		}
	else
		{
		for ( auto i = 0; i < argc; ++i )
			zeek_args.emplace_back(argv[i]);
		}

	constexpr struct option long_opts[] = {
		{"parse-only",	no_argument,		0,	'a'},
		{"bare-mode",	no_argument,		0,	'b'},
		{"debug-script",	no_argument,		0,	'd'},
		{"exec",		required_argument,	0,	'e'},
		{"filter",		required_argument,	0,	'f'},
		{"help",		no_argument,		0,	'h'},
		{"iface",		required_argument,	0,	'i'},
		{"zeekygen",		required_argument,		0,	'X'},
		{"prefix",		required_argument,	0,	'p'},
		{"readfile",		required_argument,	0,	'r'},
		{"rulefile",		required_argument,	0,	's'},
		{"tracefile",		required_argument,	0,	't'},
		{"writefile",		required_argument,	0,	'w'},
		{"version",		no_argument,		0,	'v'},
		{"no-checksums",	no_argument,		0,	'C'},
		{"force-dns",		no_argument,		0,	'F'},
		{"load-seeds",		required_argument,	0,	'G'},
		{"save-seeds",		required_argument,	0,	'H'},
		{"print-plugins",	no_argument,		0,	'N'},
		{"prime-dns",		no_argument,		0,	'P'},
		{"time",		no_argument,		0,	'Q'},
		{"debug-rules",		no_argument,		0,	'S'},
		{"re-level",		required_argument,	0,	'T'},
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
		{"jobs",	optional_argument, 0,	'j'},
		{"test",		no_argument,		0,	'#'},

		{0,			0,			0,	0},
	};

	char opts[256];
	safe_strncpy(opts, "B:e:f:G:H:I:i:j::n:p:r:s:T:t:U:w:X:CFNPQSWabdhv",
	             sizeof(opts));

#ifdef USE_PERFTOOLS_DEBUG
	strncat(opts, "mM", 2);
#endif

	int op;
	int long_optsind;
	opterr = 0;

	// getopt may permute the array, so need yet another array
	auto zargs = std::make_unique<char*[]>(zeek_args.size());

	for ( auto i = 0; i < zeek_args.size(); ++i )
		zargs[i] = zeek_args[i].data();

	while ( (op = getopt_long(zeek_args.size(), zargs.get(), opts, long_opts, &long_optsind)) != EOF )
		switch ( op ) {
		case 'a':
			rval.parse_only = true;
			break;
		case 'b':
			rval.bare_mode = true;
			break;
		case 'd':
			rval.debug_scripts = true;
			break;
		case 'e':
			rval.script_code_to_exec = optarg;
			break;
		case 'f':
			rval.pcap_filter = optarg;
			break;
		case 'h':
			rval.print_usage = true;
			break;
		case 'i':
			if ( ! rval.pcap_files.empty() )
				{
				fprintf(stderr, "Using -i is not allowed when reading pcap files");
				exit(1);
				}
			rval.interfaces.emplace_back(optarg);
			break;
		case 'j':
			rval.supervisor_mode = true;
			if ( optarg )
				{
				// TODO: for supervised offline pcap reading, the argument is
				// expected to be number of workers like "-j 4" or possibly a
				// list of worker/proxy/logger counts like "-j 4,2,1"
				}
			break;
		case 'p':
			rval.script_prefixes.emplace_back(optarg);
			break;
		case 'r':
			if ( ! rval.interfaces.empty() )
				{
				fprintf(stderr, "Using -r is not allowed when reading a live interface");
				exit(1);
				}
			rval.pcap_files.emplace_back(optarg);
			break;
		case 's':
			rval.signature_files.emplace_back(optarg);
			break;
		case 't':
			rval.debug_script_tracing_file = optarg;
			break;
		case 'v':
			rval.print_version = true;
			break;
		case 'w':
			rval.pcap_output_file = optarg;
			break;
		case 'B':
			rval.debug_log_streams = optarg;
			break;
		case 'C':
			rval.ignore_checksums = true;
			break;
		case 'E':
			rval.pseudo_realtime = 1.0;
			if ( optarg )
				rval.pseudo_realtime = atof(optarg);
			break;
		case 'F':
			if ( rval.dns_mode != DNS_DEFAULT )
				usage(zargs[0], 1);
			rval.dns_mode = DNS_FORCE;
			break;
		case 'G':
			rval.random_seed_input_file = optarg;
			break;
		case 'H':
			rval.random_seed_output_file = optarg;
			break;
		case 'I':
			rval.identifier_to_print = optarg;
			break;
		case 'N':
			++rval.print_plugins;
			break;
		case 'P':
			if ( rval.dns_mode != DNS_DEFAULT )
				usage(zargs[0], 1);
			rval.dns_mode = DNS_PRIME;
			break;
		case 'Q':
			rval.print_execution_time = true;
			break;
		case 'S':
			rval.print_signature_debug_info = true;
			break;
		case 'T':
			rval.signature_re_level = atoi(optarg);
			break;
		case 'U':
			rval.process_status_file = optarg;
			break;
		case 'W':
			rval.use_watchdog = true;
			break;
		case 'X':
			rval.zeekygen_config_file = optarg;
			break;

#ifdef USE_PERFTOOLS_DEBUG
		case 'm':
			rval.perftools_check_leaks = 1;
			break;
		case 'M':
			rval.perftools_profile = 1;
			break;
#endif

#ifdef USE_IDMEF
		case 'n':
			rval.libidmef_dtd_path = optarg;
			break;
#endif

		case '#':
			fprintf(stderr, "ERROR: --test only allowed as first argument.\n");
			usage(zargs[0], 1);
			break;

		case 0:
			// This happens for long options that don't have
			// a short-option equivalent.
			break;

		case '?':
		default:
			usage(zargs[0], 1);
			break;
		}

	// Process remaining arguments. X=Y arguments indicate script
	// variable/parameter assignments. X::Y arguments indicate plugins to
	// activate/query. The remainder are treated as scripts to load.
	while ( optind < zeek_args.size() )
		{
		if ( strchr(zargs[optind], '=') )
			rval.script_options_to_set.emplace_back(zargs[optind++]);
		else if ( strstr(zargs[optind], "::") )
			rval.plugins_to_load.emplace(zargs[optind++]);
		else
			rval.scripts_to_load.emplace_back(zargs[optind++]);
		}

	return rval;
	}

bool show_plugins(int level)
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
		                       {new Val(timer_mgr->Time(), TYPE_TIME)}),
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

	// File analysis termination may produce events, so do it early on in
	// the termination process.
	file_mgr->Terminate();

	brofiler.WriteStats();

	EventHandlerPtr zeek_done = internal_handler("zeek_done");
	if ( zeek_done )
		mgr.QueueEventFast(zeek_done, val_list{});

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

	mgr.Drain();

	plugin_mgr->FinishPlugins();

	delete zeekygen_mgr;
	delete timer_mgr;
	delete event_registry;
	delete analyzer_mgr;
	delete file_mgr;
	// broker_mgr is deleted via iosource_mgr
	// supervisor is deleted via iosource_mgr
	delete iosource_mgr;
	delete log_mgr;
	delete reporter;
	delete plugin_mgr;
	delete val_mgr;
	delete port_mgr;

	reporter = 0;
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
		copy_string(internal_val("signature_files")->AsString()->CheckString());

	char* tmp = script_signature_files;
	char* s;
	while ( (s = strsep(&tmp, " \t")) )
		if ( *s )
			rval.emplace_back(s);

	delete [] script_signature_files;
	return rval;
	}

static std::string get_exe_path(const std::string& invocation)
	{
	if ( invocation.empty() )
		return "";

	if ( invocation[0] == '/' )
		// Absolute path
		return invocation;

	if ( invocation.find('/') != std::string::npos )
		{
		// Relative path
		char cwd[PATH_MAX];

		if ( ! getcwd(cwd, sizeof(cwd)) )
			{
			fprintf(stderr, "failed to get current directory: %s\n",
			        strerror(errno));
			exit(1);
			}

		return std::string(cwd) + "/" + invocation;
		}

	auto path = getenv("PATH");

	if ( ! path )
		return "";

	return find_file(invocation, path);
	}

int main(int argc, char** argv)
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

	auto options = parse_cmdline(argc, argv);

	if ( options.print_usage )
		usage(argv[0], 0);

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
		return context.run();
		}

	pid_t stem_pid = 0;
	std::unique_ptr<bro::PipePair> supervisor_pipe;
	auto zeek_stem_env = getenv("ZEEK_STEM");

	if ( zeek_stem_env )
		{
		std::vector<std::string> fd_strings;
		tokenize_string(zeek_stem_env, ",", &fd_strings);

		if ( fd_strings.size() != 4 )
			{
			fprintf(stderr, "invalid ZEEK_STEM environment variable value: '%s'\n",
			        zeek_stem_env);
			exit(1);
			}

		int fds[4];

		for ( auto i = 0; i < 4; ++i )
			fds[i] = std::stoi(fd_strings[i]);

		supervisor_pipe.reset(new bro::PipePair{FD_CLOEXEC, O_NONBLOCK, fds});
		zeek::supervised_node = zeek::Supervisor::RunStem(std::move(supervisor_pipe));
		}
	else if ( options.supervisor_mode )
		{
		// TODO: the SIGCHLD handler should be set before fork()
		supervisor_pipe.reset(new bro::PipePair{FD_CLOEXEC, O_NONBLOCK});
		stem_pid = fork();

		if ( stem_pid == -1 )
			{
			fprintf(stderr, "failed to fork Zeek supervisor stem process: %s\n",
			        strerror(errno));
			exit(1);
			}

		if ( stem_pid == 0 )
			zeek::supervised_node = zeek::Supervisor::RunStem(std::move(supervisor_pipe));
		}

	if ( zeek::supervised_node )
		init_supervised_node(&options);

	double time_start = current_time(true);

	brofiler.ReadStats();

	auto dns_type = options.dns_mode;

	if ( dns_type == DNS_DEFAULT && zeek_dns_fake() )
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
		proc_status_file = options.process_status_file->data();

	atexit(atexit_handler);
	set_processing_status("INITIALIZING", "main");

	bro_start_time = current_time(true);

	val_mgr = new ValManager();
	port_mgr = new PortManager();
	reporter = new Reporter();
	thread_mgr = new threading::Manager();
	plugin_mgr = new plugin::Manager();

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
		zeek::supervisor = new zeek::Supervisor(std::move(cfg),
		                                        std::move(supervisor_pipe),
		                                        stem_pid);
		}

	const char* seed_load_file = zeekenv("ZEEK_SEED_FILE");

	if ( options.random_seed_input_file )
		seed_load_file = options.random_seed_input_file->data();

	init_random_seed((seed_load_file && *seed_load_file ? seed_load_file : 0),
					 options.random_seed_output_file ? options.random_seed_output_file->data() : 0);
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

	timer_mgr = new PQ_TimerMgr("<GLOBAL>");
	// timer_mgr = new CQ_TimerMgr();

	auto zeekygen_cfg = options.zeekygen_config_file.value_or("");
	zeekygen_mgr = new zeekygen::Manager(zeekygen_cfg, bro_argv[0]);

	add_essential_input_file("base/init-bare.zeek");
	add_essential_input_file("base/init-frameworks-and-bifs.zeek");

	if ( ! options.bare_mode )
		add_input_file("base/init-default.zeek");

	plugin_mgr->SearchDynamicPlugins(bro_plugin_path());

	if ( options.plugins_to_load.empty() && options.scripts_to_load.empty() &&
	     options.script_options_to_set.empty() &&
	     options.pcap_files.size() == 0 &&
	     options.interfaces.size() == 0 &&
	     ! options.identifier_to_print &&
	     ! command_line_policy && ! options.print_plugins &&
	     ! options.supervisor_mode && ! zeek::supervised_node )
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
	broker_mgr = new bro_broker::Manager(! options.pcap_files.empty());

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

	md5_type = new OpaqueType("md5");
	sha1_type = new OpaqueType("sha1");
	sha256_type = new OpaqueType("sha256");
	entropy_type = new OpaqueType("entropy");
	cardinality_type = new OpaqueType("cardinality");
	topk_type = new OpaqueType("topk");
	bloomfilter_type = new OpaqueType("bloomfilter");
	x509_opaque_type = new OpaqueType("x509");
	ocsp_resp_opaque_type = new OpaqueType("ocsp_resp");
	paraglob_type = new OpaqueType("paraglob");

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

	RecordVal::ResizeParseTimeRecords();

	init_general_global_var();
	init_net_var();
	init_builtin_funcs_subdirs();

	// Must come after plugin activation (and also after hash
	// initialization).
	binpac::FlowBuffer::Policy flowbuffer_policy;
	flowbuffer_policy.max_capacity = global_scope()->Lookup(
		"BinPAC::flowbuffer_capacity_max")->ID_Val()->AsCount();
	flowbuffer_policy.min_capacity = global_scope()->Lookup(
		"BinPAC::flowbuffer_capacity_min")->ID_Val()->AsCount();
	flowbuffer_policy.contract_threshold = global_scope()->Lookup(
		"BinPAC::flowbuffer_contract_threshold")->ID_Val()->AsCount();
	binpac::init(&flowbuffer_policy);

	plugin_mgr->InitBifs();

	if ( reporter->Errors() > 0 )
		exit(1);

	plugin_mgr->InitPostScript();
	zeekygen_mgr->InitPostScript();
	broker_mgr->InitPostScript();

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
	zeekygen_mgr->GenerateDocs();

	if ( options.pcap_filter )
		{
		ID* id = global_scope()->Lookup("cmd_line_bpf_filter");

		if ( ! id )
			reporter->InternalError("global cmd_line_bpf_filter not defined");

		id->SetVal(new StringVal(*options.pcap_filter));
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
		dbg_init_debugger(0);

	auto all_interfaces = options.interfaces;

	if ( options.pcap_files.empty() && options.interfaces.empty() )
		{
		Val* interfaces_val = internal_val("interfaces");
		if ( interfaces_val )
			{
			char* interfaces_str =
				interfaces_val->AsString()->Render();

			if ( interfaces_str[0] != '\0' )
				tokenize_string(interfaces_str, " ", &all_interfaces);

			delete [] interfaces_str;
			}
		}

	if ( dns_type != DNS_PRIME )
		net_init(all_interfaces, options.pcap_files,
		         options.pcap_output_file, options.use_watchdog);

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

	// Print the ID.
	if ( options.identifier_to_print )
		{
		ID* id = global_scope()->Lookup(*options.identifier_to_print);
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
		profiling_logger = new ProfileLogger(profiling_file->AsFile(),
			profiling_interval);

		if ( segment_profiling )
			segment_logger = profiling_logger;
		}

	if ( ! reading_live && ! reading_traces )
		// Set up network_time to track real-time, since
		// we don't have any other source for it.
		net_update_time(current_time());

	EventHandlerPtr zeek_init = internal_handler("zeek_init");
	if ( zeek_init )	//### this should be a function
		mgr.QueueEventFast(zeek_init, val_list{});

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
		Frame f(current_scope()->Length(), 0, 0);
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

			mgr.QueueEventFast(zeek_script_loaded, {
				new StringVal(i->name.c_str()),
				val_mgr->GetCount(i->include_level),
			});
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

	iosource_mgr->Register(thread_mgr, true);

	if ( zeek::supervisor )
		iosource_mgr->Register(zeek::supervisor);

	if ( iosource_mgr->Size() > 0 ||
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

		done_with_network();
		net_delete();
		}

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
