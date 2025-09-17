// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Options.h"

#include "zeek/zeek-config.h"

#if defined(HAVE_GETOPT_H) && ! defined(_MSC_VER)
#include <getopt.h>
#endif

#include <unistd.h>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <sstream>

#include "zeek/3rdparty/bsd-getopt-long.h"
#include "zeek/ScriptProfile.h"
#include "zeek/logging/writers/ascii/Ascii.h"
#include "zeek/script_opt/ScriptOpt.h"

namespace zeek {

void Options::filter_supervisor_options() {
    pcap_filter = {};
    signature_files = {};
    pcap_output_file = {};
}

void Options::filter_supervised_node_options() {
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
    deterministic_mode = og.deterministic_mode;
    abort_on_scripting_errors = og.abort_on_scripting_errors;

    pcap_filter = og.pcap_filter;
    signature_files = og.signature_files;

    // TODO: These are likely to be handled in a node-specific or
    // use-case-specific way.  e.g. interfaces is already handled for the
    // "cluster" use-case, but don't have supervised-pcap-reading
    // functionality yet.
    /* interface = og.interface; */
    /* pcap_file = og.pcap_file; */

    pcap_output_file = og.pcap_output_file;
    random_seed_input_file = og.random_seed_input_file;
    random_seed_output_file = og.random_seed_output_file;
    process_status_file = og.process_status_file;

    plugins_to_load = og.plugins_to_load;
    scripts_to_load = og.scripts_to_load;
    script_options_to_set = og.script_options_to_set;
}

bool fake_dns() { return getenv("ZEEK_DNS_FAKE"); }

extern const char* zeek_version();

void prompt_for_help(const char* prog) { fprintf(stderr, "Try '%s --help' for more information.\n", prog); }

void usage(const char* prog) {
    printf("zeek version %s\n", zeek_version());

    printf("usage: %s [options] [file ...]\n", prog);
    printf("usage: %s --test [doctest-options] -- [options] [file ...]\n", prog);
    printf("    <file>                          | Zeek script file, or read stdin\n");
    printf("    -a|--parse-only                 | exit immediately after parsing scripts\n");
    printf("    -b|--bare-mode                  | don't load scripts from the base/ directory\n");
    printf("    -c|--capture-unprocessed <file> | write unprocessed packets to a tcpdump file\n");
    printf("    -e|--exec <zeek code>           | augment loaded scripts by given code\n");
    printf("    -f|--filter <filter>            | tcpdump filter\n");
    printf("    -h|--help                       | command line help\n");
    printf("    -i|--iface <interface>          | read from given interface (only one allowed)\n");
    printf("    -p|--prefix <prefix>            | add given prefix to Zeek script file resolution\n");
    printf(
        "    -r|--readfile <readfile>        | read from given tcpdump file (only one "
        "allowed, pass '-' as the filename to read from stdin)\n");
    printf("    -s|--rulefile <rulefile>        | read rules from given file\n");
    printf("    -t|--tracefile <tracefile>      | activate execution tracing\n");
    printf("    -u|--usage-issues               | find variable usage issues and exit\n");
    printf(
        "       --no-unused-warnings         | suppress warnings of unused "
        "functions/hooks/events\n");
    printf("    -v|--version                    | print version and exit\n");
    printf("    -V|--build-info                 | print build information and exit\n");
    printf("    -w|--writefile <writefile>      | write to given tcpdump file\n");
#ifdef DEBUG
    printf(
        "    -B|--debug <dbgstreams>         | Enable debugging output for selected "
        "streams ('-B help' for help)\n");
#endif
    printf("    -C|--no-checksums               | ignore checksums\n");
    printf("    -D|--deterministic              | initialize random seeds to zero\n");
    printf(
        "    -E|--event-trace <file>         | generate a replayable event trace to "
        "the given file\n");
    printf("    -F|--force-dns                  | force DNS\n");
    printf("    -G|--load-seeds <file>          | load seeds from given file\n");
    printf("    -H|--save-seeds <file>          | save seeds to given file\n");
    printf("    -I|--print-id <ID name>         | print out given ID\n");
    printf(
        "    -N|--print-plugins              | print available plugins and exit (-NN "
        "for verbose)\n");
    printf(
        "    -O|--optimize <option>          | enable script optimization (use -O help "
        "for options)\n");
    printf(
        "    -0|--optimize-files=<pat>       | enable script optimization for all "
        "functions in files with names containing the given pattern\n");
    printf(
        "    -o|--optimize-funcs=<pat>       | enable script optimization for "
        "functions with names fully matching the given pattern\n");
    printf("    -P|--prime-dns                  | prime DNS\n");
    printf("    -Q|--time                       | print execution time summary to stderr\n");
    printf("    -S|--debug-rules                | enable rule debugging\n");
    printf("    -T|--re-level <level>           | set 'RE_level' for rules\n");
    printf("    -U|--status-file <file>         | Record process status in file\n");
    printf("    -W|--watchdog                   | activate watchdog timer\n");
    printf("    -X|--zeekygen <cfgfile>         | generate documentation based on config file; implies -a\n");

#ifdef USE_PERFTOOLS_DEBUG
    printf("    -m|--mem-leaks                  | show leaks  [perftools]\n");
    printf("    -M|--mem-profile                | record heap [perftools]\n");
#endif
    printf("    --profile-scripts[=file]        | profile scripts to given file (default stdout)\n");
    printf(
        "    --profile-script-call-stacks    | add call stacks to profile output (requires "
        "--profile-scripts)\n");
    printf(
        "    --pseudo-realtime[=<speedup>]   | enable pseudo-realtime for performance "
        "evaluation (default 1)\n");
    printf("    -j|--jobs                       | enable supervisor mode\n");

    printf(
        "    --test                          | run unit tests ('--test -h' for help, "
        "not available when built without ENABLE_ZEEK_UNIT_TESTS)\n");
    printf("    $ZEEKPATH                       | file search path (%s)\n", util::zeek_path().c_str());
    printf("    $ZEEK_PLUGIN_PATH               | plugin search path (%s)\n", util::zeek_plugin_path());
    printf("    $ZEEK_PLUGIN_ACTIVATE           | plugins to always activate (%s)\n", util::zeek_plugin_activate());
    printf("    $ZEEK_PREFIXES                  | prefix list (%s)\n", util::zeek_prefixes().c_str());
    printf("    $ZEEK_DNS_FAKE                  | disable DNS lookups (%s)\n", fake_dns() ? "on" : "off");
    printf("    $ZEEK_SEED_VALUES               | list of space separated seeds (%s)\n",
           getenv("ZEEK_SEED_VALUES") ? "set" : "not set");
    printf("    $ZEEK_SEED_FILE                 | file to load seeds from (not set)\n");
    printf("    $ZEEK_LOG_SUFFIX                | ASCII log file extension (.%s)\n",
           logging::writer::detail::Ascii::LogExt().c_str());
    printf(
        "    $ZEEK_PROFILER_FILE             | Output file for script execution "
        "statistics (not set)\n");
    printf("    $ZEEK_DISABLE_ZEEKYGEN          | Disable Zeekygen documentation support (%s)\n",
           getenv("ZEEK_DISABLE_ZEEKYGEN") ? "set" : "not set");
    printf("    $ZEEK_DNS_RESOLVER              | IPv4/IPv6 address of DNS resolver to use (%s)\n",
           getenv("ZEEK_DNS_RESOLVER") ? getenv("ZEEK_DNS_RESOLVER") :
                                         "not set, will use first IPv4 address from /etc/resolv.conf");
    printf(
        "    $ZEEK_DEBUG_LOG_STDERR          | Use stderr for debug logs generated via "
        "the -B flag\n");
    printf(
        "    $ZEEK_DEBUG_LOG_STREAMS         | Enable debugging output for selected "
        "streams (see the -B flag)");

    printf("\n");
}

static void print_analysis_help() {
    printf("--optimize options when using ZAM:\n");
    printf("    ZAM	execute scripts using ZAM and all optimizations\n");
    printf("    help	print this list\n");
    printf("    report-uncompilable	print names of functions that can't be compiled\n");
    printf("\n  primarily for developers:\n");
    printf("    dump-uds	dump use-defs to stdout; implies xform\n");
    printf("    dump-xform	dump transformed scripts to stdout; implies xform\n");
    printf("    dump-ZAM	dump generated ZAM code, including intermediaries; implies gen-ZAM-code\n");
    printf("    dump-final-ZAM	dump final generated ZAM code; implies gen-ZAM-code\n");
    printf("    gen-ZAM-code	generate ZAM code (without turning on additional optimizations)\n");
    printf("    inline	inline function calls\n");
    printf("    keep-asserts	do not optimize away \"assert\" statements\n");
    printf("    no-inline	turn off inlining\n");
    printf("    no-event-handler-coalescence	when inlining, do not coalescence event handlers\n");
    printf("    no-ZAM-opt	omit low-level ZAM optimization\n");
    printf("    optimize-all	optimize all scripts, even inlined ones\n");
    printf("    optimize-AST	optimize the (transformed) AST; implies xform\n");
    printf("    profile-ZAM	generate to zprof.out a ZAM execution profile; implies -O ZAM\n");
    printf("    report-recursive	report on recursive functions and exit\n");
    printf("    validate-ZAM	perform internal assessment of synthesized ZAM instructions and exit\n");
    printf("    xform	transform scripts to \"reduced\" form\n");

    printf("\n--optimize options when generating C++:\n");
    printf("    allow-cond	allow standalone compilation of functions influenced by conditionals\n");
    printf("    gen-C++	generate C++ script bodies\n");
    printf("    gen-standalone-C++	generate \"standalone\" C++ script bodies\n");
    printf("    help	print this list\n");
    printf("    report-C++	report available C++ script bodies and exit\n");
    printf("    report-uncompilable	print names of functions that can't be compiled\n");
    printf("    use-C++	use available C++ script bodies\n");
}

static void set_analysis_option(const char* opt, Options& opts) {
    auto& a_o = opts.analysis_options;

    if ( ! opt || util::streq(opt, "ZAM") ) {
        a_o.inliner = a_o.optimize_AST = a_o.activate = true;
        a_o.gen_ZAM = true;
        return;
    }

    if ( util::streq(opt, "help") ) {
        print_analysis_help();
        exit(0);
    }

    if ( util::streq(opt, "allow-cond") )
        a_o.allow_cond = true;
    else if ( util::streq(opt, "dump-uds") )
        a_o.activate = a_o.dump_uds = true;
    else if ( util::streq(opt, "dump-xform") )
        a_o.activate = a_o.dump_xform = true;
    else if ( util::streq(opt, "dump-ZAM") )
        a_o.activate = a_o.dump_ZAM = true;
    else if ( util::streq(opt, "dump-final-ZAM") )
        a_o.activate = a_o.dump_final_ZAM = true;
    else if ( util::streq(opt, "gen-C++") )
        a_o.gen_CPP = true;
    else if ( util::streq(opt, "gen-standalone-C++") )
        a_o.gen_standalone_CPP = true;
    else if ( util::streq(opt, "gen-ZAM-code") )
        a_o.activate = a_o.gen_ZAM_code = true;
    else if ( util::streq(opt, "inline") )
        a_o.inliner = true;
    else if ( util::streq(opt, "keep-asserts") )
        a_o.keep_asserts = true;
    else if ( util::streq(opt, "no-inline") )
        a_o.no_inliner = true;
    else if ( util::streq(opt, "no-event-handler-coalescence") )
        a_o.no_eh_coalescence = true;
    else if ( util::streq(opt, "no-ZAM-opt") )
        a_o.activate = a_o.no_ZAM_opt = true;
    else if ( util::streq(opt, "optimize-all") )
        a_o.activate = a_o.compile_all = true;
    else if ( util::streq(opt, "optimize-AST") )
        a_o.activate = a_o.optimize_AST = true;
    else if ( util::streq(opt, "profile-ZAM") )
        a_o.activate = a_o.profile_ZAM = true;
    else if ( util::streq(opt, "report-C++") )
        a_o.report_CPP = true;
    else if ( util::streq(opt, "report-recursive") )
        a_o.inliner = a_o.report_recursive = true;
    else if ( util::streq(opt, "report-uncompilable") )
        a_o.report_uncompilable = true;
    else if ( util::streq(opt, "use-C++") )
        a_o.use_CPP = true;
    else if ( util::streq(opt, "validate-ZAM") )
        a_o.validate_ZAM = true;
    else if ( util::streq(opt, "xform") )
        a_o.activate = true;

    else {
        fprintf(stderr, "zeek: unrecognized -O/--optimize option: %s\n\n", opt);
        fprintf(stderr, "Try 'zeek -O help' for more information.\n");
        exit(1);
    }
}

Options parse_cmdline(int argc, char** argv) {
    Options rval;

    // When running unit tests, the first argument on the command line must be
    // --test, followed by doctest options. Optionally, users can use "--" as
    // separator to pass Zeek options afterwards:
    //
    //     zeek --test [doctest-options] -- [zeek-options]

    // Just locally filtering out the args for Zeek usage from doctest args.
    std::vector<std::string> zeek_args;

    if ( argc > 1 && strcmp(argv[1], "--test") == 0 ) {
#ifdef DOCTEST_CONFIG_DISABLE
        fprintf(stderr,
                "ERROR: C++ unit tests are disabled for this build.\n"
                "       Please re-compile with ENABLE_ZEEK_UNIT_TESTS "
                "to run the C++ unit tests.\n");
        exit(1);
#endif

        auto is_separator = [](const char* cstr) { return strcmp(cstr, "--") == 0; };
        auto first = argv;
        auto last = argv + argc;
        auto separator = std::find_if(first, last, is_separator);
        zeek_args.emplace_back(argv[0]);

        if ( separator != last ) {
            auto first_zeek_arg = std::next(separator);

            for ( auto i = first_zeek_arg; i != last; ++i )
                zeek_args.emplace_back(*i);
        }

        rval.run_unit_tests = true;

        for ( ptrdiff_t i = 0; i < std::distance(first, separator); ++i )
            rval.doctest_args.emplace_back(argv[i]);
    }
    else {
        if ( argc > 1 ) {
            auto i = 0;
            for ( ; i < argc && ! util::ends_with(argv[i], "--"); ++i ) {
                zeek_args.emplace_back(argv[i]);
            }

            if ( i < argc ) {
                // If a script is invoked with Zeek as the interpreter, the arguments provided
                // directly in the interpreter line of the script won't be broken apart in the
                // argv on Linux so we split it up here.
                if ( util::ends_with(argv[i], "--") && zeek_args.size() == 1 ) {
                    std::istringstream iss(argv[i]);
                    for ( std::string s; iss >> s; ) {
                        if ( ! s.ends_with("--") ) {
                            zeek_args.emplace_back(s);
                        }
                    }
                }

                // There is an additional increment here to skip over the "--" if it was found.
                if ( util::ends_with(argv[i], "--") )
                    ++i;

                // The first argument after the double hyphens in implicitly a script name.
                rval.scripts_to_load.emplace_back(argv[i++]);

                // If there are more argument, grab them for script arguments
                for ( ; i < argc; ++i )
                    rval.script_args.emplace_back(argv[i]);
            }
        }
    }

    int profile_scripts = 0;
    int profile_script_call_stacks = 0;
    std::string profile_filename;
    int no_unused_warnings = 0;

    bool enable_script_profile = false;
    bool enable_script_profile_call_stacks = false;

    struct option long_opts[] = {
        {"parse-only", no_argument, nullptr, 'a'},
        {"bare-mode", no_argument, nullptr, 'b'},
        {"capture-unprocessed", required_argument, nullptr, 'c'},
        {"exec", required_argument, nullptr, 'e'},
        {"filter", required_argument, nullptr, 'f'},
        {"help", no_argument, nullptr, 'h'},
        {"iface", required_argument, nullptr, 'i'},
        {"zeekygen", required_argument, nullptr, 'X'},
        {"prefix", required_argument, nullptr, 'p'},
        {"readfile", required_argument, nullptr, 'r'},
        {"rulefile", required_argument, nullptr, 's'},
        {"tracefile", required_argument, nullptr, 't'},
        {"writefile", required_argument, nullptr, 'w'},
        {"usage-issues", no_argument, nullptr, 'u'},
        {"version", no_argument, nullptr, 'v'},
        {"build-info", no_argument, nullptr, 'V'},
        {"no-checksums", no_argument, nullptr, 'C'},
        {"force-dns", no_argument, nullptr, 'F'},
        {"deterministic", no_argument, nullptr, 'D'},
        {"event-trace", required_argument, nullptr, 'E'},
        {"load-seeds", required_argument, nullptr, 'G'},
        {"save-seeds", required_argument, nullptr, 'H'},
        {"print-plugins", no_argument, nullptr, 'N'},
        {"optimize", required_argument, nullptr, 'O'},
        {"optimize-funcs", required_argument, nullptr, 'o'},
        {"optimize-files", required_argument, nullptr, '0'},
        {"prime-dns", no_argument, nullptr, 'P'},
        {"time", no_argument, nullptr, 'Q'},
        {"debug-rules", no_argument, nullptr, 'S'},
        {"re-level", required_argument, nullptr, 'T'},
        {"watchdog", no_argument, nullptr, 'W'},
        {"print-id", required_argument, nullptr, 'I'},
        {"status-file", required_argument, nullptr, 'U'},
        {"debug", required_argument, nullptr, 'B'},

#ifdef USE_PERFTOOLS_DEBUG
        {"mem-leaks", no_argument, nullptr, 'm'},
        {"mem-profile", no_argument, nullptr, 'M'},
#endif

        {"profile-scripts", optional_argument, &profile_scripts, 1},
        {"profile-script-call-stacks", optional_argument, &profile_script_call_stacks, 1},
        {"no-unused-warnings", no_argument, &no_unused_warnings, 1},
        {"pseudo-realtime", optional_argument, nullptr, '~'},
        {"jobs", optional_argument, nullptr, 'j'},
        {"test", no_argument, nullptr, '#'},

        {nullptr, 0, nullptr, 0},
    };

    char opts[256];
    util::safe_strncpy(opts, "B:c:E:e:f:G:H:I:i:j::n:O:0:o:p:r:s:T:t:U:w:X:CDFMNPQSWabdhmuvV", sizeof(opts));

    int op;
    int long_optsind;
    opterr = 0;

    // getopt may permute the array, so need yet another array
    //
    // Make sure this array is one greater than zeek_args and ends in nullptr, otherwise
    // getopt may go beyond the end of the array
    auto zargs = std::make_unique<char*[]>(zeek_args.size() + 1);

    for ( size_t i = 0; i < zeek_args.size(); ++i )
        zargs[i] = zeek_args[i].data();

    // Make sure getopt doesn't go past the end
    zargs[zeek_args.size()] = nullptr;

    while ( (op = getopt_long(zeek_args.size(), zargs.get(), opts, long_opts, &long_optsind)) != EOF )
        switch ( op ) {
            case 'a': rval.parse_only = true; break;
            case 'b': rval.bare_mode = true; break;
            case 'c': rval.unprocessed_output_file = optarg; break;
            case 'e': rval.script_code_to_exec = optarg; break;
            case 'f': rval.pcap_filter = optarg; break;
            case 'h': rval.print_usage = true; break;
            case 'i':
                if ( rval.interface ) {
                    fprintf(stderr, "ERROR: Only a single interface option (-i) is allowed.\n");
                    prompt_for_help(zargs[0]);
                    exit(1);
                }

                if ( rval.pcap_file ) {
                    fprintf(stderr, "ERROR: Using -i is not allow when reading a pcap file.\n");
                    prompt_for_help(zargs[0]);
                    exit(1);
                }

                rval.interface = optarg;
                break;
            case 'j':
                rval.supervisor_mode = true;
                if ( optarg ) {
                    // TODO: for supervised offline pcap reading, the argument is
                    // expected to be number of workers like "-j 4" or possibly a
                    // list of worker/proxy/logger counts like "-j 4,2,1"
                }
                break;
            case 'p': rval.script_prefixes.emplace_back(optarg); break;
            case 'r':
                if ( rval.pcap_file ) {
                    fprintf(stderr, "ERROR: Only a single readfile option (-r) is allowed.\n");
                    prompt_for_help(zargs[0]);
                    exit(1);
                }

                if ( rval.interface ) {
                    fprintf(stderr, "Using -r is not allowed when reading a live interface.\n");
                    prompt_for_help(zargs[0]);
                    exit(1);
                }

                rval.pcap_file = optarg;
                break;
            case 's': rval.signature_files.emplace_back(optarg); break;
            case 't': rval.debug_script_tracing_file = optarg; break;
            case 'u': ++rval.analysis_options.usage_issues; break;
            case 'v': rval.print_version = true; break;
            case 'V': rval.print_build_info = true; break;
            case 'w': rval.pcap_output_file = optarg; break;

            case 'B':
#ifdef DEBUG
                rval.debug_log_streams = optarg;
#else
                if ( util::streq(optarg, "help") ) {
                    fprintf(stderr, "debug streams unavailable\n");
                    exit(1);
                }
#endif
                break;

            case 'C': rval.ignore_checksums = true; break;
            case 'D': rval.deterministic_mode = true; break;
            case 'E': rval.event_trace_file = optarg; break;
            case 'F':
                if ( rval.dns_mode != detail::DNS_DEFAULT ) {
                    fprintf(stderr, "ERROR: can only change DNS manager mode once\n");
                    prompt_for_help(zargs[0]);
                    exit(1);
                }
                rval.dns_mode = detail::DNS_FORCE;
                break;
            case 'G': rval.random_seed_input_file = optarg; break;
            case 'H': rval.random_seed_output_file = optarg; break;
            case 'I': rval.identifier_to_print = optarg; break;
            case 'N': ++rval.print_plugins; break;
            case 'O': set_analysis_option(optarg, rval); break;
            case 'o': add_func_analysis_pattern(rval.analysis_options, optarg); break;
            case '0': add_file_analysis_pattern(rval.analysis_options, optarg); break;
            case 'P':
                if ( rval.dns_mode != detail::DNS_DEFAULT ) {
                    fprintf(stderr, "ERROR: can only change DNS manager mode once\n");
                    prompt_for_help(zargs[0]);
                    exit(1);
                }
                rval.dns_mode = detail::DNS_PRIME;
                break;
            case 'Q': rval.print_execution_time = true; break;
            case 'S': rval.print_signature_debug_info = true; break;
            case 'T': rval.signature_re_level = atoi(optarg); break;
            case 'U': rval.process_status_file = optarg; break;
            case 'W': rval.use_watchdog = true; break;
            case 'X': rval.zeekygen_config_file = optarg; break;

#ifdef USE_PERFTOOLS_DEBUG
            case 'm': rval.perftools_check_leaks = 1; break;
            case 'M': rval.perftools_profile = 1; break;
#endif

            case '~':
                rval.pseudo_realtime = 1.0;
                if ( optarg )
                    rval.pseudo_realtime = atof(optarg);
                break;

            case '#':
                fprintf(stderr, "ERROR: --test only allowed as first argument.\n");
                prompt_for_help(zargs[0]);
                exit(1);
                break;

            case 0:
                // This happens for long options that don't have
                // a short-option equivalent.
                if ( profile_scripts ) {
                    profile_filename = optarg ? optarg : "";
                    enable_script_profile = true;
                    profile_scripts = 0;
                }

                if ( profile_script_call_stacks ) {
                    enable_script_profile_call_stacks = true;
                    profile_script_call_stacks = 0;
                }

                if ( no_unused_warnings )
                    rval.no_unused_warnings = true;
                break;

            case '?':
            default:
                if ( optopt ) {
                    fprintf(stderr, "ERROR: Option %s requires an argument.\n", zargs[optind - 1]);
                }
                else {
                    fprintf(stderr, "ERROR: Unrecognized option %s\n", zargs[optind - 1]);
                }
                prompt_for_help(zargs[0]);
                exit(1);
                break;
        }

    if ( ! enable_script_profile && enable_script_profile_call_stacks )
        fprintf(stderr, "ERROR: --profile-scripts-traces requires --profile-scripts to be passed as well.\n");

    if ( enable_script_profile ) {
        activate_script_profiling(profile_filename.empty() ? nullptr : profile_filename.c_str(),
                                  enable_script_profile_call_stacks);
    }

    // Process remaining arguments. X=Y arguments indicate script
    // variable/parameter assignments. X::Y arguments indicate plugins to
    // activate/query. The remainder are treated as scripts to load.
    while ( optind < static_cast<int>(zeek_args.size()) ) {
        if ( strchr(zargs[optind], '=') )
            rval.script_options_to_set.emplace_back(zargs[optind++]);
        else if ( strstr(zargs[optind], "::") )
            rval.plugins_to_load.emplace(zargs[optind++]);
        else
            rval.scripts_to_load.emplace_back(zargs[optind++]);
    }

    auto canonify_script_path = [](std::string* path) {
        if ( path->empty() )
            return;

        *path = util::detail::normalize_path(*path);

        if ( (*path)[0] == '/' || (*path)[0] == '~' )
            // Absolute path
            return;

        if ( (*path)[0] != '.' ) {
            // Look up file in ZEEKPATH
            auto res = util::find_script_file(*path, util::zeek_path());

            if ( res.empty() ) {
                fprintf(stderr, "failed to locate script: %s\n", path->data());
                exit(1);
            }

            *path = std::move(res);

            if ( (*path)[0] == '/' || (*path)[0] == '~' )
                // Now an absolute path
                return;
        }

        // Need to translate relative path to absolute.
        char cwd[PATH_MAX];

        if ( ! getcwd(cwd, sizeof(cwd)) ) {
            fprintf(stderr, "failed to get current directory: %s\n", strerror(errno));
            exit(1);
        }

        *path = std::string(cwd) + "/" + *path;
    };

    if ( rval.supervisor_mode ) {
        // Translate any relative paths supplied to supervisor into absolute
        // paths for use by supervised nodes since they have the option to
        // operate out of a different working directory.
        for ( auto& s : rval.scripts_to_load )
            canonify_script_path(&s);
    }

    return rval;
}

} // namespace zeek
