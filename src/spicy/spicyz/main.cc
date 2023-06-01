// See the file "COPYING" in the main distribution directory for copyright.

#include <getopt.h>

#include <hilti/base/result.h>
#include <hilti/base/util.h>

#include "config.h"
#include "driver.h"
#include "glue-compiler.h"

using namespace zeek::spicy;

constexpr int OPT_CXX_LINK = 1000;

static struct option long_driver_options[] = {{"abort-on-exceptions", required_argument, nullptr, 'A'},
                                              {"show-backtraces", required_argument, nullptr, 'B'},
                                              {"compiler-debug", required_argument, nullptr, 'D'},
                                              {"cxx-link", required_argument, nullptr, OPT_CXX_LINK},
                                              {"debug", no_argument, nullptr, 'd'},
                                              {"debug-addl", required_argument, nullptr, 'X'},
                                              {"disable-optimizations", no_argument, nullptr, 'g'},
                                              {"dump-code", no_argument, nullptr, 'C'},
                                              {"enable-profiling", no_argument, nullptr, 'Z'},
                                              {"help", no_argument, nullptr, 'h'},
                                              {"keep-tmps", no_argument, nullptr, 'T'},
                                              {"library-path", required_argument, nullptr, 'L'},
                                              {"output", required_argument, nullptr, 'o'},
                                              {"output-c++", required_argument, nullptr, 'c'},
                                              {"output-c++-files", no_argument, nullptr, 'x'},
                                              {"print-module-path", no_argument, nullptr, 'M'},
                                              {"print-plugin-path", no_argument, nullptr,
                                               'P'}, // for backwards compatiblity
                                              {"print-prefix-path", no_argument, nullptr, 'p'},
                                              {"print-zeek-config", no_argument, nullptr, 'z'},
                                              {"report-times", required_argument, nullptr, 'R'},
                                              {"print-scripts-path", no_argument, nullptr, 'S'},
                                              {"skip-validation", no_argument, nullptr, '!'},
                                              {"version", no_argument, nullptr, 'v'},
                                              {"version-number", no_argument, nullptr, 'V'},
                                              {nullptr, 0, nullptr, 0}};

static void usage() {
    std::cerr << "Usage: spicyz [options] <inputs>\n"
                 "\n"
                 "  -c | --output-c++ <prefix>      Output generated C++ code.\n"
                 "  -d | --debug                    Include debug instrumentation into generated code.\n"
                 "  -g | --disable-optimizations    Disable HILTI-side optimizations of the generated "
                 "code.\n"
                 "  -o | --output-to <path>         Path for saving output.\n"
                 "  -v | --version                  Print version information.\n"
                 "  -x | --output-c++ <prefix>      Output generated C++ code into set of files.\n"
                 "  -z | --print-zeek-config        Print path to zeek-config.\n"
                 "  -A | --abort-on-exceptions      When executing compiled code, abort() instead of "
                 "throwing HILTI "
                 "exceptions.\n"
                 "  -B | --show-backtraces          Include backtraces when reporting unhandled "
                 "exceptions.\n"
                 "  -C | --dump-code                Dump all generated code to disk for debugging.\n"
                 "  -D | --compiler-debug <streams> Activate compile-time debugging output for given "
                 "debug streams "
                 "(comma-separated; 'help' for list).\n"
                 "  -L | --library-path <path>      Add path to list of directories to search when "
                 "importing modules.\n"
                 "  -M | --print-module-path        Print the Zeek's search path for compiled Spicy modules.\n"
                 "  -p | --print-prefix-path        Print installation prefix path.\n"
                 "  -R | --report-times             Report a break-down of compiler's execution time.\n"
                 "  -T | --keep-tmps                Do not delete any temporary files created.\n"
                 "       --skip-validation          Don't validate ASTs (for debugging only).\n"
                 "  -X | --debug-addl <addl>        Implies -d and adds selected additional "
                 "instrumentation."
                 "(comma-separated; see 'help' for list).\n"
                 "       --cxx-link <lib>           Link specified static archive or shared library "
                 "during JIT or to "
                 "  -Z | --enable-profiling         Report profiling statistics after execution.\n"
                 "\n"
                 "Inputs can be *.spicy, *.evt, *.hlt, .cc/.cxx\n"
                 "\n";
}

using hilti::Nothing;

static hilti::Result<Nothing> parseOptions(int argc, char** argv, hilti::driver::Options* driver_options,
                                           hilti::Options* compiler_options) {
    while ( true ) {
        int c = getopt_long(argc, argv, "ABc:Cdgx:X:D:L:Mo:pPRSTvhzZ", long_driver_options, nullptr);

        if ( c == -1 )
            break;

        switch ( c ) {
            case 'A': driver_options->abort_on_exceptions = true; break;

            case 'B': driver_options->show_backtraces = true; break;

            case 'c':
                driver_options->output_cxx = true;
                driver_options->output_cxx_prefix = optarg;
                driver_options->execute_code = false;
                compiler_options->cxx_namespace_extern =
                    hilti::util::fmt("hlt_%s", hilti::rt::filesystem::path(optarg).stem().string());
                compiler_options->cxx_namespace_intern =
                    hilti::util::fmt("__hlt_%s", hilti::rt::filesystem::path(optarg).stem().string());
                break;

            case 'C': {
                driver_options->dump_code = true;
                break;
            }

            case 'd': {
                compiler_options->debug = true;
                break;
            }

            case 'g': {
                driver_options->global_optimizations = false;
                break;
            }

            case 'p': std::cout << configuration::InstallPrefix.native() << std::endl; return Nothing();

            case 'P':
                // For backwards compatibility with older plugins, print
                // the path where the `cmake/` folder is located.
                std::cout << configuration::DataPath().native() << std::endl;
                return Nothing();

            case 'x':
                driver_options->output_cxx = true;
                driver_options->output_cxx_prefix = optarg;
                driver_options->execute_code = false;
                driver_options->include_linker = true;
                compiler_options->cxx_namespace_extern =
                    hilti::util::fmt("hlt_%s", hilti::rt::filesystem::path(optarg).stem().string());
                compiler_options->cxx_namespace_intern =
                    hilti::util::fmt("__hlt_%s", hilti::rt::filesystem::path(optarg).stem().string());
                break;

            case 'X': {
                auto arg = std::string(optarg);

                if ( arg == "help" ) {
                    std::cerr << "Additional debug instrumentation:\n";
                    std::cerr << "   flow:     log function calls to debug stream \"hilti-flow\"\n";
                    std::cerr << "   location: track current source code location for error reporting\n";
                    std::cerr << "   trace:    log statements to debug stream \"hilti-trace\"\n";
                    std::cerr << "\n";
                    exit(0);
                }

                compiler_options->debug = true;

                if ( auto r = compiler_options->parseDebugAddl(arg); ! r )
                    return hilti::result::Error("nothing to do");

                break;
            }

            case 'D': {
                auto arg = std::string(optarg);

                if ( arg == "help" ) {
                    std::cerr << "Debug streams:\n";

                    for ( const auto& s : hilti::logging::DebugStream::all() )
                        std::cerr << "  " << s << "\n";

                    std::cerr << "\n";
                    return Nothing();
                }

                for ( const auto& s : hilti::util::split(arg, ",") ) {
                    if ( ! driver_options->logger->debugEnable(s) )
                        return hilti::result::Error(
                            hilti::util::fmt("Unknown debug stream '%s', use 'help' for list", arg));
                }

                break;
            }

            case 'L': compiler_options->library_paths.emplace_back(std::string(optarg)); break;

            case 'M': std::cout << configuration::ModulePath().native() << std::endl; return Nothing();

            case 'o': driver_options->output_path = std::string(optarg); break;

            case 'R': driver_options->report_times = true; break;

            case 'S': std::cout << "" << std::endl; return Nothing(); // No longer needed, but left for compatibility.

            case 'T':
                driver_options->keep_tmps = true;
                compiler_options->keep_tmps = true;
                break;

            case 'v': std::cout << configuration::ZeekVersion << std::endl; return Nothing();

            case 'V': std::cout << ZEEK_VERSION_NUMBER << std::endl; return Nothing();

            case 'z': {
                if ( auto zcfg = getenv("ZEEK_CONFIG"); zcfg && *zcfg )
                    std::cout << zcfg << std::endl;
                else
                    std::cout << configuration::InstallBinDir().native() << std::endl;

                return Nothing();
            }

            case 'Z':
#if SPICY_VERSION_NUMBER >= 10800
                driver_options->enable_profiling = true;
                compiler_options->enable_profiling = true;
#else
                std::cerr << "Profiling is not supported with this version of Spicy, ignoring '-Z'\n";
#endif
                break;

            case OPT_CXX_LINK:
#if SPICY_VERSION_NUMBER >= 10600
                compiler_options->cxx_link.emplace_back(optarg);
#else
                return hilti::result::Error("option '--cxx-link' is only supported for Spicy 1.6 or newer");
#endif
                break;

            case 'h': usage(); return Nothing();

            case '!': compiler_options->skip_validation = true; break;

            default: usage(); return hilti::result::Error("could not parse options");
        }
    }

    while ( optind < argc )
        driver_options->inputs.emplace_back(argv[optind++]);

    if ( driver_options->inputs.empty() )
        return hilti::result::Error("no input file given");

    if ( driver_options->output_path.empty() && ! driver_options->output_cxx )
        return hilti::result::Error("no output file for object code given, use -o <file>.hlto");

    return Nothing();
}

int main(int argc, char** argv) {
    Driver driver(std::make_unique<GlueCompiler>(), "", configuration::LibraryPath(), ZEEK_VERSION_NUMBER);

    hilti::driver::Options driver_options;
    driver_options.execute_code = true;
    driver_options.include_linker = true;

    auto compiler_options = driver.hiltiOptions();

    if ( auto rc = parseOptions(argc, argv, &driver_options, &compiler_options); ! rc ) {
        hilti::logger().error(rc.error().description());
        return 1;
    }

    driver.setDriverOptions(std::move(driver_options));
    driver.setCompilerOptions(std::move(compiler_options));
    driver.initialize();

    for ( const auto& p : driver.driverOptions().inputs ) {
        if ( auto rc = driver.loadFile(p); ! rc ) {
            hilti::logger().error(rc.error().description());
            return 1;
        }
    }

    if ( auto rc = driver.compile(); ! rc ) {
        hilti::logger().error(rc.error().description());

        if ( rc.error().context().size() )
            hilti::logger().error(rc.error().context());

        return 1;
    }

    return 0;
}
