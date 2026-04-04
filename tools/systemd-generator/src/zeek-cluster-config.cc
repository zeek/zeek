// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-cluster-config.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {

void ltrim(std::string& s) {
    s.erase(s.begin(), std::ranges::find_if(s.begin(), s.end(), [](unsigned char ch) { return ! std::isspace(ch); }));
}

void rtrim(std::string& s) {
    s.erase(std::ranges::find_if(s.rbegin(), s.rend(), [](unsigned char ch) { return ! std::isspace(ch); }).base(),
            s.end());
}

void trim(std::string& s) {
    ltrim(s);
    rtrim(s);
}

void tolower(std::string& s) {
    std::ranges::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
}

/**
 * Split \a v by \a delim into a vector of string views.
 */
std::vector<std::string_view> split(std::string_view v, char delim) {
    std::vector<std::string_view> result;
    size_t pos = 0;

    do {
        size_t end = v.find(delim, pos);
        // if npos, npos-pos still means till end of string.
        result.emplace_back(v.substr(pos, end - pos));
        if ( end == std::string_view::npos )
            break;

        pos = end + 1;

        // Trailing delimiter? Add empty entry.
        if ( pos >= v.size() )
            result.emplace_back(v.substr(pos, 0));
    } while ( pos < v.size() );

    return result;
}

struct Option {
    std::string key;
    std::string value;
    std::string orig; // The line from which key and value were extracted.
};

/**
 * Split the configuration into a vector of options.
 */
std::vector<Option> split_config(std::string content) {
    std::vector<Option> result;
    using std::operator""sv;

    for ( const auto line_sv : split(content, '\n') ) {
        auto line = std::string(line_sv.data(), line_sv.size());

        trim(line);

        if ( line.empty() || line[0] == '#' )
            continue;

        auto eq_pos = line.find('=');
        if ( eq_pos == std::string::npos ) {
            std::fprintf(stderr, "line '%s' missing =\n", line.c_str());
            std::exit(1);
        }

        auto key = line.substr(0, eq_pos);
        auto value = line.substr(eq_pos + 1);
        trim(key);
        trim(value);

        result.push_back({.key = std::move(key), .value = std::move(value), .orig = {line_sv.begin(), line_sv.end()}});
    }

    return result;
}

/**
 * " ".join(...) in C++, meh.
 */
std::string join(const std::vector<std::string>& args, const std::string& sep = " ") {
    std::string result;

    for ( const auto& arg : args ) {
        if ( ! result.empty() && ! sep.empty() )
            result += sep;

        result += arg;
    }

    return result;
}

bool validate_bool(const Option& opt) {
    auto val = opt.value;
    tolower(val);

    if ( val == "1" || val == "true" )
        return true;
    else if ( val == "0" || val == "false" )
        return false;

    fprintf(stderr, "invalid bool: %s for %s", opt.value.c_str(), opt.key.c_str());
    std::exit(1);
}

std::string validate_memory_max(const Option& opt) {
    auto val = opt.value;
    if ( val.empty() )
        return "";

    auto c = val[val.size() - 1];

    if ( ! std::isdigit(c) ) {
        if ( c != 'K' && c != 'M' && c != 'G' && c != 'T' ) {
            std::fprintf(stderr, "invalid memory max: %s for %s\n", opt.value.c_str(), opt.key.c_str());
            std::exit(1);
        }

        val = val.substr(0, val.size() - 1);
    }

    if ( ! std::ranges::all_of(val.begin(), val.end(), [](auto c) { return std::isdigit(c); }) ) {
        std::fprintf(stderr, "invalid memory max: '%s' for %s\n", opt.value.c_str(), opt.key.c_str());
        std::exit(1);
    }

    return opt.value;
}

std::optional<int> parse_int(std::string_view sv) {
    if ( sv.size() == 0 )
        return {};

    // Copy to a string instance.
    std::string s = {sv.data(), sv.size()};

    char* endptr = nullptr;
    int result = std::strtol(s.c_str(), &endptr, 10);

    if ( endptr != &s[s.size()] ) // was the whole string valid?
        return {};

    return result;
}

int validate_nice(const Option& opt) {
    std::string val = opt.value;
    trim(val);

    if ( val.empty() )
        return 0;

    auto nice = parse_int(val);
    if ( ! nice.has_value() || *nice < -20 || *nice > 19 ) {
        std::fprintf(stderr, "invalid nice value: %s for %s\n", opt.value.c_str(), opt.key.c_str());
        std::exit(1);
    }

    return *nice;
};

} // namespace

namespace zeek::detail {

// Grumble. Feels like wrong to implement this by hand.
std::optional<std::string> ZeekClusterConfig::SubstituteVars(const std::string& s,
                                                             const std::map<std::string, std::string>& vars) {
    std::size_t pos = 0;
    std::string result;

    while ( pos < s.size() ) {
        std::size_t needle = s.find("${", pos);
        if ( needle == std::string::npos ) {
            result += s.substr(pos);
            break;
        }
        // std::fprintf(stderr, "found needle at %zu in %s\n", needle, s.c_str());

        // Check for escaped $, don't include the \\, but include the ${
        if ( needle > 0 && s[needle - 1] == '\\' ) {
            result += s.substr(pos, needle - (pos + 1));
            result += "${";
            pos = needle + 2;
            continue;
        }

        if ( needle > pos )
            result += s.substr(pos, needle - pos);

        // Skip the ${
        pos = needle + 2;

        std::size_t close_needle = s.find('}', pos);

        // Missing closing } - it's an error.
        if ( close_needle == std::string::npos )
            return std::nullopt;

        std::string var = s.substr(pos, close_needle - pos);
        auto it = vars.find(var);

        if ( it == vars.end() ) {
            fprintf(stderr, "invalid substitution var '%s'\n", var.c_str());
            return std::nullopt;
        }

        result += it->second;

        pos = close_needle + 1;
    }

    return result;
}

// More grumble.
CpuList::CpuList(const std::string& list) {
    using std::operator""sv;

    auto number_or_range_parts = split(list, ',');

    for ( const auto& number_or_range : number_or_range_parts ) {
        auto parts = split(number_or_range, '-');

        if ( parts.size() == 2 ) {
            // Parse the l-r[:stride] format.
            int stride = 1;
            std::optional<int> l, r;

            // Any stride in the range?
            auto stride_parts = split(parts[1], ':');
            if ( stride_parts.size() == 2 ) {
                auto maybe_stride = parse_int(stride_parts[1]);
                if ( maybe_stride.has_value() && *maybe_stride > 0 ) {
                    stride = *maybe_stride;
                }
                else {
                    is_valid = false;
                    return;
                }

                r = parse_int(stride_parts[0]);
            }
            else if ( stride_parts.size() == 1 ) {
                r = parse_int(parts[1]);
            }
            else {
                is_valid = false;
                return;
            }

            l = parse_int(parts[0]);

            if ( ! l.has_value() || ! r.has_value() || *l < 0 || *r < 0 || *r < *l ) {
                is_valid = false;
                return;
            }

            // Expand range with strides.
            for ( int i = *l; i <= *r; i += stride )
                cpus.push_back(i);
        }
        else if ( parts.size() == 1 ) {
            // Not a range, just a single number expected.
            auto n = parse_int(parts[0]);
            if ( ! n ) {
                is_valid = false;
                return;
            }
            cpus.push_back(*n);
        }
        else {
            is_valid = false;
            return;
        }
    }
}

ZeekClusterConfig parse_config(const std::filesystem::path& default_zeek_base_dir,
                               const std::filesystem::path& source_path) {
    ZeekClusterConfig config(default_zeek_base_dir, source_path);
    std::ifstream ifs(source_path, std::ios::binary);
    if ( ! ifs )
        return config;

    config.SetExists();

    auto content = std::string{std::istreambuf_iterator<char>(ifs), {}};
    auto entries = split_config(std::move(content));

    // Before we start building a generic configuration framework, we should consider
    // that the number of options we ever add here should be limited, so maybe that
    // horrid if-else thing isn't all that bad, and it's obvious what's going on.
    for ( const auto& entry : entries ) {
        std::string key = entry.key;
        tolower(key);

        if ( key == "interface" ) {
            config.interface = entry.value;
        }
        else if ( key == "args" ) {
            config.args = entry.value;
        }
        else if ( key == "user" ) {
            config.user = entry.value;
        }
        else if ( key == "group" ) {
            config.group = entry.value;
        }
        else if ( key == "workers" ) {
            config.workers = std::atoi(entry.value.c_str());
        }
        else if ( key == "proxies" ) {
            config.proxies = std::atoi(entry.value.c_str());
        }
        else if ( key == "loggers" ) {
            config.loggers = std::atoi(entry.value.c_str());
        }
        else if ( key == "base_dir" && ! entry.value.empty() ) {
            config.zeek_base_dir = entry.value;
        }
        else if ( key == "path" ) {
            config.path = entry.value;
        }
        else if ( key == "ext_path" ) {
            config.ext_path = entry.value;
        }
        else if ( key == "ext_zeek_path" ) {
            config.ext_zeek_path = entry.value;
        }
        else if ( key == "workers_cpu_list" ) {
            config.workers_cpu_list = CpuList(entry.value);
        }
        else if ( key == "workers_numa_policy" ) {
            if ( entry.value != "local" && entry.value != "default" ) {
                std::fprintf(stderr, "invalid workers_numa_policy '%s'", entry.value.c_str());
                std::exit(1);
            }

            config.workers_numa_policy = entry.value;
        }
        else if ( key == "cluster_backend_args" ) {
            config.cluster_backend_args = entry.value;
        }
        else if ( key == "port" ) {
            config.port = std::atoi(entry.value.c_str());
        }
        else if ( key == "address" ) {
            config.address = entry.value;
        }
        else if ( key == "metrics_port" ) {
            config.metrics_port = std::atoi(entry.value.c_str());
        }
        else if ( key == "metrics_address" ) {
            config.metrics_address = entry.value;
        }
        else if ( key == "archiver" ) {
            config.enable_archiver = validate_bool(entry);
        }
        else if ( key == "archiver_args" ) {
            config.archiver_args = entry.value;
        }
        else if ( key == "manager_nice" ) {
            config.nice_manager = validate_nice(entry);
        }
        else if ( key == "logger_nice" ) {
            config.nice_logger = validate_nice(entry);
        }
        else if ( key == "proxy_nice" ) {
            config.nice_proxy = validate_nice(entry);
        }
        else if ( key == "worker_nice" ) {
            config.nice_worker = validate_nice(entry);
        }
        else if ( key == "manager_memory_max" ) {
            config.memory_max_manager = validate_memory_max(entry);
        }
        else if ( key == "logger_memory_max" ) {
            config.memory_max_logger = validate_memory_max(entry);
        }
        else if ( key == "proxy_memory_max" ) {
            config.memory_max_proxy = validate_memory_max(entry);
        }
        else if ( key == "worker_memory_max" ) {
            config.memory_max_worker = validate_memory_max(entry);
        }
        else if ( key == "restart_interval_sec" ) {
            config.restart_interval_sec = std::atoi(entry.value.c_str());
        }
        else {
            std::fprintf(stderr, "ignoring unknown key '%s' from line '%s'\n", key.c_str(), entry.orig.c_str());
        }
    }

    // Default to the ZeroMQ backend if none is set.
    if ( config.cluster_backend_args.empty() )
        config.cluster_backend_args = "frameworks/cluster/backend/zeromq";

    if ( config.args.empty() )
        config.args = "local";

    // Assume zeek-cluster-layout-generator is in /bin
    config.cluster_layout_generator = config.ZeekBaseDir() / "bin" / "zeek-cluster-layout-generator";

    config.source_path = source_path;

    return config;
}

std::string ZeekClusterConfig::ClusterLayoutGeneratorCommand() const {
    std::vector<std::string> cmd_args = {
        cluster_layout_generator.string(),
        "-L",
        std::to_string(loggers),
        "-P",
        std::to_string(proxies),
        "-W",
        std::to_string(workers),
        "-p",
        std::to_string(port),
        "-a",
        address,
        "-m",
        std::to_string(metrics_port),
        "-b",
        metrics_address,
        "-o",
        (GeneratedScriptsDir() / "cluster-layout.zeek").string(),
    };

    return join(cmd_args);
}

std::string ZeekClusterConfig::ArchiverCommand() const {
    std::filesystem::path archiver_exe = ZeekBaseDir() / "bin" / "zeek-archiver";
    std::vector<std::string> cmd_args = {
        archiver_exe.string(),
        ArchiverArgs(),
        LogQueueDir().string(),
        LogArchiveDir().string(),
    };

    return join(cmd_args);
}

std::string ZeekClusterConfig::ZeekPath() const {
    // TODO: Are these somewhere available as definition in a header or define?
    std::vector<std::filesystem::path> suffixes = {
        "share/zeek",
        "share/zeek/policy",
        "share/zeek/site",
        "share/zeek/builtin-plugins",
    };

    std::string result;

    if ( ! ext_zeek_path.empty() )
        result += ext_zeek_path + ":";

    result += GeneratedScriptsDir().string();
    result += ":";

    for ( size_t i = 0; i < suffixes.size(); i++ ) {
        result += (zeek_base_dir / suffixes[i]).string();
        if ( i < suffixes.size() - 1 )
            result += ":";
    }
    return result;
}

std::string ZeekClusterConfig::Path() const {
    std::string result;
    if ( ! ext_zeek_path.empty() )
        result += ext_path + ":";

    result += BinDir().string() + ":";

    return result + path;
}

int ZeekClusterConfig::NiceFor(const std::string& node) const {
    if ( node == "manager" )
        return nice_manager;
    else if ( node.starts_with("logger-") )
        return nice_logger;
    else if ( node.starts_with("proxy-") )
        return nice_proxy;
    else if ( node.starts_with("worker-") )
        return nice_worker;

    std::fprintf(stderr, "invalid node '%s' in NiceFor()\n", node.c_str());
    abort();
}

const std::string& ZeekClusterConfig::MemoryMaxFor(const std::string& node) const {
    if ( node == "manager" )
        return memory_max_manager;
    else if ( node.starts_with("logger-") )
        return memory_max_logger;
    else if ( node.starts_with("proxy-") )
        return memory_max_proxy;
    else if ( node.starts_with("worker-") )
        return memory_max_worker;

    std::fprintf(stderr, "invalid node '%s' in MemoryMaxFor()\n", node.c_str());
    abort();
}

/**
 * Really just testing for the SubstituteVars() function.
 */
void ZeekClusterConfig::RunUnitTests() {
    int errors = 0;

    auto test_split = [&errors](std::string s, char delim, std::vector<std::string_view> expected) {
        auto result = split(s, delim);

        if ( result != expected ) {
            std::fprintf(stderr, "FAIL: %s\n", s.c_str());
            std::fprintf(stderr, " result  ");
            for ( const auto& r : result )
                fprintf(stderr, " %s", std::string(r.data(), r.size()).c_str());
            fprintf(stderr, "\n");

            std::fprintf(stderr, " expected");
            for ( const auto& r : expected )
                fprintf(stderr, " %s", std::string(r.data(), r.size()).c_str());
            fprintf(stderr, "\n");
            ++errors;
        }
    };

    test_split("", ',', {""});
    test_split(",", ',', {"", ""});
    test_split("1,", ',', {"1", ""});
    test_split("1,2", ',', {"1", "2"});
    test_split("9,10-12:1,18-24:2", ',', {"9", "10-12:1", "18-24:2"});
    test_split("9:10", ':', {"9", "10"});
    test_split("9::10", ':', {"9", "", "10"});

    auto test_replace_vars = [&errors](std::string s, std::map<std::string, std::string> vars,
                                       std::optional<std::string> expected) {
        // std::fprintf(stderr, "=== run %s\n", s.c_str());
        auto result = ZeekClusterConfig::SubstituteVars(s, vars);

        if ( ! expected.has_value() ) {
            if ( result.has_value() ) {
                std::fprintf(stderr, "FAIL: expected error, but got result '%s'\n", result->c_str());
                ++errors;
            }
        }
        else {
            if ( ! result.has_value() ) {
                ++errors;
                std::fprintf(stderr, "FAIL: expected '%s' from '%s' but got error\n", expected.value().c_str(),
                             s.c_str());
            }
            else if ( result != expected ) {
                ++errors;
                std::fprintf(stderr, "FAIL: '%s', got '%s'\n", expected.value().c_str(), result.value().c_str());
            }
        }
    };

    test_replace_vars("af_packet::eth0", {{"b", "XXX"}}, "af_packet::eth0");
    test_replace_vars("\\${a}", {{"a", "XXX"}}, "${a}");
    test_replace_vars("${a}", {{"a", "AAA"}}, "AAA");
    test_replace_vars("a\\${b}", {{"b", "XXX"}}, "a${b}");
    test_replace_vars("a\\${b}c", {{"b", "XXX"}}, "a${b}c");
    test_replace_vars("a\\${b}\\c", {{"b", "XXX"}}, "a${b}\\c");
    test_replace_vars("a${b}", {{"b", "BBB"}}, "aBBB");
    test_replace_vars("a${b}${c}", {{"b", "BBB"}, {"c", "CCC"}}, "aBBBCCC");
    test_replace_vars("a${b}x${c}y", {{"b", "BBB"}, {"c", "CCC"}}, "aBBBxCCCy");


    auto test_parse_cpu = [&errors](std::string s, std::optional<std::vector<int>> expected = {}) {
        auto result = CpuList(s);

        if ( ! expected.has_value() ) {
            if ( result.IsValid() ) {
                fprintf(stderr, "FAIL: Expected failure but result valid for '%s'\n", s.c_str());
                ++errors;
                return;
            }
            return; // Expected failure and got it.
        }

        if ( result.Indices() != *expected ) {
            std::fprintf(stderr, "FAIL: indices wrong for '%s'\n", s.c_str());
            std::fprintf(stderr, " result  ");
            for ( const auto& r : result.Indices() )
                fprintf(stderr, " %d", r);
            fprintf(stderr, "\n");

            std::fprintf(stderr, " expected");
            for ( const auto& r : *expected )
                fprintf(stderr, " %d", r);
            fprintf(stderr, "\n");

            ++errors;
        }
    };

    test_parse_cpu("a");
    test_parse_cpu(",");
    test_parse_cpu("-");
    test_parse_cpu(":");
    test_parse_cpu("1,");
    test_parse_cpu("1,,2");
    test_parse_cpu(",2");
    test_parse_cpu("-2");
    test_parse_cpu("2-");
    test_parse_cpu("2-3-");
    test_parse_cpu("1,2-");
    test_parse_cpu("3-2");
    test_parse_cpu("1-2,3-2");
    test_parse_cpu("1-2:");
    test_parse_cpu("1-2:0");
    test_parse_cpu("1-2:-2");
    test_parse_cpu("1:");
    test_parse_cpu("1:0");
    test_parse_cpu("1:1");
    test_parse_cpu("1-2:1:2");
    test_parse_cpu("1-2:1:");
    test_parse_cpu("1-2::1::");
    test_parse_cpu("1-2:1::");

    test_parse_cpu("", std::vector<int>{});
    test_parse_cpu("1", {{1}});
    test_parse_cpu("3,2,2,4", {{3, 2, 2, 4}});
    test_parse_cpu("1-4", {{1, 2, 3, 4}});
    test_parse_cpu("1,3-5", {{1, 3, 4, 5}});
    test_parse_cpu("1-5:2", {{1, 3, 5}});
    test_parse_cpu("9,10-12:1,18-24:2,19-22:3", {{9, 10, 11, 12, 18, 20, 22, 24, 19, 22}});
    test_parse_cpu("0-8:2,10-20:3", {{0, 2, 4, 6, 8, 10, 13, 16, 19}});

    if ( errors > 0 )
        std::exit(1);
}

} // namespace zeek::detail
