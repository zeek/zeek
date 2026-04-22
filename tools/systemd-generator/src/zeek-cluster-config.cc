// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-cluster-config.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iterator>
#include <optional>
#include <regex>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace {

using zeek::detail::Option;
using zeek::detail::Section;

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

/**
 * Parses \a content as ini-like format, returning vector of Section instances
 * or a vector of error messages.
 *
 * Options not preceded by a [section] are placed into an unnamed section that
 * has an empty string as the name. This will be the first entry in the returned
 * list of sections. Zeek's config format either requires all options to exist
 * in the unnamed section, or only in sections, but not mixed.
 *
 * @param content The full content of zeek.conf as a string.
 *
 * @return Parsed sections and a vector of errors. If any errors occurred, do not work with the sections.
 */
std::pair<std::vector<Section>, std::vector<std::string>> parse_ini_like(const std::string& content) {
    std::vector<std::string> errors;
    std::set<std::string> section_names;
    std::set<std::string> option_names;
    std::vector<Section> sections;

    // Default unnamed section.
    Section current_section = Section();

    std::regex re_ignore("^(#.*|)$");       // commented or empty line
    std::regex re_section("^\\[(.+)\\]$");  // [<section_name>]
    std::regex re_option("^([^=]+)=(.*)$"); // key-value with = inbetween, value optional

    for ( const auto line_sv : split(content, '\n') ) {
        auto line = std::string(line_sv.data(), line_sv.size());
        trim(line);

        std::smatch smatch;

        if ( std::regex_search(line, re_ignore) ) {
            // ignore
        }
        else if ( std::regex_search(line, smatch, re_section) ) {
            if ( ! current_section.Options().empty() || ! current_section.Name().empty() ) {
                section_names.insert(current_section.Name());
                sections.push_back(std::move(current_section));
            }

            std::string section_name = smatch[1];
            if ( section_names.contains(section_name) ) {
                errors.push_back("duplicate section '" + section_name + "'");
                current_section = Section();
                break;
            }

            current_section = Section(std::move(section_name));
            option_names.clear();
        }
        else if ( std::regex_search(line, smatch, re_option) ) {
            std::string key = smatch[1];
            std::string value = smatch[2];
            trim(key);
            trim(value);

            if ( option_names.contains(key) ) {
                std::string message = "duplicate option '" + key + "'";
                if ( ! current_section.Name().empty() )
                    message = message + " in section '" + current_section.Name() + "'";

                errors.push_back(std::move(message));
                continue;
            }

            option_names.insert(key);
            current_section.AddOption({std::move(key), std::move(value)});
        }
        else {
            std::string message = "invalid line '" + line + "'";
            if ( ! current_section.Name().empty() )
                message = message + " in section '" + current_section.Name() + "'";

            errors.push_back(std::move(message));
            continue;
        }
    }

    if ( ! current_section.Options().empty() || ! current_section.Name().empty() ) {
        section_names.insert(current_section.Name());
        sections.push_back(std::move(current_section));
    }

    return {sections, errors};
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
    auto val = opt.Value();
    tolower(val);

    if ( val == "1" || val == "true" )
        return true;
    else if ( val == "0" || val == "false" )
        return false;

    fprintf(stderr, "invalid bool: %s for %s", opt.Value().c_str(), opt.Key().c_str());
    std::exit(1);
}

std::string validate_memory_max(const Option& opt) {
    auto val = opt.Value();
    if ( val.empty() )
        return "";

    auto c = val[val.size() - 1];

    if ( ! std::isdigit(c) ) {
        if ( c != 'K' && c != 'M' && c != 'G' && c != 'T' ) {
            std::fprintf(stderr, "invalid memory max: %s for %s\n", opt.Value().c_str(), opt.Key().c_str());
            std::exit(1);
        }

        val = val.substr(0, val.size() - 1);
    }

    if ( ! std::ranges::all_of(val.begin(), val.end(), [](auto c) { return std::isdigit(c); }) ) {
        std::fprintf(stderr, "invalid memory max: '%s' for %s\n", opt.Value().c_str(), opt.Key().c_str());
        std::exit(1);
    }

    return opt.Value();
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
    std::string val = opt.Value();
    trim(val);

    if ( val.empty() )
        return 0;

    auto nice = parse_int(val);
    if ( ! nice.has_value() || *nice < -20 || *nice > 19 ) {
        std::fprintf(stderr, "invalid nice value: %s for %s\n", opt.Value().c_str(), opt.Key().c_str());
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

std::pair<InterfaceWorkerConfig, std::string> zeek::detail::InterfaceWorkerConfig::from_section(
    const Section& section, bool allow_unknown_options) {
    auto section_name = section.Name();
    InterfaceWorkerConfig iwc;

    std::regex section_tag_re("interface ([_a-z0-9]+)$");

    if ( section_name.starts_with("interface") ) {
        std::smatch smatch;

        if ( ! std::regex_search(section_name, smatch, section_tag_re) )
            return {iwc, "invalid interface tag in '" + section_name + "' (must match /interface [_a-z0-9]+/)"};

        // Re-initialize iwc with the appropriate tag.
        iwc = InterfaceWorkerConfig(smatch[1]);
    }

    auto options = section.Options();
    if ( options.empty() )
        return {iwc, {"empty section"}};

    for ( const auto& option : options ) {
        std::string key = option.Key();
        tolower(key);

        // When the next interface option is reached, stop interpreting any keys.
        if ( key == "interface" ) {
            iwc.interface = option.Value();
        }
        else if ( key == "workers" ) {
            if ( auto workers = parse_int(option.Value()); workers )
                iwc.workers = *workers;
            else {
                return {iwc, "invalid workers value"};
            }
        }
        else if ( key == "worker_args" ) {
            iwc.args = option.Value();
        }
        else if ( key == "workers_cpu_list" ) {
            iwc.cpu_list = CpuList(option.Value());
            if ( ! iwc.cpu_list.IsValid() )
                return {iwc, "invalid workers_cpu_list value"};
        }
        else if ( key == "worker_numa_policy" || key == "workers_numa_policy" ) {
            if ( key == "workers_numa_policy" )
                fprintf(stderr, "Remove in v9.1: workers_numa_policy is deprecated, replace with worker_numa_policy\n");

            if ( option.Value() != "local" && option.Value() != "default" ) {
                return {iwc, "invalid '" + key + "' value"};
            }

            iwc.numa_policy = option.Value();
        }
        else if ( key == "worker_nice" ) {
            iwc.nice = validate_nice(option);
        }
        else if ( key == "worker_memory_max" ) {
            iwc.memory_max = validate_memory_max(option);
        }
        else if ( ! allow_unknown_options ) {
            std::string message = "invalid option '" + key + "'";
            if ( ! section.Name().empty() )
                message = message + " in section '" + section.Name() + "'";
            return {iwc, message};
        }
    }

    // Verify interface and workers was set!
    if ( iwc.Interface().empty() ) {
        std::string message = "missing or empty interface option";
        if ( ! section.Name().empty() )
            message = message + " in section '" + section.Name() + "'";
        return {iwc, message};
    }

    if ( iwc.Workers() <= 0 ) {
        // Tiny quirk: If this is section-less parsing and there's 0 workers,
        // default to 1 workers so that a simple zeek.conf that *only* contains
        // an interface works.
        if ( iwc.Workers() == 0 && section_name.empty() ) {
            iwc.workers = 1;
        }
        else {
            // Otherwise it is an error.

            std::string message = "missing or bad workers option";
            if ( ! section.Name().empty() )
                message = message + " in section '" + section.Name() + "'";
            return {iwc, message};
        }
    }

    return {iwc, ""};
}

ZeekClusterConfig parse_config(const std::filesystem::path& default_zeek_base_dir,
                               const std::filesystem::path& source_path) {
    ZeekClusterConfig config(default_zeek_base_dir, source_path);
    std::ifstream ifs(source_path, std::ios::binary);
    if ( ! ifs )
        return config;

    config.SetExists();

    // Read the whole config file into memory.
    auto content = std::string{std::istreambuf_iterator<char>(ifs), {}};

    // Parse ini-like.
    auto [sections, errors] = parse_ini_like(content);

    if ( ! errors.empty() ) {
        for ( const auto& error : errors )
            config.Error(error);

        return config;
    }

    // Empty section to use when there's no [zeek] section.
    Section empty_section;
    const Section* zeek_section = nullptr;

    // We support two configuration styles:
    //
    // 1) section-less: All configuration keys plainly in zeek.conf. Only a single
    //    interface is supported. parse_ini_like() returns a single unnamed Section
    //    with an empty string as the name.
    //
    // 2) A [zeek] section + multiple [interface <tag>] sections, where tag is
    //    some identifier.
    if ( sections.size() == 1 && sections[0].Name() == "" ) {
        // section-less
        auto [iwc, error] = InterfaceWorkerConfig::from_section(sections[0], /*allow_unknown_options=*/true);
        if ( ! error.empty() ) {
            config.Error(std::move(error));
            return config;
        }

        config.interface_worker_configs.push_back(std::move(iwc));

        zeek_section = &sections[0];
    }
    else {
        // Iterate through all sections, remember the [zeek] section
        // and interpret every [interface tag] section, too. If there's
        // an unnamed section, that's an error.
        for ( const auto& section : sections ) {
            if ( section.Name() == "" ) {
                config.Error("options in unnamed section mixed with options in sections");
                return config;
            }

            if ( section.Name() == "zeek" ) {
                zeek_section = &section;
                continue;
            }

            if ( ! section.Name().starts_with("interface") )
                continue;

            auto [iwc, error] = InterfaceWorkerConfig::from_section(section);
            if ( ! error.empty() ) {
                config.Error(std::move(error));
                return config;
            }

            config.interface_worker_configs.push_back(std::move(iwc));
        }

        if ( ! zeek_section )
            zeek_section = &empty_section;
    }

    assert(zeek_section);
    assert(zeek_section->Name() == "" || zeek_section->Name() == "zeek");

    // Before we start building a generic configuration framework, we should consider
    // that the number of options we ever add here should be limited, so maybe that
    // horrid if-else thing isn't all that bad, and it's obvious what's going on.
    auto options = zeek_section->Options();

    for ( size_t i = 0; i < options.size(); i++ ) {
        const auto& option = options[i];
        std::string key = option.Key();
        tolower(key);

        if ( key == "args" ) {
            config.args = option.Value();
        }
        else if ( key == "user" ) {
            config.user = option.Value();
        }
        else if ( key == "group" ) {
            config.group = option.Value();
        }
        else if ( key == "proxies" ) {
            config.proxies = std::atoi(option.Value().c_str());
        }
        else if ( key == "loggers" ) {
            config.loggers = std::atoi(option.Value().c_str());
        }
        else if ( key == "base_dir" ) {
            if ( ! option.Value().empty() )
                config.zeek_base_dir = option.Value();
        }
        else if ( key == "path" ) {
            config.path = option.Value();
        }
        else if ( key == "ext_path" ) {
            config.ext_path = option.Value();
        }
        else if ( key == "ext_zeek_path" ) {
            config.ext_zeek_path = option.Value();
        }
        else if ( key == "cluster_backend_args" ) {
            config.cluster_backend_args = option.Value();
        }
        else if ( key == "port" ) {
            config.port = std::atoi(option.Value().c_str());
        }
        else if ( key == "address" ) {
            config.address = option.Value();
        }
        else if ( key == "metrics_port" ) {
            config.metrics_port = std::atoi(option.Value().c_str());
        }
        else if ( key == "metrics_address" ) {
            config.metrics_address = option.Value();
        }
        else if ( key == "archiver" ) {
            config.enable_archiver = validate_bool(option);
        }
        else if ( key == "archiver_args" ) {
            config.archiver_args = option.Value();
        }
        else if ( key == "manager_nice" ) {
            config.nice_manager = validate_nice(option);
        }
        else if ( key == "logger_nice" ) {
            config.nice_logger = validate_nice(option);
        }
        else if ( key == "proxy_nice" ) {
            config.nice_proxy = validate_nice(option);
        }
        else if ( key == "manager_memory_max" ) {
            config.memory_max_manager = validate_memory_max(option);
        }
        else if ( key == "logger_memory_max" ) {
            config.memory_max_logger = validate_memory_max(option);
        }
        else if ( key == "proxy_memory_max" ) {
            config.memory_max_proxy = validate_memory_max(option);
        }
        else if ( key == "restart_interval_sec" ) {
            config.restart_interval_sec = std::atoi(option.Value().c_str());
        }
        else {
            // Ignore unknown keys if we parse section-less
            if ( zeek_section->Name().empty() )
                continue;

            // Otherwise, it's an error.
            config.Error("invalid key '" + key + "' in section '" + zeek_section->Name() + "'");
        }
    }

    // Default to the ZeroMQ backend if none is set.
    if ( config.cluster_backend_args.empty() )
        config.cluster_backend_args = "frameworks/cluster/backend/zeromq";

    // Default to local if args is empty - not sure if this is so clever.
    if ( config.args.empty() )
        config.args = "local";

    // Assume zeek-cluster-layout-generator is in /bin
    config.cluster_layout_generator = config.ZeekBaseDir() / "bin" / "zeek-cluster-layout-generator";

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
        std::to_string(Workers()),
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
    if ( ! ext_path.empty() )
        result += ext_path + ":";

    result += BinDir().string() + ":";

    return result + path;
}

std::optional<int> ZeekClusterConfig::NiceFor(const std::string& node) const {
    if ( node == "manager" )
        return nice_manager;
    else if ( node.starts_with("logger") )
        return nice_logger;
    else if ( node.starts_with("proxy") )
        return nice_proxy;

    std::fprintf(stderr, "invalid node '%s' in NiceFor()\n", node.c_str());
    return std::nullopt;
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
