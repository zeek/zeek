// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-cluster-config.h"

#include <unistd.h>
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <climits>
#include <cstring>
#include <fstream>
#include <iterator>
#include <optional>
#include <regex>
#include <set>
#include <stdexcept>
#include <string> // strerror
#include <string_view>
#include <vector>

#include "utils.h"

/**
 * Implementation for reading the zeek.conf file in C++ without third-party dependencies.
 *
 * Not overly pretty, but fairly straightforward.
 */
namespace {

using zeek::detail::is_valid_ip;
using zeek::detail::Option;
using zeek::detail::parse_int;
using zeek::detail::Section;
using zeek::detail::trim;

// Supports K, M, G or T as suffixes. Think systemd MemoryMax notation.
std::optional<std::string> parse_memory(const Option& opt) {
    auto val = opt.Value();
    if ( val.empty() )
        return {};

    auto c = val[val.size() - 1];

    if ( ! std::isdigit(c) ) {
        if ( c != 'K' && c != 'M' && c != 'G' && c != 'T' )
            return {};

        val = val.substr(0, val.size() - 1);
    }

    if ( ! std::ranges::all_of(val.begin(), val.end(), [](auto c) { return std::isdigit(c); }) )
        return {};

    return opt.Value();
}

std::optional<int> parse_nice(const Option& opt) {
    std::string val = opt.Value();
    trim(val);

    if ( val.empty() )
        return {};

    auto nice = parse_int(val);
    if ( ! nice.has_value() || *nice < -20 || *nice > 19 )
        return {};

    return *nice;
};

} // namespace

namespace zeek::detail {

// Use std::regex to parse ini like
std::pair<std::vector<Section>, std::vector<std::string>> parse_ini_like(const std::string& content) {
    std::vector<std::string> errors;
    std::set<std::string> section_names;
    std::set<std::string> option_names;
    std::vector<Section> sections;

    // Default unnamed section.
    Section current_section = Section();
    Option* current_option = nullptr;

    std::regex re_ignore("^(#.*|)$");                // commented or empty line
    std::regex re_section("^\\[(.+)\\]$");           // [<section_name>]
    std::regex re_option("^([_0-9a-z][^=]*)=(.*)$"); // key-value with = inbetween, value optional
    std::regex re_option_cont("^\\s+([^\\s]+.*)$");  // option continuation starts with space

    for ( const auto line_sv : split(content, '\n') ) {
        auto line = std::string(line_sv.data(), line_sv.size());
        rtrim(line);

        std::smatch smatch;

        if ( std::regex_search(line, re_ignore) ) {
            // ignore
        }
        else if ( std::regex_search(line, smatch, re_section) ) {
            // new section
            if ( current_section.HasOptions() || ! current_section.IsUnnamed() ) {
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
            current_option = nullptr;
            option_names.clear();
        }
        else if ( std::regex_search(line, smatch, re_option) ) {
            // new option
            std::string key = smatch[1];
            std::string value = smatch[2];
            trim(key);
            trim(value);

            if ( ! option_names.contains(key) ) {
                option_names.insert(key);
                // Keep the current option around for continuation lines.
                current_option = current_section.AddOption({std::move(key), std::move(value)});
            }
            else {
                std::string message = "duplicate option '" + key + "'";
                if ( ! current_section.Name().empty() )
                    message = message + " in section '" + current_section.Name() + "'";

                errors.push_back(std::move(message));
                continue;
            }
        }
        else if ( std::regex_search(line, smatch, re_option_cont) ) {
            // option value continuation
            if ( ! current_option ) {
                std::string message = "unexpected continuation line '" + line + "'";
                if ( ! current_section.Name().empty() )
                    message = message + " in section '" + current_section.Name() + "'";

                errors.push_back(std::move(message));
                continue;
            }

            current_option->AddValue(smatch[1]);
        }
        else {
            // error
            std::string message = "invalid line '" + line + "'";
            if ( ! current_section.Name().empty() )
                message = message + " in section '" + current_section.Name() + "'";

            errors.push_back(std::move(message));
            continue;
        }
    }

    // Include the last in-progress section.
    if ( current_section.HasOptions() || ! current_section.IsUnnamed() ) {
        section_names.insert(current_section.Name());
        sections.push_back(std::move(current_section));
    }

    return {sections, errors};
}

std::pair<InterfaceWorkerConfig, std::string> zeek::detail::InterfaceWorkerConfig::from_section(
    const Section& section, bool allow_unknown_options) {
    auto section_name = section.Name();
    InterfaceWorkerConfig iwc;

    std::regex section_name_re("interface ([-_a-z0-9]+)$");

    if ( section_name.starts_with("interface") ) {
        std::smatch smatch;

        if ( ! std::regex_search(section_name, smatch, section_name_re) )
            return {iwc, "invalid interface name in '" + section_name + "' (must match /interface [-_a-z0-9]+/)"};

        // Re-initialize iwc with the appropriate name.
        iwc = InterfaceWorkerConfig(smatch[1]);
    }

    auto options = section.Options();
    if ( options.empty() )
        return {iwc, {"empty section"}};

    bool has_interface = false;

    for ( const auto& option : options ) {
        std::string key = option.Key();
        tolower(key);

        // Only env and args options support multiple values.

        if ( ! key.ends_with("env") && ! key.ends_with("args") && option.Values().size() > 1 )
            return {iwc, "multiple values for '" + key + "' given"};

        // When the next interface option is reached, stop interpreting any keys.
        if ( key == "interface" ) {
            iwc.interface = option.Value();
            has_interface = true;
        }
        else if ( key == "workers" ) {
            auto result = parse_int(option.Value());
            if ( result && *result >= 0 )
                iwc.workers = *result;
            else {
                return {iwc, "invalid workers value: '" + option.Value() + "'"};
            }
        }
        else if ( key == "worker_args" ) {
            iwc.args = option.JoinedValues();
        }
        else if ( key == "worker_env" ) {
            auto [env, error] = option.AsEnvVars();
            if ( ! error.empty() )
                return {iwc, "error in worker_env: " + error};

            iwc.env = std::move(env);
        }
        else if ( key == "workers_cpu_list" ) {
            iwc.cpu_list = CpuList(option.Value());
            if ( ! iwc.cpu_list.IsValid() )
                return {iwc, "invalid workers_cpu_list value '" + option.Value() + "'"};
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
            iwc.nice = parse_nice(option);
            if ( ! iwc.nice.has_value() )
                return {iwc, "invalid worker_nice value '" + option.Value() + "'"};
        }
        else if ( key == "worker_memory_max" ) {
            iwc.memory_max = parse_memory(option);
            if ( ! iwc.memory_max.has_value() )
                return {iwc, "invalid worker_memory_max '" + option.Value() + "'"};
        }
        else if ( ! allow_unknown_options ) {
            std::string message = "invalid option '" + key + "'";
            if ( ! section.Name().empty() )
                message = message + " in section '" + section.Name() + "'";
            return {iwc, message};
        }
    }

    // This is probably overdoing it... If workers option is set to anything,
    // also expect a non-empty interface, else error. An empty interface option
    // is not allowed in an interface section, only in the unnamed section.
    if ( iwc.Workers() >= 0 && ! has_interface ) {
        std::string message = "found workers but no interface option";
        if ( ! section.Name().empty() )
            message = message + " in section '" + section.Name() + "'";
        return {iwc, message};
    }
    else if ( iwc.Workers() < 0 && ! iwc.Interface().empty() ) {
        std::string message = "found interface but no worker option";
        if ( ! section.Name().empty() )
            message = message + " in section '" + section.Name() + "'";
        return {iwc, message};
    }
    else if ( ! iwc.Name().empty() && iwc.Interface().empty() ) {
        std::string message = "empty interface option not allowed";
        if ( ! section.Name().empty() )
            message = message + " in section '" + section.Name() + "'";
        return {iwc, message};
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
    // 2) A [zeek] section + multiple [interface <name>] sections, where name
    //    is some user controlled identifier that is independent of the actual
    //    interface used for sniffing.
    if ( sections.size() == 1 && sections[0].Name() == "" ) {
        // section-less
        auto [iwc, error] = InterfaceWorkerConfig::from_section(sections[0], /*allow_unknown_options=*/true);
        if ( ! error.empty() )
            config.Error(std::move(error));

        config.interface_worker_configs.push_back(std::move(iwc));
        zeek_section = &sections[0];
    }
    else {
        // Iterate through all sections, remember the [zeek] section
        // and interpret every [interface name] section, too. If there's
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
            config.args = option.JoinedValues();
        }
        else if ( key == "manager_args" ) {
            config.manager_args = option.JoinedValues();
        }
        else if ( key == "logger_args" ) {
            config.logger_args = option.JoinedValues();
        }
        else if ( key == "proxy_args" ) {
            config.proxy_args = option.JoinedValues();
        }
        else if ( key == "archiver_args" ) {
            config.archiver_args = option.JoinedValues();
        }
        else if ( key == "env" ) {
            auto [env, error] = option.AsEnvVars();
            if ( error.empty() )
                config.env = std::move(env);
            else
                config.Error("error in env: " + error);
        }
        else if ( key == "manager_env" ) {
            auto [env, error] = option.AsEnvVars();
            if ( error.empty() )
                config.manager_env = std::move(env);
            else
                config.Error("error in manager_env: " + error);
        }
        else if ( key == "logger_env" ) {
            auto [env, error] = option.AsEnvVars();
            if ( error.empty() )
                config.logger_env = std::move(env);
            else
                config.Error("error in logger_env: " + error);
        }
        else if ( key == "proxy_env" ) {
            auto [env, error] = option.AsEnvVars();
            if ( error.empty() )
                config.proxy_env = std::move(env);
            else
                config.Error("error in proxy_env: " + error);
        }
        else if ( key == "archiver_env" ) {
            auto [env, error] = option.AsEnvVars();
            if ( error.empty() )
                config.archiver_env = std::move(env);
            else
                config.Error("error in proxy_env: " + error);
        }
        else if ( key == "user" ) {
            config.user = option.Value();
        }
        else if ( key == "group" ) {
            config.group = option.Value();
        }
        else if ( key == "manager" ) {
            // manager only support 0 or 1 for now. on or off.
            auto result = parse_int(option.Value());
            if ( result == 0 || result == 1 )
                config.manager = result == 1;
            else
                config.Error("invalid manager value: '" + option.Value() + "'");
        }
        else if ( key == "loggers" ) {
            auto result = parse_int(option.Value());
            if ( result && result >= 0 )
                config.loggers = *result;
            else
                config.Error("invalid loggers value: '" + option.Value() + "'");
        }
        else if ( key == "proxies" ) {
            auto result = parse_int(option.Value());
            if ( result && *result >= 0 )
                config.proxies = *result;
            else
                config.Error("invalid proxies value: '" + option.Value() + "'");
        }
        else if ( key == "archiver" ) {
            config.archiver_option = option.Value();
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
            config.cluster_backend_args = option.JoinedValues();
        }
        else if ( key == "cluster_layout" ) {
            config.cluster_layout = option.Value();
        }
        else if ( key == "cluster_node_prefix" ) {
            std::regex re_cluster_node_prefix("^[a-z0-0][-a-z0-9_]*");
            if ( option.Value().empty() || std::regex_match(option.Value(), re_cluster_node_prefix) )
                config.cluster_node_prefix = option.Value();
            else
                config.Error("invalid cluster_node_prefix '" + option.Value() +
                             "' (must be empty or match /[a-z0-9][-_a-z0-9]+/)");
        }
        else if ( key == "port" || key == "cluster_port" ) {
            config.cluster_port = std::atoi(option.Value().c_str());
        }
        else if ( key == "address" || key == "cluster_address" ) {
            if ( is_valid_ip(option.Value()) )
                config.cluster_address = option.Value();
            else
                config.Error("invalid address '" + option.Value() + "'");
        }
        else if ( key == "metrics_port" ) {
            config.metrics_port = std::atoi(option.Value().c_str());
        }
        else if ( key == "manager_nice" && ! option.Empty() ) {
            config.manager_nice = parse_nice(option);
            if ( ! config.manager_nice.has_value() )
                config.Error("invalid manager_nice value '" + option.Value() + "'");
        }
        else if ( key == "logger_nice" && ! option.Empty() ) {
            config.logger_nice = parse_nice(option);
            if ( ! config.logger_nice.has_value() )
                config.Error("invalid logger_nice value '" + option.Value() + "'");
        }
        else if ( key == "proxy_nice" && ! option.Empty() ) {
            config.proxy_nice = parse_nice(option);
            if ( ! config.proxy_nice.has_value() )
                config.Error("invalid proxy_nice value '" + option.Value() + "'");
        }
        else if ( key == "archiver_nice" && ! option.Empty() ) {
            config.archiver_nice = parse_nice(option);
            if ( ! config.archiver_nice.has_value() )
                config.Error("invalid archiver_nice value '" + option.Value() + "'");
        }
        else if ( key == "manager_memory_max" && ! option.Empty() ) {
            config.manager_memory_max = parse_memory(option);
            if ( ! config.manager_memory_max.has_value() )
                config.Error("invalid manager_memory_max '" + option.Value() + "'");
        }
        else if ( key == "logger_memory_max" && ! option.Empty() ) {
            config.logger_memory_max = parse_memory(option);
            if ( ! config.logger_memory_max.has_value() )
                config.Error("invalid logger_memory_max '" + option.Value() + "'");
        }
        else if ( key == "proxy_memory_max" && ! option.Empty() ) {
            config.proxy_memory_max = parse_memory(option);
            if ( ! config.proxy_memory_max.has_value() )
                config.Error("invalid proxy_memory_max '" + option.Value() + "'");
        }
        else if ( key == "archiver_memory_max" && ! option.Empty() ) {
            config.archiver_memory_max = parse_memory(option);
            if ( ! config.archiver_memory_max.has_value() )
                config.Error("invalid archiver_memory_max '" + option.Value() + "'");
        }
        else if ( key == "manager_cpu_set" ) {
            config.manager_cpu_set = CpuList(option.Value());
            if ( ! config.manager_cpu_set->IsValid() )
                config.Error("invalid manager_cpu_set '" + option.Value() + "'");
        }
        else if ( key == "logger_cpu_set" ) {
            config.logger_cpu_set = CpuList(option.Value());
            if ( ! config.logger_cpu_set->IsValid() )
                config.Error("invalid logger_cpu_set '" + option.Value() + "'");
        }
        else if ( key == "proxy_cpu_set" ) {
            config.proxy_cpu_set = CpuList(option.Value());
            if ( ! config.proxy_cpu_set->IsValid() )
                config.Error("invalid proxy_cpu_set '" + option.Value() + "'");
        }
        else if ( key == "archiver_cpu_set" ) {
            config.archiver_cpu_set = CpuList(option.Value());
            if ( ! config.archiver_cpu_set->IsValid() )
                config.Error("invalid archiver_cpu_set '" + option.Value() + "'");
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

    // If this is a cluster configuration, but no explicit cluster_node_prefix set
    // in the configuration,  use the hostname part of the filename.
    if ( ! config.cluster_node_prefix.has_value() && config.HasFilenameHost() )
        config.cluster_node_prefix = config.FilenameHost();

    // If archiver_option wasn't set, default it to "1" if this host
    // has a manager, or is running loggers.
    if ( ! config.archiver_option.has_value() && (config.manager || config.loggers > 0) )
        config.archiver_option = "1";

    // Single host mode? Use cluster_address 127.0.0.1 if not set.
    if ( ! config.HasFilenameHost() && config.cluster_address.empty() )
        config.cluster_address = "127.0.0.1";

    // Default to local if args is empty - not sure if this is so clever.
    if ( config.args.empty() )
        config.args = "local";

    // Assume zeek-cluster-layout-generator is in /bin
    config.cluster_layout_generator = config.ZeekBaseDir() / "bin" / "zeek-cluster-layout-generator";

    return config;
}

bool ZeekClusterConfig::HasFilenameHost() const {
    // Example: xxx/cluster/<hostname>.zeek.conf
    auto ext1 = source_path.extension();
    auto ext2 = source_path.stem().extension();
    auto host = source_path.stem().stem();
    return ! host.empty() && ext2 == ".zeek" && ext1 == ".conf";
}

std::string ZeekClusterConfig::FilenameHost() const {
    // Example: xxx/cluster/host.zeek.conf
    if ( ! HasFilenameHost() )
        throw std::logic_error("Do not call FilenameHost() if ! HasFilenameHost()");

    return source_path.stem().stem();
}

std::string ZeekClusterConfig::ClusterLayoutCommand() const {
    // If a cluster_layout is given in the configuration, copy that
    // into the generated script directory.
    if ( cluster_layout.has_value() ) {
        std::vector<std::string> cmd_args = {
            "cp",
            "-f",
            cluster_layout->string(),
            (GeneratedScriptsDir() / "cluster-layout.zeek").string(),
        };

        return join(cmd_args);
    }

    // If this configuration is coming from /etc/zeek/cluster, use
    // the zeek-cluster-layout-generator executable's -C argument to
    // pass the directory.
    if ( HasFilenameHost() ) {
        std::vector<std::string> cmd_args = {
            cluster_layout_generator.string(),
            "-C",
            Directory(),
            "-o",
            (GeneratedScriptsDir() / "cluster-layout.zeek").string(),
        };

        return join(cmd_args);
    }

    // First, construct the -W argument. Either it's a single number when
    // there's only a single unnamed interface, or it's in eth0:2,eth1:2,...
    // form as to include the interface name/identifier into the worker names.
    std::string worker_arg;
    for ( const auto& iwc : interface_worker_configs ) {
        // If there is an interface with an empty name, there should only
        // be a single interface and worker_arg not yet populated.
        //
        // If this throws, there must be some config validation error earlier.
        if ( iwc.Name().empty() ) {
            if ( ! worker_arg.empty() || interface_worker_configs.size() != 1 )
                throw std::logic_error("empty name but worker_arg already populated?");

            worker_arg = std::to_string(iwc.Workers() >= 0 ? iwc.Workers() : 0);
            break;
        }

        if ( ! worker_arg.empty() )
            worker_arg += ",";

        worker_arg += (iwc.Name() + ":" + std::to_string(iwc.Workers()));
    }

    // If there weren't any workers at all, pass zero.
    if ( worker_arg.empty() )
        worker_arg = "0";

    std::vector<std::string> cmd_args = {
        cluster_layout_generator.string(),
        "-L",
        std::to_string(loggers >= 0 ? loggers : 0),
        "-P",
        std::to_string(proxies >= 0 ? proxies : 0),
        "-W",
        worker_arg,
        "-p",
        std::to_string(cluster_port),
        "-a",
        cluster_address,
        "-m",
        std::to_string(metrics_port),
        "-b",
        cluster_address,
    };

    // Just in case - if there's no manager, disable it.
    if ( ! Manager() ) {
        cmd_args.emplace_back("-M");
        cmd_args.emplace_back("0");
    }

    // Add -x if a cluster_node_prefix was given.
    if ( cluster_node_prefix.has_value() && ! cluster_node_prefix->empty() ) {
        cmd_args.emplace_back("-x");
        cmd_args.emplace_back(*cluster_node_prefix);
    }

    // Where to store the generated file.
    cmd_args.emplace_back("-o");
    cmd_args.emplace_back((GeneratedScriptsDir() / "cluster-layout.zeek").string());

    return join(cmd_args);
}

std::string ZeekClusterConfig::ArchiverCommand() const {
    if ( ! archiver_option.has_value() || (*archiver_option == "0") )
        throw std::logic_error("ArchiverCommand() called but archiver_option is 0");

    std::vector<std::string> cmd_args;

    if ( *archiver_option == "1" ) {
        std::filesystem::path archiver_exe = ZeekBaseDir() / "bin" / "zeek-archiver";
        cmd_args = {
            archiver_exe.string(),
            ArchiverArgs(),
            LogQueueDir().string(),
            LogArchiveDir().string(),
        };
    }
    else {
        cmd_args = {
            *archiver_option,
            ArchiverArgs(),
        };
    }

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

std::optional<std::string> gethostname() {
#ifdef HOST_NAME_MAX
    char buf[HOST_NAME_MAX];
#else
    char buf[64];
#endif

    if ( ::gethostname(buf, sizeof(buf)) < 0 ) {
        std::fprintf(stderr, "failed gethostname: %s", ::strerror(errno));
        return std::nullopt;
    }

    // Use the short hostname only. The system's hostname as returned by
    // gethostname() may contain a domain part if that was included in a
    // call to sethostname(). Truncate by replacing the first dot with 0.
    if ( auto* dot = strchr(buf, '.'); dot )
        *dot = '\0';

    return buf;
}

} // namespace zeek::detail
