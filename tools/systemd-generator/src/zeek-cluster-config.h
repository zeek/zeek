// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

// Support reading a single-node Zeek deployment configuration.
//
// This allows for reading a simple key-value based configuration file
// from <PREFIX>/etc/default/zeek and providing programmatic access.

#include <cassert>
#include <filesystem>
#include <map>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace zeek::detail {

/**
 *Split \a v by \a delim into a vector of string views.
 */
std::vector<std::string_view> split(std::string_view v, char delim);

/**
 * " ".join(...) in C++, meh.
 */
std::string join(std::span<const std::string> args, const std::string& sep = " ");

/**
 * Replace \a s with with all occurrences of ${var} replaced with the values of var in the map \a vars.
 */
std::optional<std::string> substitute_vars(const std::string& s, const std::map<std::string, std::string>& vars);

class Section;

/**
 * Parses \a content as ini-like format, returning vector of Section instances
 * or a vector of error messages.
 *
 * Options not preceded by a [section] are placed into an unnamed section that
 * has an empty string as the name. This will be the first entry in the returned
 * list of sections. Zeek's config format either requires all options to exist
 * in the unnamed section, or only in sections, but not mixed.
 *
 * This parser supports multi-value options by recognizing continuation lines
 * and inserting every line as a separate value to support things like environment
 * variables.
 *
 * worker_env =
 *   key1=val1
 *   key2=val2
 *
 * @param content The full content of zeek.conf as a string.
 *
 * @return Parsed sections and a vector of errors. If any errors occurred, do not work with the sections.
 */
std::pair<std::vector<Section>, std::vector<std::string>> parse_ini_like(const std::string& content);

class ZeekClusterConfig;

/**
 * Parse a single-node Zeek deployment configuration from file.
 *
 * @param default_zeek_base_dir Default path to use for constructing /bin /spool and /log directories.
 * @param file The configuration file to parse.
 *
 * @return A configuration instance. Use Exist() and IsValid() to determine if it is good to use.
 */
ZeekClusterConfig parse_config(const std::filesystem::path& default_zeek_base_dir, const std::filesystem::path& file);

/**
 * Parses a CPU list via the constructor.
 *
 * Some examples:
 *
 *   1,2,3,4  -> 1,2,3,4
 *   1-4      -> 1,2,3,4
 *   1-4:2    -> 1,3
 *   2-3,8-9  -> 2,3,8,9
 */
class CpuList {
public:
    /**
     * Parse a list of CPUs from a comma-separated string.
     *
     * @param list string representing a list of CPU numbers separated by commas.
     */
    CpuList(const std::string& list = "");

    /**
     * Get the CPU affinity for index \a index (1-based).
     */
    std::string CpuAtIndex(int index) const {
        if ( index <= 0 )
            throw std::logic_error("bad index: " + std::to_string(index));

        if ( cpus.empty() )
            return "";

        return std::to_string(cpus[(index - 1) % cpus.size()]);
    }

    bool IsValid() { return is_valid; }

    /**
     * Access to the parsed CPUs.
     */
    const std::vector<int>& Indices() const { return cpus; }

    /**
     * @return CPU indices as string sorted and joined using by \a sep.
     */
    std::string IndicesSetString(const std::string& sep = ",") const;

private:
    bool is_valid = true;
    std::vector<int> cpus;
};

/**
 * Environment variable.
 */
class EnvVar {
public:
    EnvVar(std::string key, std::string value) : key(std::move(key)), value(std::move(value)) {}

    const std::string& Key() const { return key; }
    const std::string& Value() const { return value; }

private:
    std::string key;
    std::string value;
};

/**
 * A single option.
 *
 * Most options have just a single value, but options can span multiple
 * lines via continuation. Every line is a dedicated value.
 */
struct Option {
public:
    Option(std::string key, std::string value) : key(std::move(key)) { values.push_back(std::move(value)); }

    const std::string& Key() const { return key; }
    const std::string& Value() const {
        if ( values.size() > 1 )
            throw std::logic_error("ignoring extra values from " + key);

        return values[0];
    }

    void AddValue(std::string value) { values.push_back(std::move(value)); }

    std::span<const std::string> Values() const { return values; }

    std::string JoinedValues() const { return join(values); };

    /**
     * Helper to create a vector of EnvVar instances from an option.
     *
     * This is useful for converting the multi-line env variables
     * into the EnvVar representation.
     */
    std::pair<std::vector<EnvVar>, std::string> AsEnvVars() const {
        std::vector<EnvVar> envs;
        for ( const auto& value : values ) {
            if ( value.empty() )
                continue;

            auto idx = value.find('=');
            if ( idx == std::string::npos )
                return {{}, "invalid env value '" + value + "'"};

            std::string k = value.substr(0, idx);
            std::string v = value.substr(idx + 1);
            envs.emplace_back(EnvVar(std::move(k), std::move(v)));
        }

        return {std::move(envs), ""};
    }

    /**
     * An option with an empty value is considered "empty".
     */
    bool Empty() const { return values.size() == 0 || (values.size() == 1 && values[0].empty()); }

private:
    std::string key;
    std::vector<std::string> values;
};

/**
 * A section in the configuration file.
 */
class Section {
public:
    Section() {}
    explicit Section(std::string name) : name(std::move(name)) {}

    const std::string& Name() const { return name; }
    std::span<const Option> Options() const { return {options.begin(), options.end()}; }
    bool IsUnnamed() const { return name.empty(); }
    bool HasOptions() const { return ! options.empty(); }

    /**
     * Add an option to this section.
     *
     * @return Pointer to the Option instance within the vector.
     */
    Option* AddOption(Option o) {
        options.push_back(std::move(o));
        return &(*std::prev(options.end()));
    }

private:
    std::string name;
    std::vector<Option> options;
};


/**
 * Hold info about an interface worker configuration.
 *
 * Essentially, this describes how many workers listen on a specific interface (which can be specified as template)
 * and the worker's arguments, memory settings, pinning, etc.
 *
 * From the perspective of the zeek.conf file, this is instantiated based on [interface <tag>] sections.
 */
class InterfaceWorkerConfig {
public:
    /**
     * Instantiate a InterfaceWorkerConfig from a section.
     *
     * @param section The options to parse from
     * @param allow_unknown_options If false, will error and return an error when encountering an unknown option.
     *
     * @return An instantiated InterfaceWorkerConfig or an error message on error.
     */
    static std::pair<InterfaceWorkerConfig, std::string> from_section(const Section& section,
                                                                      bool allow_unknown_options = false);

    /**
     * The tag from [interface <tag>] section.
     */
    const std::string& Tag() const { return tag; }

    const std::string& Interface() const { return interface; }

    int Workers() const { return workers; }

    /**
     * @return worker-{tag}-{index} or worker-{index}, depending on whether tag is set or not.
     */
    std::string FullWorkerName(int index) const {
        if ( index <= 0 || index > Workers() )
            throw std::logic_error("bad index: " + std::to_string(index));

        return FullWorkerName(std::to_string(index));
    }

    /**
     * A worker's working directory.
     */
    std::filesystem::path MakeWorkingDirectory(const std::filesystem::path& spool_dir,
                                               const std::string& suffix) const {
        return spool_dir / FullWorkerName(suffix);
    }

    const std::string& Args() const { return args; }

    const std::optional<std::string>& MemoryMax() const { return memory_max; }

    std::optional<int> Nice() const { return nice; }

    std::string AffinityFor(int index) const { return cpu_list.CpuAtIndex(index); }

    std::optional<const std::string> NumaPolicy() const { return numa_policy; }

    std::span<const EnvVar> Env() const { return std::span{env}; }

private:
    InterfaceWorkerConfig(std::string tag = "") : tag(std::move(tag)) {}

    std::string FullWorkerName(const std::string& suffix) const {
        if ( ! Tag().empty() )
            return "worker-" + Tag() + "-" + suffix;

        return "worker-" + suffix;
    }

    std::string tag;
    std::string interface;
    int workers = -1;

    std::string args; // worker specific args to append
    std::vector<EnvVar> env;

    std::optional<int> nice;
    std::optional<std::string> memory_max;
    CpuList cpu_list;
    std::optional<std::string> numa_policy;
};

/**
 * A Zeek cluster configuration for a single node.
 *
 * XXX: I want to rename this just to ZeekConfig.
 */
class ZeekClusterConfig {
public:
    ZeekClusterConfig(std::filesystem::path base_dir, std::filesystem::path source_path)
        : zeek_base_dir(std::move(base_dir)), source_path(std::move(source_path)) {}

    const std::filesystem::path& SourcePath() const { return source_path; }

    void SetExists() { exists = true; }

    bool Exists() const { return exists; }

    bool IsValid() const { return errors.empty(); }

    /**
     * @return true if the config's filename is <hostname>.zeek.conf
     */
    bool HasFilenameHost() const;

    /**
     * @return returns the <hostname> part from <hostname>.zeek.conf
     */
    std::string FilenameHost() const;

    /**
     * @return The directory where this configuration file lives in.
     */
    std::filesystem::path Directory() const { return source_path.parent_path(); }

    /**
     * Add error information to this config.
     */
    void Error(std::string msg) { errors.emplace_back(std::move(msg)); }

    std::span<const std::string> Errors() const { return errors; }

    const std::filesystem::path& ZeekBaseDir() const { return zeek_base_dir; }

    std::filesystem::path ZeekExe() const { return zeek_base_dir / "bin" / "zeek"; }

    std::filesystem::path BinDir() const { return ZeekBaseDir() / "bin"; };

    std::filesystem::path SpoolDir() const { return ZeekBaseDir() / "var" / "spool" / "zeek"; }

    /**
     * @return Where the zeek-archiver process archives logs into.
     */
    std::filesystem::path LogArchiveDir() const { return ZeekBaseDir() / "var" / "logs" / "zeek"; }

    std::filesystem::path GeneratedScriptsDir() const { return SpoolDir() / "generated-scripts"; }

    std::filesystem::path WorkingDirectory(const std::string& wdir) const { return SpoolDir() / wdir; }

    /**
     * @return the mkdir command for a process's working directory.
     */
    std::string MakeWorkingDirectoryCommand(const std::string& wdir) const {
        return "mkdir -p " + WorkingDirectory(wdir).string();
    }

    /**
     * @return the chown command for the process's working directory.
     */
    std::string ChownWorkingDirectoryCommand(const std::string& wdir) const {
        return "chown " + User() + ":" + Group() + " " + WorkingDirectory(wdir).string();
    }

    /**
     * @return Where logger processes rotate their log files into and zeek-archiver picks them up.
     */
    std::filesystem::path LogQueueDir() const { return SpoolDir() / "log-queue"; }

    /**
     * @return True if the manager should be installed, otherwise false.
     */
    bool Manager() const { return manager; }

    /**
     * @return The number of loggers to run.
     */
    int Loggers() const { return loggers; }

    /**
     * @return The number of of proxies to run.
     */
    int Proxies() const { return proxies; }

    /**
     * @return The total number of workers running on this system.
     */
    int Workers() const {
        int result = 0;
        for ( const auto& iwc : interface_worker_configs )
            result += iwc.Workers();
        return result;
    }

    const std::vector<InterfaceWorkerConfig>& InterfaceWorkerConfigs() const { return interface_worker_configs; }

    /**
     * @return Colon separated string for the ZEEKPATH variable to use.
     */
    std::string ZeekPath() const;

    /**
     * @return The value of the args configuration.
     */
    const std::string& Args() const { return args; }
    const std::string& ManagerArgs() const { return manager_args; }
    const std::string& LoggerArgs() const { return logger_args; }
    const std::string& ProxyArgs() const { return proxy_args; }

    std::span<const EnvVar> Env() const { return std::span{env}; }
    std::span<const EnvVar> ManagerEnv() const { return std::span{manager_env}; }
    std::span<const EnvVar> LoggerEnv() const { return std::span{logger_env}; }
    std::span<const EnvVar> ProxyEnv() const { return std::span{proxy_env}; }
    std::span<const EnvVar> ArchiverEnv() const { return std::span{archiver_env}; }

    std::optional<CpuList> ManagerCpuSet() const { return manager_cpu_set; }
    std::optional<CpuList> LoggerCpuSet() const { return logger_cpu_set; }
    std::optional<CpuList> ProxyCpuSet() const { return proxy_cpu_set; }
    std::optional<CpuList> ArchiverCpuSet() const { return archiver_cpu_set; }

    std::optional<int> ManagerNice() const { return manager_nice; }
    std::optional<int> LoggerNice() const { return logger_nice; }
    std::optional<int> ProxyNice() const { return proxy_nice; }
    std::optional<int> ArchiverNice() const { return archiver_nice; }

    const std::optional<std::string>& ManagerMemoryMax() const { return manager_memory_max; }
    const std::optional<std::string>& LoggerMemoryMax() const { return logger_memory_max; }
    const std::optional<std::string>& ProxyMemoryMax() const { return proxy_memory_max; }
    const std::optional<std::string>& ArchiverMemoryMax() const { return archiver_memory_max; }

    /**
     * @return The value of the cluster backend arguments.
     */
    const std::string& ClusterBackendArgs() const { return cluster_backend_args; }

    /**
     * If cluster_node_prefix is set, return the given string prepended with the prefix and a dash, else return s.
     */
    std::string PrefixedClusterNode(const std::string& s) const {
        if ( cluster_node_prefix )
            return *cluster_node_prefix + "-" + s;

        return s;
    }

    /**
     * Computes the PATH to use from ext_path, base_dir / bin and path.
     *
     * @return Colon separated string for the PATH variable to use.
     */
    std::string Path() const;

    const std::string& User() const { return user; }
    const std::string& Group() const { return group; }

    int RestartIntervalSec() const { return restart_interval_sec; }

    /**
     * @return Whether to run zeek-archiver.
     */
    bool IsArchiverEnabled() const { return archiver_option != "0"; }

    /**
     * @return Additional argument for the zeek-archiver.
     */
    const std::string& ArchiverArgs() const { return archiver_args; }

    /**
     * Generates string to run for generating cluster-layout.zeek
     *
     * This produces either an invocation of the zeek-cluster-layout-generator
     * executable, or a command that copies the cluster_layout a specified
     * in the configuration file.
     */
    std::string ClusterLayoutCommand() const;

    const std::string& ClusterAddress() const { return cluster_address; }
    int ClusterPort() const { return cluster_port; }

    int MetricsPort() const { return metrics_port; };

    /**
     * Generate a command string for the zeek-archiver.
     *
     * If the archiver option is 1, uses <zeek_base_dir>/bin/zeek-archiver
     * and appends archiver_args and log queue and archive directories. Otherwise,
     * uses the option as executable and appends archiver_args only.
     */
    std::string ArchiverCommand() const;

private:
    friend ZeekClusterConfig parse_config(const std::filesystem::path&, const std::filesystem::path&);
    std::filesystem::path zeek_base_dir;
    std::filesystem::path source_path;
    bool exists = false;

    bool manager = true;
    int loggers = 1;
    int proxies = 1;

    std::string args;
    std::string manager_args;
    std::string logger_args;
    std::string proxy_args;

    std::vector<EnvVar> env;
    std::vector<EnvVar> manager_env;
    std::vector<EnvVar> logger_env;
    std::vector<EnvVar> proxy_env;

    std::optional<CpuList> manager_cpu_set;
    std::optional<CpuList> logger_cpu_set;
    std::optional<CpuList> proxy_cpu_set;

    std::string user = "zeek";
    std::string group = "zeek";

    std::string path = "/usr/local/bin:/usr/bin:/bin";
    std::string ext_path = "";

    std::string ext_zeek_path;

    int start_limit_interval_sec = 0;

    std::optional<int> manager_nice;
    std::optional<int> logger_nice;
    std::optional<int> proxy_nice;
    std::optional<int> worker_nice;
    std::optional<int> archiver_nice;

    std::optional<std::string> manager_memory_max;
    std::optional<std::string> logger_memory_max;
    std::optional<std::string> proxy_memory_max;
    std::optional<std::string> worker_memory_max;
    std::optional<std::string> archiver_memory_max;

    std::vector<InterfaceWorkerConfig> interface_worker_configs;

    std::string restart = "always";
    int restart_sec = 1;

    // Broker and ZeroMQ stuff
    std::string cluster_backend_args;

    int cluster_port = 27760;
    std::string cluster_address;

    // Metrics
    int metrics_port = 9991;

    int restart_interval_sec = 1;

    std::string archiver_option = "1"; // 1, 0 or path to a custom archiver command.
    std::string archiver_args;
    std::vector<EnvVar> archiver_env;
    std::optional<CpuList> archiver_cpu_set;

    std::filesystem::path cluster_layout_generator;

    // Manually specify the cluster-layout.zeek
    std::optional<std::filesystem::path> cluster_layout;

    // Prefix for CLUSTER_NODE
    std::optional<std::string> cluster_node_prefix;

    std::vector<std::string> errors;
};

ZeekClusterConfig parse_config(const std::filesystem::path& zeek_base_dir, const std::filesystem::path& source_path);

/**
 * Get the hostname via gethostname(), returning nullopt on error.
 */
std::optional<std::string> gethostname();
} // namespace zeek::detail
