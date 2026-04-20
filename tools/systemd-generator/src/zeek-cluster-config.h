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
#include <string>
#include <vector>

namespace zeek::detail {

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
    std::string AffinityFor(unsigned int index) const {
        if ( index == 0 ) {
            std::fprintf(stderr, "index starts at 1\n");
            abort();
        }

        if ( cpus.empty() )
            return "";

        return std::to_string(cpus[(index - 1) % cpus.size()]);
    }

    bool IsValid() { return is_valid; }

    /**
     * Access to the parsed CPUs.
     */
    const std::vector<int>& Indices() const { return cpus; }

private:
    bool is_valid = true;
    std::vector<int> cpus;
};

/**
 * A single option.
 */
struct Option {
    std::string key;
    std::string value;
    std::string orig; // The line from which key and value were extracted.
};

/**
 * Hold info about an interface worker configuration.
 *
 * Essentially, this describes how many workers listen on a specific interface (which can be specified as template).
 */
class InterfaceWorkerConfig {
public:
    /**
     * Instantiate a new interface worker config.
     *
     * @param index One-based index of this interface config in the configuration file.
     * @param interface The interface string from the configuration.
     */
    InterfaceWorkerConfig(int index, std::string interface) : interface(std::move(interface)) {}

    /**
     * Instantiate a InterfaceWorkerConfig from a span of options.
     *
     * For backwards compat, this has a bit of special behavior.
     *
     * 1) The first option in options is expected to be an "interface".
     * 2) It uses options up until the next "interface" Option in options
     * 3) It errors on non worker option keys unless allow_non_worker_keys is true.
     *    This is used for the first interface by the parser to continue support
     *    single interface entries followed by non-worker options to allow the original
     *    zeek.conf layout.
     *
     * @param index One-based index of the interface config.
     * @param options The options to parse from
     * @param allow_non_worker_keys If false, will return nullopt when encountering non worker options.
     *
     * @return An instantiated InterfaceWorkerConfig or or std::nullopt on error.
     */
    static std::optional<InterfaceWorkerConfig> from_options(int index, std::span<const Option> options,
                                                             bool allow_non_worker_keys = false);

    const std::string& Interface() const noexcept { return interface; }

    int Workers() const noexcept { return workers; }

    const std::string& MemoryMax() const noexcept { return memory_max; }

    std::optional<int> Nice() const noexcept { return nice; }

    std::string AffinityFor(unsigned int index) const { return cpu_list.AffinityFor(index); }

    std::optional<const std::string> NumaPolicy() const { return numa_policy; }

private:
    int index = 0;
    std::string interface;
    int workers = 1;

    std::optional<int> nice;
    std::string memory_max;
    CpuList cpu_list;
    std::optional<std::string> numa_policy;
};

/**
 * A Zeek cluster configuration for a single node.
 */
class ZeekClusterConfig {
public:
    ZeekClusterConfig(std::filesystem::path base_dir, std::filesystem::path source_path)
        : zeek_base_dir(std::move(base_dir)), source_path(std::move(source_path)) {}

    const std::filesystem::path& SourcePath() const noexcept { return source_path; }

    void SetExists() noexcept { exists = true; }

    bool Exists() const noexcept { return exists; }

    bool IsValid() const noexcept { return errors.empty(); }

    bool IsEnabled() const noexcept { return ! interface_worker_configs.empty(); }

    void Error(std::string msg) { errors.emplace_back(std::move(msg)); }

    const std::filesystem::path& ZeekBaseDir() const { return zeek_base_dir; }

    std::filesystem::path ZeekExe() const { return zeek_base_dir / "bin" / "zeek"; }

    std::filesystem::path BinDir() const { return ZeekBaseDir() / "bin"; };

    std::filesystem::path SpoolDir() const { return ZeekBaseDir() / "var" / "spool" / "zeek"; }

    /**
     * @return Where the zeek-archiver process archives logs into.
     */
    std::filesystem::path LogArchiveDir() const { return ZeekBaseDir() / "var" / "logs" / "zeek"; }

    std::filesystem::path GeneratedScriptsDir() const { return SpoolDir() / "generated-scripts"; }

    std::filesystem::path WorkingDirectory(const std::string& type, std::optional<unsigned int> index = {}) const {
        if ( index == 0 ) {
            std::fprintf(stderr, "index starts at 1\n");
            abort();
        }
        return SpoolDir() / (type + (index.has_value() ? ("-" + std::to_string(*index)) : ""));
    }

    /**
     * @return the mkdir command for the process's working directory.
     */
    std::string MakeWorkingDirectoryCommand(const std::string& type, std::optional<unsigned int> index = {}) const {
        return "mkdir -p " + WorkingDirectory(type, index).string();
    }

    /**
     * @return the chown command for the process's working directory.
     */
    std::string ChownWorkingDirectoryCommand(const std::string& type, std::optional<unsigned int> index = {}) const {
        return "chown " + User() + ":" + Group() + " " + WorkingDirectory(type, index).string();
    }

    /**
     * @return Where logger processes rotate their log files into and zeek-archiver picks them up.
     */
    std::filesystem::path LogQueueDir() const { return SpoolDir() / "log-queue"; }

    /**
     * @return The number of loggers to run.
     */
    int Loggers() const noexcept { return loggers; }

    /**
     * @return The number of of proxies to run.
     */
    int Proxies() const noexcept { return proxies; }

    /**
     * @return The total number of workers running on this system.
     */
    int Workers() const noexcept {
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

    std::optional<int> NiceFor(const std::string& node) const;

    const std::string& MemoryMaxFor(const std::string& node) const;

    /**
     * @return The value of the args configuration.
     */
    const std::string& Args() const { return args; }

    /**
     * @return The value of the cluster backend arguments.
     */
    const std::string& ClusterBackendArgs() const { return cluster_backend_args; }

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
    bool IsArchiverEnabled() const { return enable_archiver; }

    /**
     * @return Additional argument for the zeek-archiver.
     */
    const std::string& ArchiverArgs() const { return archiver_args; }

    /**
     * Generates string to run for generating cluster-layout.zeek
     */
    std::string ClusterLayoutGeneratorCommand() const;

    /**
     * Generate a command string for the zeek-archiver.
     */
    std::string ArchiverCommand() const;

    /**
     * @return A new string with with all occurrences of ${var} in \a s replaced with values from \a vars.
     */
    static std::optional<std::string> SubstituteVars(const std::string& s,
                                                     const std::map<std::string, std::string>& vars);

    static void RunUnitTests();

private:
    friend ZeekClusterConfig parse_config(const std::filesystem::path&, const std::filesystem::path&);
    std::filesystem::path zeek_base_dir;
    std::filesystem::path source_path;
    bool exists = false;

    int loggers = 1;
    int proxies = 1;

    std::string args;

    std::string user = "zeek";
    std::string group = "zeek";

    std::string path = "/usr/local/bin:/usr/bin:/bin";
    std::string ext_path = "";

    std::string ext_zeek_path;

    int start_limit_interval_sec = 0;

    std::optional<int> nice_manager;
    std::optional<int> nice_logger;
    std::optional<int> nice_proxy;
    std::optional<int> nice_worker;

    std::string memory_max_manager;
    std::string memory_max_logger;
    std::string memory_max_proxy;
    std::string memory_max_worker;

    std::vector<InterfaceWorkerConfig> interface_worker_configs;

    std::string restart = "always";
    int restart_sec = 1;

    // Broker and ZeroMQ stuff
    std::string cluster_backend_args;

    int port = 27760;
    std::string address = "127.0.0.1";

    // Metrics
    int metrics_port = 9991;
    std::string metrics_address = "127.0.0.1";

    int restart_interval_sec = 1;

    bool enable_archiver = true;
    std::string archiver_args;

    std::filesystem::path cluster_layout_generator;

    std::vector<std::string> errors;
};

ZeekClusterConfig parse_config(const std::filesystem::path& zeek_base_dir, const std::filesystem::path& source_path);
} // namespace zeek::detail
