// See the file "COPYING" in the main distribution directory for copyright.

//
// A systemd unit file generator for Zeek.
//
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <initializer_list>
#include <map>
#include <optional>
#include <string>
#include <system_error>
#include <vector>

#include "systemd-unit.h"
#include "zeek-cluster-config.h"

namespace {

using path = std::filesystem::path;
using Unit = zeek::detail::systemd::Unit;
using ZeekClusterConfig = zeek::detail::ZeekClusterConfig;

/**
 * Returns policy scripts that come before zeek_args.
 */
std::string systemd_generator_policy_scripts() {
    // Is this worth it?
    return "policy/misc/systemd-generator";
}

/**
 * Construct zeek-{name}@{idx}.service.
 */
std::string systemd_unit_name(const std::string& name, int idx = 0) {
    std::string result = "zeek-";
    result += name;
    if ( idx > 0 ) {
        result += "@";
        result += std::to_string(idx);
    }
    return result + ".service";
}

/**
 * Put a new symlink at \a new_link to \a to.
 *
 * If \a to exists, this function attempts to unlink the file
 * and create another symlink.
 */
void ensure_symlink(const path& to, const path& new_link) {
    std::error_code ec;
    std::filesystem::create_symlink(to, new_link, ec);
    if ( ec.value() == EEXIST ) {
        std::filesystem::remove(new_link);
        std::filesystem::create_symlink(to, new_link);
    }
}

Unit systemd_add_node_unit(const path& file, const std::string& node, const std::string& description,
                           const ZeekClusterConfig& config) {
    auto unit = Unit(file, description, config.SourcePath(), "zeek.target");
    unit.SetUser(config.User());
    unit.SetGroup(config.Group());
    unit.AddRequires("zeek-setup.service");
    unit.AddAfter("zeek-setup.service");
    unit.AddEnvironment("PATH", config.Path());
    unit.AddEnvironment("ZEEKPATH", config.ZeekPath());
    unit.AddEnvironment("CLUSTER_NODE", node);

    // Loggers add all of the var directory, too.
    unit.AddReadWritePath(config.SpoolDir() / node);
    unit.SetWorkingDirectory(config.SpoolDir() / node);

    // Replaced for workers with SetExecStart() to add the interface.
    unit.AddExecStart(config.ZeekExe().string(),
                      {systemd_generator_policy_scripts(), config.Args(), config.ClusterBackendArgs()});

    unit.SetRestart("always");
    unit.SetRestartSec(config.RestartIntervalSec());

    unit.SetNice(config.NiceFor(node));
    unit.SetMemoryMax(config.MemoryMaxFor(node));

    // Disable any start limit.
    unit.SetStartLimitIntervalSec("0");

    return unit;
}

/**
 * Write all unit files for the give \a config into \a dir.
 *
 * @param dir The directory to place unit files into.
 * @param config The cluster configuration to use.
 */
void systemd_write_units(const path& dir, const ZeekClusterConfig& config) {
    // zeek_target_wants is where all generated units will be linked into
    // so that systemctl start zeek.target works out.
    std::error_code ec;

    auto zeek_target_wants = dir / "zeek.target.wants";
    if ( std::filesystem::create_directory(zeek_target_wants, ec); ec ) {
        std::fprintf(stderr, "failed to create directory %s: %s\n", zeek_target_wants.string().c_str(),
                     ec.message().c_str());
        std::exit(1);
    }

    std::string target_desc = "The Zeek Network Security Monitor";
    auto target_unit = Unit(dir / "zeek.target", target_desc, config.SourcePath());

    // The setup unit creates all working directories and sets permissions
    auto setup_unit = Unit(dir / "zeek-setup.service", "Zeek Setup", config.SourcePath(), "zeek.target");

    setup_unit.SetServiceType("oneshot");
    setup_unit.SetStartLimitIntervalSec("0");
    setup_unit.AddExecStart("mkdir -p " + config.GeneratedScriptsDir().string());
    setup_unit.AddExecStart(config.ClusterLayoutGeneratorCommand());

    setup_unit.AddExecStart("mkdir -p " + (config.LogArchiveDir() / "logs").string());
    setup_unit.AddExecStart("chown " + config.User() + ":" + config.Group() + " " + config.LogArchiveDir().string());
    setup_unit.AddExecStart("mkdir -p " + config.LogQueueDir().string());
    setup_unit.AddExecStart("chown " + config.User() + ":" + config.Group() + " " + config.LogQueueDir().string());
    setup_unit.SetRemainAfterExit(true);

    // Manager
    setup_unit.AddExecStart(config.MakeWorkingDirectoryCommand("manager"));
    setup_unit.AddExecStart(config.ChownWorkingDirectoryCommand("manager"));
    ensure_symlink("../zeek-manager.service", zeek_target_wants / "zeek-manager.service");

    // Loggers
    for ( int idx = 1; idx <= config.Loggers(); idx++ ) {
        setup_unit.AddExecStart(config.MakeWorkingDirectoryCommand("logger", idx));
        setup_unit.AddExecStart(config.ChownWorkingDirectoryCommand("logger", idx));
        auto name = systemd_unit_name("logger", idx);
        ensure_symlink("../zeek-logger@.service", zeek_target_wants / name);
    }

    // Proxies
    for ( int idx = 1; idx <= config.Proxies(); idx++ ) {
        setup_unit.AddExecStart(config.MakeWorkingDirectoryCommand("proxy", idx));
        setup_unit.AddExecStart(config.ChownWorkingDirectoryCommand("proxy", idx));

        auto name = systemd_unit_name("proxy", idx);
        ensure_symlink("../zeek-proxy@.service", zeek_target_wants / name);
    }

    // Workers
    for ( int idx = 1; idx <= config.Workers(); idx++ ) {
        setup_unit.AddExecStart(config.MakeWorkingDirectoryCommand("worker", idx));
        setup_unit.AddExecStart(config.ChownWorkingDirectoryCommand("worker", idx));

        auto name = systemd_unit_name("worker", idx);
        ensure_symlink("../zeek-worker@.service", zeek_target_wants / name);

        // Create drop-in .d directories for worker instance to define their
        // INTERFACE and CPUAffinity settings.
        auto d_dir = dir / (name + ".d");
        std::filesystem::create_directories(d_dir);
        auto unit = Unit(d_dir / "10-zeek-systemd-generator.conf", config.SourcePath());


        std::string cpu = config.WorkersCpuList().AffinityFor(idx);

        // Setup templating variables.
        std::map<std::string, std::string> vars = {
            {"worker_index", std::to_string(idx)},
            {"worker_index0", std::to_string(idx - 1)},
            {"worker_name", "worker-" + std::to_string(idx)},
            {"worker_cpu", cpu},
        };

        auto interface = config.SubstituteVars(config.Interface(), vars);
        if ( ! interface.has_value() ) {
            std::fprintf(stderr, "interface substitution for '%s' failed\n", config.Interface().c_str());
            std::exit(1);
        }

        unit.AddEnvironment("INTERFACE", *interface);
        if ( ! cpu.empty() )
            unit.SetCpuAffinity(cpu);

        unit.WriteDropIn();
    }

    auto manager_unit = systemd_add_node_unit(dir / "zeek-manager.service", "manager", "Zeek Manager", config);
    manager_unit.AddAfter("zeek-logger@.service");
    manager_unit.SetSlice("zeek.slice");

    auto logger_unit = systemd_add_node_unit(dir / "zeek-logger@.service", "logger-%i", "Zeek Logger %i", config);
    // This makes <PREFIX>/var read-writeable for the logger
    // process such that it can move logs from its working directory
    // into <PREFIX>/var/logs/zeek. This currently means a logger
    // has read-write access to individual node spool directories.
    // We could also mark certain paths read-only if that's an issue.
    logger_unit.AddReadWritePath(config.ZeekBaseDir() / "var");
    logger_unit.SetSlice("zeek-loggers.slice");

    auto proxy_unit = systemd_add_node_unit(dir / "zeek-proxy@.service", "proxy-%i", "Zeek Proxy %i", config);
    proxy_unit.AddAfter("zeek-logger@.service");
    proxy_unit.SetSlice("zeek-proxies.slice");

    auto worker_unit = systemd_add_node_unit(dir / "zeek-worker@.service", "worker-%i", "Zeek Worker %i", config);

    worker_unit.SetExecStart(config.ZeekExe().string(), {"-i", "${INTERFACE}", systemd_generator_policy_scripts(),
                                                         config.Args(), config.ClusterBackendArgs()});
    worker_unit.AddAfter(manager_unit.Name());
    worker_unit.AddAfter(logger_unit.Name());
    worker_unit.AddAfter(proxy_unit.Name());
    worker_unit.SetAmbientCapabilities("CAP_NET_RAW");
    worker_unit.SetCapabilityBoundingSet("CAP_NET_RAW");
    worker_unit.SetSlice("zeek-workers.slice");

    if ( auto numa_policy = config.WorkersNumaPolicy(); ! numa_policy.empty() )
        worker_unit.SetNumaPolicy(numa_policy);

    target_unit.Write();
    setup_unit.Write();
    manager_unit.Write();
    logger_unit.Write();
    proxy_unit.Write();
    worker_unit.Write();

    if ( config.IsArchiverEnabled() ) {
        auto archiver_unit = Unit(dir / "zeek-archiver.service", "Zeek Archiver", config.SourcePath(), "zeek.target");
        archiver_unit.SetStartLimitIntervalSec("0");
        archiver_unit.SetExecStart(config.ArchiverCommand());
        archiver_unit.SetUser(config.User());
        archiver_unit.SetGroup(config.Group());
        archiver_unit.AddRequires("zeek-setup.service");
        archiver_unit.AddAfter("zeek-setup.service");
        // zeek-archiver copies files from the log queue dir to the
        // archive dir, so restrict its access.
        archiver_unit.AddReadWritePath(config.LogQueueDir());
        archiver_unit.AddReadWritePath(config.LogArchiveDir());

        archiver_unit.SetRestart("always");
        archiver_unit.SetRestartSec(config.RestartIntervalSec());

        archiver_unit.Write();

        ensure_symlink("../zeek-archiver.service", zeek_target_wants / "zeek-archiver.service");
    }
}


} // namespace

int main(int argc, const char* argv[]) {
    ZeekClusterConfig::RunUnitTests();

    const char* program = argv[0]; // We fiddle with argv later on, keep the program name around.
    bool explicit_config = false;  // Did the user provide --config ?

    // Default configuration files to attempt to load.
    std::vector<std::filesystem::path> config_files = {
        DEFAULT_CONFIG_FILE,   // Injected via -D during compilation, usually <PREFIX>/etc/zeek/zeek.conf
        "/etc/zeek/zeek.conf", // Fallback
    };

    // Allow overriding the configuration file lookup with --config for testing.
    if ( argc >= 3 && std::string_view(argv[1]) == "--config" ) {
        auto config = std::filesystem::weakly_canonical(argv[2]);

        config_files = {config};

        argc -= 2;
        argv = &argv[2];
    }

    std::string_view normal_dir;
    if ( argc == 2 || argc == 4 ) {
        normal_dir = argv[1];
    }
    else {
        std::fprintf(stderr, "Usage: %s [--config test-config] normal-dir [early-dir] [late-dir]\n", program);
        std::exit(1);
    }


    // Find the first existing configuration file.
    for ( const auto& config_file : config_files ) {
        // The xZEEK_BASE_DIR comes from cmake via -D but can be overridden
        // in the configuration file.
        auto config = zeek::detail::parse_config(DEFAULT_BASE_DIR, config_file);
        if ( ! config.Exists() )
            continue;

        if ( ! config.IsValid() )
            return 1;

        if ( config.IsEnabled() )
            systemd_write_units(normal_dir, config);

        return 0;
    }

    // If an explicit config was given and we get here, treat it as an error, otherwise probably a disabled config.
    return explicit_config ? 1 : 0;
}
