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

Unit systemd_add_node_unit(const path& file, const std::string& description, const ZeekClusterConfig& config) {
    auto unit = Unit(file, description, config.SourcePath());
    unit.AddStopPropagatedFrom("zeek.target");
    unit.SetUser(config.User());
    unit.SetGroup(config.Group());
    unit.AddAfter("zeek-setup.service");
    unit.AddEnvironment("PATH", config.Path());
    unit.AddEnvironment("ZEEKPATH", config.ZeekPath());

    // Replaced for workers with SetExecStart() to add the interface.
    unit.AddExecStart(config.ZeekExe().string(),
                      {systemd_generator_policy_scripts(), config.Args(), config.ClusterBackendArgs()});

    unit.SetRestart("always");
    unit.SetRestartSec(config.RestartIntervalSec());

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
    auto target_unit = Unit(dir / "zeek.target", std::move(target_desc), config.SourcePath());

    // The setup unit creates all working directories and sets permissions
    auto setup_unit = Unit(dir / "zeek-setup.service", "Zeek Setup", config.SourcePath());
    setup_unit.SetPartOf("zeek.target");
    setup_unit.SetServiceType("oneshot");
    setup_unit.SetStartLimitIntervalSec("0");
    setup_unit.AddExecStart("mkdir -p " + config.GeneratedScriptsDir().string());
    setup_unit.AddExecStart(config.ClusterLayoutGeneratorCommand());
    setup_unit.AddExecStart("mkdir -p " + (config.LogArchiveDir()).string());
    setup_unit.AddExecStart("chown " + config.User() + ":" + config.Group() + " " + config.LogArchiveDir().string());
    setup_unit.AddExecStart("mkdir -p " + config.LogQueueDir().string());
    setup_unit.AddExecStart("chown " + config.User() + ":" + config.Group() + " " + config.LogQueueDir().string());
    setup_unit.SetRemainAfterExit(true);

    ensure_symlink("../zeek-setup.service", zeek_target_wants / "zeek-setup.service");

    // Manager
    setup_unit.AddExecStart(config.MakeWorkingDirectoryCommand("manager"));
    setup_unit.AddExecStart(config.ChownWorkingDirectoryCommand("manager"));
    ensure_symlink("../zeek-manager.service", zeek_target_wants / "zeek-manager.service");

    // Loggers
    for ( int idx = 1; idx <= config.Loggers(); idx++ ) {
        auto wdir = "logger-" + std::to_string(idx);
        setup_unit.AddExecStart(config.MakeWorkingDirectoryCommand(wdir));
        setup_unit.AddExecStart(config.ChownWorkingDirectoryCommand(wdir));
        auto name = systemd_unit_name("logger", idx);
        ensure_symlink("../zeek-logger@.service", zeek_target_wants / name);
    }

    // Proxies
    for ( int idx = 1; idx <= config.Proxies(); idx++ ) {
        auto wdir = "proxy-" + std::to_string(idx);
        setup_unit.AddExecStart(config.MakeWorkingDirectoryCommand(wdir));
        setup_unit.AddExecStart(config.ChownWorkingDirectoryCommand(wdir));

        auto name = systemd_unit_name("proxy", idx);
        ensure_symlink("../zeek-proxy@.service", zeek_target_wants / name);
    }

    // Manager Unit
    auto manager_unit = systemd_add_node_unit(dir / "zeek-manager.service", "Zeek Manager", config);
    manager_unit.AddEnvironment("CLUSTER_NODE", "manager");
    manager_unit.SetSyslogIdentifier("zeek-manager");
    manager_unit.SetWorkingDirectory(config.WorkingDirectory("manager"));
    manager_unit.AddReadWritePath(config.WorkingDirectory("manager"));
    manager_unit.AddAfter("zeek-logger@.service");
    manager_unit.SetSlice("zeek-manager.slice");
    manager_unit.SetMemoryMax(config.MemoryMaxFor("manager"));
    if ( auto nice = config.NiceFor("manager"); nice )
        manager_unit.SetNice(*nice);

    // Logger Template Unit
    auto logger_unit = systemd_add_node_unit(dir / "zeek-logger@.service", "Zeek Logger %i", config);
    logger_unit.AddEnvironment("CLUSTER_NODE", "logger-%i");
    logger_unit.SetSyslogIdentifier("zeek-logger-%i");
    logger_unit.SetWorkingDirectory(config.WorkingDirectory("logger-%i"));
    logger_unit.AddReadWritePath(config.WorkingDirectory("logger-%i"));
    // This makes <PREFIX>/var read-writeable for the logger
    // process such that it can move logs from its working directory
    // into <PREFIX>/var/logs/zeek. This currently means a logger
    // has read-write access to individual node spool directories.
    // We could also mark certain paths read-only if that's an issue.
    logger_unit.AddReadWritePath(config.ZeekBaseDir() / "var");
    logger_unit.SetSlice("zeek-loggers.slice");
    logger_unit.SetMemoryMax(config.MemoryMaxFor("logger"));
    if ( auto nice = config.NiceFor("logger"); nice )
        logger_unit.SetNice(*nice);

    // Proxy Template Unit
    auto proxy_unit = systemd_add_node_unit(dir / "zeek-proxy@.service", "Zeek Proxy %i", config);
    proxy_unit.AddEnvironment("CLUSTER_NODE", "proxy-%i");
    proxy_unit.SetSyslogIdentifier("zeek-proxy-%i");
    proxy_unit.SetWorkingDirectory(config.WorkingDirectory("proxy-%i"));
    proxy_unit.AddReadWritePath(config.WorkingDirectory("proxy-%i"));
    proxy_unit.AddAfter("zeek-logger@.service");
    proxy_unit.SetSlice("zeek-proxies.slice");
    proxy_unit.SetMemoryMax(config.MemoryMaxFor("proxy"));
    if ( auto nice = config.NiceFor("proxy"); nice )
        proxy_unit.SetNice(*nice);

    // Global worker index.
    int global_worker_index = 0;
    for ( const auto& iwc : config.InterfaceWorkerConfigs() ) {
        // For every interface section, there's a separate zeek-worker-{interface_tag}@.service
        // template unit created so that we can have per interface worker args and drop-in files
        // that affect all workers of a single interface. In a sectionless configuration, the tag
        // is empty and the name is reduced to zeek-worker@.service.
        std::string worker_cluster_node = "worker";
        std::string worker_unit_prefix = "zeek-worker";
        std::string worker_unit_description = "Zeek Worker %i";

        if ( ! iwc.Tag().empty() ) {
            worker_cluster_node = worker_cluster_node + "-" + iwc.Tag();
            worker_unit_prefix = worker_unit_prefix + "-" + iwc.Tag();
            worker_unit_description = worker_unit_description + " (" + iwc.Tag() + ")";
        }

        std::string worker_template_unit = worker_unit_prefix + "@.service";

        // Create a template unit for all workers of this interface.
        auto worker_interface_unit =
            systemd_add_node_unit(dir / worker_template_unit, std::move(worker_unit_description), config);

        worker_interface_unit.SetExecStart(config.ZeekExe().string(),
                                           {"-i", "${INTERFACE}", systemd_generator_policy_scripts(), config.Args(),
                                            iwc.Args(), config.ClusterBackendArgs()});
        worker_interface_unit.AddEnvironment("CLUSTER_NODE", worker_cluster_node + "-%i");
        worker_interface_unit.SetSyslogIdentifier(worker_unit_prefix + "-%i");
        worker_interface_unit.AddAfter(manager_unit.Name());
        worker_interface_unit.AddAfter(logger_unit.Name());
        worker_interface_unit.AddAfter(proxy_unit.Name());
        worker_interface_unit.SetAmbientCapabilities("CAP_NET_RAW");
        worker_interface_unit.SetCapabilityBoundingSet("CAP_NET_RAW");
        worker_interface_unit.SetSlice("zeek-workers.slice");
        worker_interface_unit.SetMemoryMax(iwc.WorkerMemoryMax());
        if ( auto nice = iwc.Nice(); nice )
            worker_interface_unit.SetNice(*nice);

        // Overwrite the working directory
        worker_interface_unit.SetWorkingDirectory(iwc.MakeWorkingDirectory(config.SpoolDir(), "%i"));
        worker_interface_unit.AddReadWritePath(iwc.MakeWorkingDirectory(config.SpoolDir(), "%i"));

        worker_interface_unit.Write();

        // The "local" index of a worker for templating. This resets for every interface,
        // while worker_index counts over all workers.
        for ( int index = 1; index <= iwc.Workers(); index++ ) {
            ++global_worker_index;

            setup_unit.AddExecStart(config.MakeWorkingDirectoryCommand(iwc.FullWorkerName(index)));
            setup_unit.AddExecStart(config.ChownWorkingDirectoryCommand(iwc.FullWorkerName(index)));

            auto name = worker_unit_prefix + "@" + std::to_string(index) + ".service";
            ensure_symlink("../" + worker_template_unit, zeek_target_wants / name);

            // Create drop-in .d directories for worker instance to define their
            // INTERFACE and CPUAffinity settings.
            auto d_dir = dir / (name + ".d");
            std::filesystem::create_directories(d_dir);
            auto unit = Unit(d_dir / "10-zeek-systemd-generator.conf", config.SourcePath());

            // Setup templating variables for the interface.
            std::map<std::string, std::string> vars = {
                {"worker_index", std::to_string(index)},
                {"worker_index0", std::to_string(index - 1)},
                {"global_worker_index", std::to_string(global_worker_index)},
                {"global_worker_index0", std::to_string(global_worker_index - 1)},
            };

            std::string cpu = iwc.AffinityFor(global_worker_index);
            if ( ! cpu.empty() )
                vars["worker_cpu"] = cpu;

            if ( ! iwc.Tag().empty() )
                vars["interface_tag"] = iwc.Tag();

            auto interface = config.SubstituteVars(iwc.Interface(), vars);
            if ( ! interface.has_value() ) {
                std::fprintf(stderr, "interface substitution for '%s' failed\n", iwc.Interface().c_str());
                std::exit(1);
            }

            unit.AddEnvironment("INTERFACE", *interface);

            if ( ! cpu.empty() )
                unit.SetCpuAffinity(std::move(cpu));

            if ( auto numa_policy = iwc.NumaPolicy(); numa_policy )
                unit.SetNumaPolicy(std::move(*numa_policy));

            // Write out all worker_env settings as Environment
            for ( const auto& env : iwc.Envs() ) {
                auto value = config.SubstituteVars(env.second, vars);
                if ( ! value ) {
                    std::fprintf(stderr, "worker_env substitution for '%s' failed of '%s'\n", env.second.c_str(),
                                 env.first.c_str());
                    std::exit(1);
                }
                unit.AddEnvironment(env.first, std::move(*value));
            }

            unit.WriteDropIn();
        }
    }

    target_unit.Write();
    setup_unit.Write();
    manager_unit.Write();
    logger_unit.Write();
    proxy_unit.Write();

    // Optional archiver service.
    if ( config.IsArchiverEnabled() ) {
        auto archiver_unit = Unit(dir / "zeek-archiver.service", "Zeek Archiver", config.SourcePath());
        archiver_unit.SetPartOf("zeek.target");
        archiver_unit.SetStartLimitIntervalSec("0");
        archiver_unit.SetExecStart(config.ArchiverCommand());
        archiver_unit.SetUser(config.User());
        archiver_unit.SetGroup(config.Group());
        archiver_unit.AddAfter("zeek-setup.service");
        // zeek-archiver copies files from the log queue dir to the
        // archive dir, so restrict its access.
        archiver_unit.AddReadWritePath(config.LogQueueDir());
        archiver_unit.AddReadWritePath(config.LogArchiveDir());

        archiver_unit.SetRestart("always");
        archiver_unit.SetRestartSec(config.RestartIntervalSec());

        archiver_unit.SetSlice("zeek-archiver.slice");

        archiver_unit.Write();

        ensure_symlink("../zeek-archiver.service", zeek_target_wants / "zeek-archiver.service");
    }
}


} // namespace

int main(int argc, const char* argv[]) {
    ZeekClusterConfig::RunUnitTests();

    const char* program = argv[0]; // We fiddle with argv later on, keep the program name around.
    bool explicit_config = false;  // Did the user provide --config ?

    // Injected via -D during compilation, usually <PREFIX>/etc/zeek/zeek.conf
    std::string config_file = DEFAULT_CONFIG_FILE;

    // Allow overriding the configuration file lookup with --config for testing.
    if ( argc >= 3 && std::string_view(argv[1]) == "--config" ) {
        config_file = std::filesystem::weakly_canonical(argv[2]);
        explicit_config = true;

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


    auto config = zeek::detail::parse_config(DEFAULT_BASE_DIR, config_file);
    if ( ! config.Exists() ) {
        if ( explicit_config ) {
            std::fprintf(stderr, "config %s does not exist\n", config_file.c_str());
            return 1;
        }

        return 0;
    }

    if ( ! config.IsValid() ) {
        std::fprintf(stderr, "config %s is invalid\n", config_file.c_str());
        for ( const auto& error : config.Errors() )
            fprintf(stderr, "%s\n", error.c_str());

        return 1;
    }

    if ( config.IsEnabled() )
        systemd_write_units(normal_dir, config);

    return 0;
}
