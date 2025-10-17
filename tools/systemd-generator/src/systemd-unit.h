// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

//
// Hand-rolled systemd unit file rendering.
//
#include <filesystem>
#include <initializer_list>
#include <optional>
#include <vector>

namespace zeek::detail::systemd {

class Unit {
public:
    /**
     * Constructor.
     */
    Unit(std::filesystem::path file, std::string description, std::filesystem::path source_path,
         std::optional<std::string> part_of = {});

    /**
     * Constructor for drop in units.
     */
    Unit(std::filesystem::path file, std::filesystem::path source_path)
        : Unit(std::move(file), "", std::move(source_path)) {}

    /**
     * The last part of the Unit.
     *
     * TODO: If this is a drop-in file, it should be the parent's directory
     *       name with the .d stripped from the name.
     */
    std::string Name() { return file.filename().string(); }

    /**
     * Render the unit as a string that can be written to a unit file.
     */
    std::string ToString() const;

    void AddAfter(std::string a) { after.emplace_back(std::move(a)); }

    void AddRequires(std::string r) { requires_.emplace_back(std::move(r)); }

    void AddExecStart(const std::string& cmd, std::initializer_list<std::string> args = {}) {
        std::string add;
        for ( const auto& a : args ) {
            add += " ";
            add += a;
        }

        exec_start.emplace_back(cmd + add);
    }

    /**
     * Replace the existing ExecStart lines with the given one.
     */
    void SetExecStart(const std::string& cmd, std::initializer_list<std::string> args = {}) {
        exec_start.clear();
        AddExecStart(cmd, args);
    }

    void SetUser(std::string u) { user = std::move(u); };
    void SetGroup(std::string g) { group = std::move(g); };
    void SetSlice(std::string s) { slice = std::move(s); }
    void SetRemainAfterExit(bool v) { remain_after_exit = v; }

    void SetServiceType(std::string st) { service_type = std::move(st); }
    void AddWantedBy(std::string wb) { wanted_by.emplace_back(std::move(wb)); }

    void SetCapabilityBoundingSet(std::string caps) { capability_bounding_set = std::move(caps); }

    void SetAmbientCapabilities(std::string caps) { ambient_capabilities = std::move(caps); }
    void SetCpuAffinity(std::string cpu) { cpu_affinity = cpu; }
    void SetNumaPolicy(std::string np) { numa_policy = np; }

    void SetNice(int n) { nice = n; }
    void SetMemoryMax(std::string max) { memory_max = max; }

    void AddEnvironment(std::string name, std::string value) { env.emplace_back(std::move(name), std::move(value)); }

    void SetWorkingDirectory(std::filesystem::path wd) { working_directory = std::move(wd); }

    void AddReadWritePath(std::filesystem::path rw) { read_write_paths.emplace_back(std::move(rw)); }

    void SetStartLimitIntervalSec(std::string s) { start_limit_interval_sec = std::move(s); }
    void SetStartLimitBurst(std::string b) { start_limit_burst = std::move(b); }
    void SetRestart(std::string r) { restart = std::move(r); }
    void SetRestartSec(int sec) { restart_sec = sec; }

    /**
     * Write this unit file to the file provided in the constructor.
     */
    bool Write() const;

    /**
     * Writes just Environment and CPUAffinity fields.
     *
     * Subject to change at any time.
     */
    bool WriteDropIn() const;

private:
    std::filesystem::path file;

    // [Unit]
    std::string description;
    std::vector<std::string> after;
    std::vector<std::string> requires_;
    std::filesystem::path source_path;
    std::optional<std::string> part_of;

    // [Service]
    std::string service_type = "exec";
    std::string user;
    std::string group;
    std::optional<std::string> cpu_affinity;
    std::optional<std::string> numa_policy;

    std::vector<std::filesystem::path> read_write_paths;
    std::filesystem::path working_directory;

    std::string memory_max;
    int nice = 0;

    std::optional<std::string> capability_bounding_set;
    std::optional<std::string> ambient_capabilities;

    bool remain_after_exit = false;

    std::vector<std::pair<std::string, std::string>> env;
    std::vector<std::string> exec_start_pre;
    std::vector<std::string> exec_start;

    std::optional<std::string> slice;

    std::optional<std::string> start_limit_interval_sec;
    std::optional<std::string> start_limit_burst;
    std::optional<std::string> restart;
    std::optional<int> restart_sec = 1;

    // [Install]
    std::vector<std::string> wanted_by;
};
}; // namespace zeek::detail::systemd
