// See the file "COPYING" in the main distribution directory for copyright.
#include "systemd-unit.h"

#include <cerrno>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

namespace zeek::detail::systemd {

Unit::Unit(std::filesystem::path file, std::string description, std::filesystem::path source_path,
           std::optional<std::string> part_of)
    : file(std::move(file)),
      description(std::move(description)),
      source_path(std::move(source_path)),
      part_of(std::move(part_of)) {}


std::string Unit::ToString() const {
    std::stringstream ss;
    ss << "# Auto-generated, do not edit. Use drop-in files instead!";
    ss << "\n";
    ss << "[Unit]\n";
    ss << "Description=" << description << "\n";
    ss << "SourcePath=" << source_path << "\n";

    for ( const auto& a : after )
        ss << "After=" << a << "\n";
    for ( const auto& r : requires_ )
        ss << "Requires=" << r << "\n";

    if ( part_of.has_value() )
        ss << "PartOf=" << *part_of << "\n";

    if ( start_limit_interval_sec.has_value() )
        ss << "StartLimitIntervalSec=" << start_limit_interval_sec.value() << "\n";

    if ( start_limit_burst.has_value() )
        ss << "StartLimitBurst=" << start_limit_burst.value() << "\n";

    // Make the [Service] section depending on availability of ExecStar or
    // ExecStartPre for now.
    if ( exec_start.size() > 0 || exec_start_pre.size() > 0 ) {
        ss << "\n";
        ss << "[Service]" << "\n";
        ss << "Type=" << service_type << "\n";
        ss << "Nice=" << nice << "\n";
        ss << "MemoryMax=" << memory_max << "\n";
        ss << "User=" << user << "\n";
        ss << "Group=" << group << "\n";
        ss << "WorkingDirectory=" << working_directory.string() << "\n";

        if ( ! read_write_paths.empty() ) {
            ss << "ReadWritePaths=";
            for ( const auto& rw : read_write_paths ) {
                ss << rw.string() << " ";
            }
            ss << "\n";
        }

        if ( cpu_affinity.has_value() )
            ss << "CPUAffinity=" << *cpu_affinity << "\n";

        if ( capability_bounding_set.has_value() )
            ss << "CapabilityBoundingSet=" << capability_bounding_set.value() << "\n";

        if ( ambient_capabilities.has_value() )
            ss << "AmbientCapabilities=" << ambient_capabilities.value() << "\n";

        if ( cpu_affinity.has_value() )
            ss << "CPUAffinity=" + cpu_affinity.value() << "\n";

        if ( numa_policy.has_value() )
            ss << "NUMAPolicy=" + numa_policy.value() << "\n";

        for ( const auto& [name, value] : env )
            ss << "Environment=" << name << "=" << value << "\n";

        for ( const auto& cmd : exec_start_pre )
            ss << "ExecStartPre=" << cmd << "\n";

        for ( const auto& cmd : exec_start )
            ss << "ExecStart=" << cmd << "\n";

        if ( remain_after_exit )
            ss << "RemainAfterExit=yes" << "\n";

        if ( slice.has_value() )
            ss << "Slice=" << slice.value() << "\n";

        if ( restart.has_value() ) {
            ss << "Restart=" << restart.value() << "\n";
            ss << "RestartSec=" << restart_sec.value() << "\n";
        }
    }

    if ( ! wanted_by.empty() ) {
        ss << "\n";
        ss << "[Install]" << "\n";
        for ( const auto& wb : wanted_by )
            ss << "WantedBy=" << wb << "\n";
    }

    return ss.str();
}
bool Unit::Write() const {
    if ( std::ofstream ofs(file, std::ios::trunc); ofs ) {
        ofs << ToString();
        return true;
    }

    return false;
}

bool Unit::WriteDropIn() const {
    if ( std::ofstream ofs(file, std::ios::trunc); ofs ) {
        ofs << "[Unit]" << "\n";
        ofs << "SourcePath=" << source_path << "\n";
        ofs << "\n";
        ofs << "[Service]" << "\n";

        if ( cpu_affinity.has_value() )
            ofs << "CPUAffinity=" << *cpu_affinity << "\n";

        for ( const auto& [name, value] : env )
            ofs << "Environment=" << name << "=" << value << "\n";
    }

    return false;
}
} // namespace zeek::detail::systemd
