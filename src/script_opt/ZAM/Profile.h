// See the file "COPYING" in the main distribution directory for copyright.

// Classes for profiling ZAM execution.

#pragma once

#include <memory>
#include <set>
#include <string>

namespace zeek::detail {

class Location;

class ZAMLocInfo {
public:
    // A generalization of the notion of "Location" that includes associating
    // with the location a function name, a static parent (i.e., one we can
    // determine at compile time, reflecting an outer block or inlining), and
    // a group of modules. It's a group of modules rather than a single one
    // because of event handler coalescence.
    ZAMLocInfo(std::string _func_name, std::shared_ptr<Location> _loc, std::shared_ptr<ZAMLocInfo> _parent);

    const std::string& FuncName() const { return func_name; }
    const Location* Loc() const { return loc.get(); }
    std::shared_ptr<Location> LocPtr() const { return loc; }
    std::shared_ptr<ZAMLocInfo> Parent() { return parent; }
    const auto& GetModules() const { return modules; }

    // If include_lines is true, then in the description we include line
    // number information, otherwise we omit them.
    std::string Describe(bool include_lines) const;

private:
    std::string func_name;
    std::set<std::string> modules;
    std::shared_ptr<Location> loc;
    std::shared_ptr<ZAMLocInfo> parent;
};

// Computes the approximate overhead of ZAM CPU and memory profiling.
extern void estimate_ZAM_profiling_overhead();

// Reports a profile of the different ZAM operations (instructions)
// that executed.
extern void report_ZOP_profile();

} // namespace zeek::detail
