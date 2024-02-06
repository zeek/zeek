// See the file "COPYING" in the main distribution directory for copyright.

// Classes for profiling ZAM execution.

#pragma once

#include "zeek/script_opt/ProfileFunc.h"
#include "zeek/util.h"

namespace zeek::detail {

class ZAMLocInfo {
public:
    ZAMLocInfo(std::string _func_name, std::shared_ptr<Location> _loc, std::shared_ptr<ZAMLocInfo> _parent);

    const std::string& FuncName() const { return func_name; }
    const Location* Loc() const { return loc.get(); }
    std::shared_ptr<Location> LocPtr() const { return loc; }

    std::shared_ptr<ZAMLocInfo> Parent() { return parent; }
    void AddInModules(std::set<std::string>& target) const { target.insert(modules.begin(), modules.end()); }

    std::string Describe(bool include_lines = false) const;

private:
    std::string func_name;
    std::set<std::string> modules;
    std::shared_ptr<Location> loc;
    std::shared_ptr<ZAMLocInfo> parent;
};

// ###
extern void report_ZOP_profile();

} // namespace zeek::detail
