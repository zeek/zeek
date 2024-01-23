// See the file "COPYING" in the main distribution directory for copyright.

// Classes for profiling ZAM execution.

#pragma once

#include "zeek/script_opt/ScriptOpt.h"
#include "zeek/util.h"

namespace zeek::detail {

class ZAMLocInfo {
public:
    ZAMLocInfo(std::string _func_name, std::shared_ptr<Location> _loc)
        : func_name(std::move(_func_name)), loc(std::move(_loc)) {}

    const std::string& FuncName() const { return func_name; }
    const Location* Loc() const { return loc.get(); }
    std::shared_ptr<Location> LocPtr() const { return loc; }

    void AddParent(std::shared_ptr<ZAMLocInfo> _parent) { parent = std::move(_parent); }
    std::shared_ptr<ZAMLocInfo> Parent() { return parent; }

    std::string Describe(bool include_lines = false) const;

private:
    std::string func_name;
    std::shared_ptr<Location> loc;
    std::shared_ptr<ZAMLocInfo> parent;
};

class LocProfileElem {
public:
    LocProfileElem(std::shared_ptr<Location> _loc) : loc(std::move(_loc)) {}

    const auto& Loc() const { return loc; }

    zeek_uint_t Count() const { return count; }
    double CPU() const { return cpu; }

    void BumpCount() { ++count; }
    void BumpCPU(double new_cpu) { cpu += new_cpu; }

private:
    std::shared_ptr<Location> loc;
    zeek_uint_t count = 0;
    double cpu = 0.0;
};

class ProfileStack {
public:
    void PushCall(ScriptFuncPtr sf, CallExprPtr call);
};

// ###
extern void profile_ZAM_execution(const std::vector<FuncInfo>& funcs);
extern void report_ZOP_profile();

} // namespace zeek::detail
