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

    std::string Describe(bool include_lines = false) const {
        std::string desc;

        if ( parent ) {
            desc = parent->Describe();
            if ( func_name != parent->FuncName() )
                desc += ";" + func_name;
        }
        else
            desc = func_name;

        if ( include_lines ) {
            desc += ":" + std::to_string(loc->first_line);
            if ( loc->last_line > loc->first_line )
                desc += "-" + std::to_string(loc->last_line);
        }

        return desc;
    }

private:
    std::string func_name;
    std::shared_ptr<Location> loc;
    std::shared_ptr<ZAMLocInfo> parent;
};

class ProfileElem {
public:
    ProfileElem(int _line) : first_line(_line), last_line(_line) {}

    int FirstLine() const { return first_line; }
    int LastLine() const { return last_line; }

    zeek_uint_t Count() const { return count; }
    double CPU() const { return cpu; }
    double CallCPU() const { return call_cpu; }
    bool IsCall() const { return is_call; }

protected:
    bool is_call = false;
    zeek_uint_t count = 0;
    double cpu = 0.0;
    double call_cpu = 0.0;

private:
    int first_line, last_line;
};

class LocProfileElem : public ProfileElem {
public:
    LocProfileElem(std::shared_ptr<Location> _loc, bool _is_call) : ProfileElem(_loc->first_line), loc(_loc) {
        is_call = _is_call;
    }

    const auto& Loc() const { return loc; }

    void BumpCount() { ++count; }
    void BumpCPU(double new_cpu) {
        cpu += new_cpu;
        if ( is_call )
            call_cpu += new_cpu;
    }

private:
    std::shared_ptr<Location> loc;
};

// ###
extern void profile_ZAM_execution(const std::vector<FuncInfo>& funcs);
extern void report_ZOP_profile();

} // namespace zeek::detail
