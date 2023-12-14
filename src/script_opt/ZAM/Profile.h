// See the file "COPYING" in the main distribution directory for copyright.

// Classes for profiling ZAM execution.

#pragma once

#include "zeek/script_opt/ScriptOpt.h"
#include "zeek/util.h"

namespace zeek::detail {

class ProfileElem {
public:
    ProfileElem(int _line, int _count = 0, double _cpu = 0.0)
        : first_line(_line), last_line(_line), count(_count), cpu(_cpu) {}

    int FirstLine() const { return first_line; }
    int LastLine() const { return last_line; }
    zeek_uint_t Count() const { return count; }
    double CPU() const { return cpu; }

    void BumpCount() { ++count; }
    void BumpCPU(double new_cpu) { cpu += new_cpu; }

    void MergeIn(const ProfileElem* pe) {
        first_line = std::min(first_line, pe->FirstLine());
        last_line = std::max(last_line, pe->LastLine());
        count += pe->count;
        cpu += pe->cpu;
    }

    void ExpandLastLine(int new_last_line) {
        ASSERT(last_line <= new_last_line);
        last_line = new_last_line;
    }

private:
    int first_line, last_line;
    zeek_uint_t count;
    double cpu;
};

class LocProfileElem : public ProfileElem {
public:
    LocProfileElem(std::shared_ptr<Location> _loc) : ProfileElem(_loc->first_line), loc(_loc) {}

    const auto& Loc() const { return loc; }

private:
    std::shared_ptr<Location> loc;
};

// ###
extern void profile_ZAM_execution(const std::vector<FuncInfo>& funcs);
extern void report_ZOP_profile();

} // namespace zeek::detail
