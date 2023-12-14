// See the file "COPYING" in the main distribution directory for copyright.

// Classes for profiling ZAM execution.

#pragma once

#include "zeek/script_opt/ScriptOpt.h"
#include "zeek/util.h"

namespace zeek::detail {

class ProfileElem {
public:
    ProfileElem(int _line) : first_line(_line), last_line(_line) {}

    int FirstLine() const { return first_line; }
    int LastLine() const { return last_line; }

    zeek_uint_t Count() const { return count; }
    double CPU() const { return cpu; }
    double CallCPU() const { return call_cpu; }
    bool IsCall() const { return is_call; }

    void MergeIn(const ProfileElem* pe) {
        first_line = std::min(first_line, pe->FirstLine());
        last_line = std::max(last_line, pe->LastLine());
        count += pe->count;
        cpu += pe->cpu;
        call_cpu += pe->call_cpu;
    }

    void ExpandLastLine(int new_last_line) {
        ASSERT(last_line <= new_last_line);
        last_line = new_last_line;
    }

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
    LocProfileElem(std::shared_ptr<Location> _loc, bool _is_call) : ProfileElem(_loc->first_line), loc(_loc) { is_call = _is_call; }

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
