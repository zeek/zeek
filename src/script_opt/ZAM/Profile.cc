// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/ZAM/Profile.h"

#include <unordered_map>
#include <unordered_set>

#include "zeek/Obj.h"
#include "zeek/script_opt/ProfileFunc.h"
#include "zeek/script_opt/ZAM/ZBody.h"

namespace zeek::detail {

std::string ZAMLocInfo::Describe(bool include_lines) const {
    std::string desc;

    if ( blocks ) {
        desc = blocks->GetDesc(loc.get());
        if ( parent )
            desc = parent->Describe(false) + ";" + desc;
    }
    else {
        if ( parent ) {
            desc = parent->Describe();
            if ( func_name != parent->FuncName() )
                desc += ";" + func_name;
        }
        else
            desc = func_name;

        if ( include_lines ) {
            desc += ";" + func_name + ":" + std::to_string(loc->first_line);
            if ( loc->last_line > loc->first_line )
                desc += "-" + std::to_string(loc->last_line);
        }
    }

    return desc;
}

void profile_ZAM_execution(const std::vector<FuncInfo>& funcs) {
    report_ZOP_profile();

    for ( auto& f : funcs ) {
        if ( f.Body()->Tag() != STMT_ZAM )
            continue;

        auto zb = cast_intrusive<ZBody>(f.Body());
        zb->ProfileExecution();
    }
}

} // namespace zeek::detail
