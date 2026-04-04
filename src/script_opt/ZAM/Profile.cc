// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/ZAM/Profile.h"

#include "zeek/Obj.h"
#include "zeek/script_opt/ProfileFunc.h"

namespace zeek::detail {

ZAMLocInfo::ZAMLocInfo(std::string _func_name, std::shared_ptr<Location> _loc, std::shared_ptr<ZAMLocInfo> _parent)
    : loc(std::move(_loc)), parent(std::move(_parent)) {
    func_name = func_name_at_loc(std::move(_func_name), loc.get());

    auto main_module = func_name.find("::");
    if ( main_module != std::string::npos )
        modules.insert(func_name.substr(0, main_module));

    if ( parent ) {
        auto& m = parent->GetModules();
        modules.insert(m.begin(), m.end());
    }
}

std::string ZAMLocInfo::Describe(bool include_lines) const {
    std::string desc;

    if ( AST_blocks ) {
        desc = AST_blocks->GetDesc(loc.get());
        if ( parent )
            desc = parent->Describe(false) + ";" + desc;
    }
    else {
        if ( parent ) {
            desc = parent->Describe(false);
            if ( func_name != parent->FuncName() )
                desc += ";" + func_name;
        }
        else
            desc = func_name;

        if ( include_lines ) {
            desc += ";" + func_name + ":" + std::to_string(loc->FirstLine());
            if ( loc->LastLine() > loc->FirstLine() ) {
                desc.append("-");
                desc.append(std::to_string(loc->LastLine()));
            }
        }
    }

    return desc;
}

} // namespace zeek::detail
