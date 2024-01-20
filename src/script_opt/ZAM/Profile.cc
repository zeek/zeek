// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/ZAM/Profile.h"

#include <unordered_map>
#include <unordered_set>

#include "zeek/Obj.h"
#include "zeek/script_opt/ProfileFunc.h"
#include "zeek/script_opt/ZAM/ZBody.h"

namespace zeek::detail {

void profile_ZAM_execution(const std::vector<FuncInfo>& funcs) {
    report_ZOP_profile();

#if 0
    // Collect all of the profiles (and do initial reporting on them).
    std::unordered_map<std::string, std::shared_ptr<FileProfInfo>> file_profs;
#endif

    for ( auto& f : funcs ) {
        if ( f.Body()->Tag() != STMT_ZAM )
            continue;

        auto zb = cast_intrusive<ZBody>(f.Body());
        zb->ProfileExecution();

        for ( auto& pe : zb->ExecProfile() ) {
            if ( pe.Count() == 0 )
                continue;

            auto loc = pe.Loc();
#if 0
            auto fp = file_profs.find(loc->filename);
            if ( fp == file_profs.end() )
                file_profs[loc->filename] = std::make_shared<FileProfInfo>(loc->filename, &pe);
            else
                fp->second->AddProfileElem(&pe);
#endif
        }
    }

#if 0
    for ( auto& bb : basic_blocks->BasicBlocks() ) {
        auto& loc = bb.second;
        auto fp = file_profs.find(loc.filename);
        if ( fp != file_profs.end() )
            fp->second->AddBasicBlock(&loc);
    }

    for ( auto& fp : file_profs )
        fp.second->CompileProfileElems();

    for ( auto& fp : file_profs )
        fp.second->CompileBasicBlocks();
#endif
}

} // namespace zeek::detail
