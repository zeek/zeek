// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/ZAM/Profile.h"

#include <unordered_map>
#include <unordered_set>

#include "zeek/Obj.h"
#include "zeek/script_opt/ProfileFunc.h"
#include "zeek/script_opt/ZAM/ZBody.h"

namespace zeek::detail {

class FileProfInfo {
public:
    FileProfInfo(std::string _filename, const ProfileElem* pe) : filename(std::move(_filename)) { AddProfileElem(pe); }

    void AddProfileElem(const ProfileElem* pe) {
        base_profs.push_back(pe);
        max_line = std::max(max_line, pe->LastLine());
    }

    void AddBasicBlock(const Location* bb);

    void CompileProfileElems();
    void CompileBasicBlocks();

private:
    std::shared_ptr<ProfileElem> UpdateBBProfile(const Location* bb);

    std::string filename;

    std::vector<const ProfileElem*> base_profs;
    std::unordered_set<const Location*> bbs;

    std::vector<std::shared_ptr<ProfileElem>> line_profs;

    int max_line = 0;
};

void FileProfInfo::AddBasicBlock(const Location* bb) {
    max_line = std::max(max_line, bb->last_line);
    bbs.insert(bb);
}

void FileProfInfo::CompileProfileElems() {
    line_profs.resize(max_line + 1);

    for ( auto p : base_profs ) {
        auto line = p->FirstLine();
        if ( line_profs[line] )
            line_profs[line]->MergeIn(p);
        else
            line_profs[line] = std::make_shared<ProfileElem>(*p);
    }
}

void FileProfInfo::CompileBasicBlocks() {
    // Ordered by size of the block, so it's easy to find overlaps.
    std::vector<const Location*> ordered_bbs;

    for ( auto bb : bbs ) {
        for ( auto i = bb->first_line; i <= bb->last_line; ++i )
            if ( line_profs[i] ) {
                // It's relevant, we have data for it.
                ordered_bbs.push_back(bb);
                break;
            }
    }

    std::sort(ordered_bbs.begin(), ordered_bbs.end(), [](const Location* l1, const Location* l2) {
        return l1->last_line - l1->first_line < l2->last_line - l2->first_line;
    });

    for ( auto bb : ordered_bbs ) {
        auto prof = UpdateBBProfile(bb);
        if ( ! prof )
            continue;

        int first_line = prof->FirstLine();
        int last_line = prof->LastLine();

        printf("%s:%d", filename.c_str(), first_line);
        if ( first_line < last_line )
            printf("-%d", last_line);

        auto cpu = prof->CPU();
        auto call_cpu = prof->CallCPU();

        printf(" %" PRId64 " %.06f %.06f\n", prof->Count(), cpu - call_cpu, call_cpu);
    }
}

std::shared_ptr<ProfileElem> FileProfInfo::UpdateBBProfile(const Location* bb) {
    auto bb_first = bb->first_line;
    auto bb_last = bb->last_line;
    auto& lp1 = line_profs[bb_first];

    if ( lp1 ) {
        ASSERT(lp1->LastLine() <= bb_last);
        if ( bb_first != bb_last && lp1->FirstLine() == bb_first && lp1->LastLine() == bb_last )
            // A consolidated block that we've already reported.
            return nullptr;
    }
    else
        lp1 = std::make_shared<ProfileElem>(bb_first);

    int num_merged = 0;
    for ( int i = bb_first + 1; i <= bb_last; ++i ) {
        auto& lp_i = line_profs[i];
        if ( lp_i ) {
            ++num_merged;
            lp1->MergeIn(lp_i.get());
            // Skip past what's already accounted for in this profile.
            i = lp1->LastLine();

            // Don't reuse this profile in the future.
            lp_i = nullptr;
        }
    }

    if ( lp1->Count() == 0 )
        // This can happen when script-level basic blocks overlap (due to
        // inaccurate location-tracking) and the one processed earlier
        // has subsumed all the profiling lines needed by the latter..
        return nullptr;

    lp1->ExpandLastLine(bb_last);

    if ( num_merged == 1 )
        // This is not a consolidation but just an expansion of the range.
        return nullptr;

    return lp1;
}

void profile_ZAM_execution(const std::vector<FuncInfo>& funcs) {
    report_ZOP_profile();

    // Collect all of the profiles (and do initial reporting on them).
    std::unordered_map<std::string, std::shared_ptr<FileProfInfo>> file_profs;

    for ( auto& f : funcs ) {
        if ( f.Body()->Tag() != STMT_ZAM )
            continue;

        auto zb = cast_intrusive<ZBody>(f.Body());
        zb->ProfileExecution();

        for ( auto& pe : zb->ExecProfile() ) {
            if ( pe.Count() == 0 )
                continue;

            auto loc = pe.Loc();
            auto fp = file_profs.find(loc->filename);
            if ( fp == file_profs.end() )
                file_profs[loc->filename] = std::make_shared<FileProfInfo>(loc->filename, &pe);
            else
                fp->second->AddProfileElem(&pe);
        }
    }

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
}

} // namespace zeek::detail
