// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <list>
#include <map>
#include <string>
#include <utility>

#include "zeek/ID.h"
#include "zeek/StmtBase.h"

namespace zeek::detail {

using ObjPtr = IntrusivePtr<Obj>;

/**
 * A class for managing stats of Zeek script coverage across Zeek runs.
 */
class ScriptCoverageManager {
public:
    ScriptCoverageManager();

    /**
     * Returns true if the manager is active (will do work), false if not.
     *
     * @return: true if active, false if not.
     */
    bool IsActive() const { return pf != nullptr; }

    /**
     * Imports Zeek script Stmt usage information from file pointed to by
     * environment variable ZEEK_PROFILER_FILE.
     *
     * @return: true if usage info was read, otherwise false.
     */
    bool ReadStats();

    /**
     * Combines usage stats from current run with any read from ReadStats(),
     * then writes information to file pointed to by environment variable
     * ZEEK_PROFILER_FILE.  If the value of that env. variable ends with
     * ".XXXXXX" (exactly 6 X's), then it is first passed through mkstemp
     * to get a unique file.
     *
     * @return: true when usage info is written, otherwise false.
     */
    bool WriteStats();

    void SetDelim(char d) { delim = d; }

    void IncIgnoreDepth() { ignoring++; }
    void DecIgnoreDepth() { ignoring--; }

    void AddStmt(Stmt* s);
    void AddFunction(IDPtr func_id, StmtPtr body);
    void AddConditional(Location cond_loc, std::string_view text, bool was_true);

private:
    /**
     * The name of the profile file, or nil if we're not profiling.
     */
    const char* pf;

    /**
     * The current, global ScriptCoverageManager instance creates this list at parse-time.
     */
    std::list<StmtPtr> stmts;

    /**
     * A similar list for tracking functions and their bodies.
     */
    std::list<std::pair<IDPtr, StmtPtr>> func_instances;

    /**
     * Helper struct for tracking the result of @-directives.
     */
    struct Conditional {
        Location loc;
        std::string text;
        bool result;
    };

    /**
     * A similar list for tracking conditionals and whether they were true.
     */
    std::list<Conditional> cond_instances;

    /**
     * Indicates whether new statements will not be considered as part of
     * coverage statistics because it was marked with the @no-test tag.
     */
    uint32_t ignoring = 0;

    /**
     * The character to use to delimit ScriptCoverageManager output files.  Default is '\t'.
     */
    char delim = '\t';

    /**
     * This maps Stmt location-desc pairs to the total number of times that
     * Stmt has been executed.  The map can be initialized from a file at
     * startup time and modified at shutdown time before writing back
     * to a file.
     */
    std::map<std::pair<std::string, std::string>, uint64_t> usage_map;

    /**
     * A canonicalization routine for Stmt descriptions containing characters
     * that don't agree with the output format of ScriptCoverageManager.
     */
    struct canonicalize_desc {
        char delim;

        void operator()(char& c) {
            if ( c == '\n' )
                c = ' ';
            if ( c == delim )
                c = ' ';
        }
    };

    /**
     * Tracks the usage of a given object with a given description
     * and a given coverage count.
     */
    void TrackUsage(const ObjPtr& obj, std::string desc, uint64_t cnt) {
        TrackUsage(obj->GetLocationInfo(), std::move(desc), cnt);
    }
    void TrackUsage(const Location* loc, std::string desc, uint64_t cnt);

    /**
     * Reports a single coverage instance.
     */
    void Report(FILE* f, uint64_t cnt, std::string loc, std::string desc);
};

extern ScriptCoverageManager script_coverage_mgr;

} // namespace zeek::detail
