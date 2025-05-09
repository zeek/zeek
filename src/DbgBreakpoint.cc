// See the file "COPYING" in the main distribution directory for copyright.

// Implementation of breakpoints.

#include "zeek/DbgBreakpoint.h"

#include <cassert>

#include "zeek/Debug.h"
#include "zeek/Desc.h"
#include "zeek/Frame.h"
#include "zeek/Func.h"
#include "zeek/ID.h"
#include "zeek/Reporter.h"
#include "zeek/Scope.h"
#include "zeek/Timer.h"
#include "zeek/Val.h"
#include "zeek/module_util.h"

namespace zeek::detail {

// BreakpointTimer used for time-based breakpoints
class BreakpointTimer final : public Timer {
public:
    BreakpointTimer(DbgBreakpoint* arg_bp, double arg_t) : Timer(arg_t, TIMER_BREAKPOINT) { bp = arg_bp; }

    void Dispatch(double t, bool is_expire) override;

protected:
    DbgBreakpoint* bp;
};

void BreakpointTimer::Dispatch(double t, bool is_expire) {
    if ( is_expire )
        return;

    bp->ShouldBreak(t);
}

DbgBreakpoint::DbgBreakpoint() {
    kind = BP_STMT;

    enabled = temporary = false;
    BPID = -1;

    at_stmt = nullptr;
    at_time = -1.0;

    repeat_count = hit_count = 0;

    description[0] = 0;
    source_filename = nullptr;
    source_line = 0;
}

DbgBreakpoint::~DbgBreakpoint() {
    SetEnable(false); // clean up any active state
    RemoveFromGlobalMap();
}

bool DbgBreakpoint::SetEnable(bool do_enable) {
    bool old_value = enabled;
    enabled = do_enable;

    // Update statement counts.
    if ( do_enable && ! old_value )
        AddToStmt();

    else if ( ! do_enable && old_value )
        RemoveFromStmt();

    return old_value;
}

void DbgBreakpoint::AddToGlobalMap() {
    // Make sure it's not there already.
    RemoveFromGlobalMap();

    g_debugger_state.breakpoint_map.insert(BPMapType::value_type(at_stmt, this));
}

void DbgBreakpoint::RemoveFromGlobalMap() {
    std::pair<BPMapType::iterator, BPMapType::iterator> p;
    p = g_debugger_state.breakpoint_map.equal_range(at_stmt);

    for ( BPMapType::iterator i = p.first; i != p.second; ) {
        if ( i->second == this ) {
            BPMapType::iterator next = i;
            ++next;
            g_debugger_state.breakpoint_map.erase(i);
            i = next;
        }
        else
            ++i;
    }
}

void DbgBreakpoint::AddToStmt() {
    if ( at_stmt )
        at_stmt->IncrBPCount();
}

void DbgBreakpoint::RemoveFromStmt() {
    if ( at_stmt )
        at_stmt->DecrBPCount();
}

bool DbgBreakpoint::SetLocation(ParseLocationRec plr, std::string_view loc_str) {
    if ( plr.type == PLR_UNKNOWN ) {
        debug_msg("Breakpoint specifier invalid or operation canceled.\n");
        return false;
    }

    if ( plr.type == PLR_FILE_AND_LINE ) {
        kind = BP_LINE;
        source_filename = plr.filename;
        source_line = plr.line;

        if ( ! plr.stmt ) {
            debug_msg("No statement at that line.\n");
            return false;
        }

        at_stmt = plr.stmt;
        snprintf(description, sizeof(description), "%s:%d", source_filename, source_line);

        debug_msg("Breakpoint %d set at %s\n", GetID(), Description());
    }

    else if ( plr.type == PLR_FUNCTION ) {
        std::string loc_s(loc_str);
        kind = BP_FUNC;
        function_name = make_full_var_name(current_module.c_str(), loc_s.c_str());
        at_stmt = plr.stmt;
        const Location* loc = at_stmt->GetLocationInfo();
        snprintf(description, sizeof(description), "%s at %s:%d", function_name.c_str(), loc->filename, loc->last_line);

        debug_msg("Breakpoint %d set at %s\n", GetID(), Description());
    }

    SetEnable(true);
    AddToGlobalMap();
    return true;
}

bool DbgBreakpoint::SetLocation(Stmt* stmt) {
    if ( ! stmt )
        return false;

    kind = BP_STMT;
    at_stmt = stmt;

    SetEnable(true);
    AddToGlobalMap();

    const Location* loc = stmt->GetLocationInfo();
    snprintf(description, sizeof(description), "%s:%d", loc->filename, loc->last_line);

    debug_msg("Breakpoint %d set at %s\n", GetID(), Description());

    return true;
}

bool DbgBreakpoint::SetLocation(double t) {
    debug_msg("SetLocation(time) has not been debugged.");
    return false;

    kind = BP_TIME;
    at_time = t;

    timer_mgr->Add(new BreakpointTimer(this, t));

    debug_msg("Time-based breakpoints not yet supported.\n");
    return false;
}

bool DbgBreakpoint::Reset() {
    ParseLocationRec plr;

    switch ( kind ) {
        case BP_TIME: debug_msg("Time-based breakpoints not yet supported.\n"); break;

        case BP_FUNC:
        case BP_STMT:
        case BP_LINE:
            plr.type = PLR_FUNCTION;
            // ### How to deal with wildcards?
            // ### perhaps save user choices?--tough...
            break;
    }

    reporter->InternalError("DbgBreakpoint::Reset function incomplete.");

    // Cannot be reached.
    return false;
}

bool DbgBreakpoint::SetCondition(const std::string& new_condition) {
    condition = new_condition;
    return true;
}

bool DbgBreakpoint::SetRepeatCount(int count) {
    repeat_count = count;
    return true;
}

BreakCode DbgBreakpoint::HasHit() {
    if ( temporary ) {
        SetEnable(false);
        return BC_HIT_AND_DELETE;
    }

    if ( condition.size() ) {
        // TODO: ### evaluate using debugger frame too
        auto yes = dbg_eval_expr(condition.c_str());

        if ( ! yes ) {
            debug_msg("Breakpoint condition '%s' invalid, removing condition.\n", condition.c_str());
            SetCondition("");
            PrintHitMsg();
            return BC_HIT;
        }

        if ( ! IsIntegral(yes->GetType()->Tag()) && ! IsBool(yes->GetType()->Tag()) ) {
            PrintHitMsg();
            debug_msg("Breakpoint condition should return an integral type");
            return BC_HIT_AND_DELETE;
        }

        yes->CoerceToInt();
        if ( yes->IsZero() ) {
            return BC_NO_HIT;
        }
    }

    int repcount = GetRepeatCount();
    if ( repcount ) {
        if ( ++hit_count == repcount ) {
            hit_count = 0;
            PrintHitMsg();
            return BC_HIT;
        }

        return BC_NO_HIT;
    }

    PrintHitMsg();
    return BC_HIT;
}

BreakCode DbgBreakpoint::ShouldBreak(Stmt* s) {
    if ( ! IsEnabled() )
        return BC_NO_HIT;

    switch ( kind ) {
        case BP_STMT:
        case BP_FUNC:
            if ( at_stmt != s )
                return BC_NO_HIT;
            break;

        case BP_LINE:
            assert(s->GetLocationInfo()->first_line <= source_line && s->GetLocationInfo()->last_line >= source_line);
            break;

        case BP_TIME: assert(false);

        default: reporter->InternalError("Invalid breakpoint type in DbgBreakpoint::ShouldBreak");
    }

    // If we got here, that means that the breakpoint could hit,
    // except potentially if it has a special condition or a repeat count.

    BreakCode code = HasHit();
    if ( code )
        g_debugger_state.BreakBeforeNextStmt(true);

    return code;
}

BreakCode DbgBreakpoint::ShouldBreak(double t) {
    if ( kind != BP_TIME )
        reporter->InternalError("Calling ShouldBreak(time) on a non-time breakpoint");

    if ( t < at_time )
        return BC_NO_HIT;

    if ( ! IsEnabled() )
        return BC_NO_HIT;

    BreakCode code = HasHit();
    if ( code )
        g_debugger_state.BreakBeforeNextStmt(true);

    return code;
}

void DbgBreakpoint::PrintHitMsg() {
    switch ( kind ) {
        case BP_STMT:
        case BP_FUNC:
        case BP_LINE: {
            ODesc d;
            Frame* f = g_frame_stack.back();
            const ScriptFunc* func = f->GetFunction();

            if ( func )
                func->DescribeDebug(&d, f->GetFuncArgs());

            const Location* loc = at_stmt->GetLocationInfo();

            debug_msg("Breakpoint %d, %s at %s:%d\n", GetID(), d.Description(), loc->filename, loc->first_line);
        }
            return;

        case BP_TIME: assert(false);

        default: reporter->InternalError("Missed a case in DbgBreakpoint::PrintHitMsg\n");
    }
}

} // namespace zeek::detail
