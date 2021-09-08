// See the file "COPYING" in the main distribution directory for copyright.

// Low-level support utilities/globals for ZAM compilation.

#pragma once

#include "zeek/Expr.h"
#include "zeek/Stmt.h"

namespace zeek::detail {

using ValVec = std::vector<ValPtr>;

// The (reduced) statement currently being compiled.  Used for both
// tracking "use" and "reaching" definitions, and for error messages.
extern const Stmt* curr_stmt;

// True if a function with the given profile can be compiled to ZAM.
// If not, returns the reason in *reason, if non-nil.
class ProfileFunc;
extern bool is_ZAM_compilable(const ProfileFunc* pf,
                              const char** reason = nullptr);

// True if a given type is one that we treat internally as an "any" type.
extern bool IsAny(const Type* t);

// Convenience functions for getting to these.
inline bool IsAny(const TypePtr& t) { return IsAny(t.get()); }
inline bool IsAny(const Expr* e) { return IsAny(e->GetType()); }


// Needed for the logging built-in.  Exported so that ZAM can make sure it's
// defined when compiling.
extern TypePtr log_ID_enum_type;

// Needed for a slight performance gain when dealing with "any" types.
extern TypePtr any_base_type;

extern void ZAM_run_time_error(const char* msg);
extern void ZAM_run_time_error(const Location* loc, const char* msg);
extern void ZAM_run_time_error(const Location* loc, const char* msg,
                               const Obj* o);
extern void ZAM_run_time_error(const Stmt* stmt, const char* msg);
extern void ZAM_run_time_error(const char* msg, const Obj* o);

extern bool ZAM_error;

extern void ZAM_run_time_warning(const Location* loc, const char* msg);

extern StringVal* ZAM_to_lower(const StringVal* sv);
extern StringVal* ZAM_sub_bytes(const StringVal* s, bro_uint_t start, bro_int_t n);

} // namespace zeek::detail
