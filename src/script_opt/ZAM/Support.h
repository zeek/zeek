// See the file "COPYING" in the main distribution directory for copyright.

// Low-level support utilities/globals for ZAM compilation.
//
// Many of the wrapper functions are here to break header dependencies
// between ZBody.cc and the rest of Zeek. This avoids rebuilding of ZBody.cc
// when working on Zeek components unrelated to script optimization.
//

#pragma once

#include <memory>
#include <string>
#include <vector>

#include "zeek/IntrusivePtr.h"
#include "zeek/script_opt/ZAM/Profile.h"
#include "zeek/util-types.h"

namespace zeek {

class Connection;
class EnumVal;
class RecordVal;
class StringVal;
class Type;
class Val;

using ValPtr = IntrusivePtr<Val>;
using StringValPtr = IntrusivePtr<StringVal>;
using TypePtr = IntrusivePtr<Type>;

namespace plugin {
class Component;
}

namespace detail {

class Expr;
class Stmt;

using ValVec = std::vector<ValPtr>;

namespace ZAM {

// The name of the current function being compiled. For inlined functions,
// this is the name of the inlinee, not the inliner.
extern std::string curr_func;

// The location corresponding to the current statement being compiled.
extern std::shared_ptr<ZAMLocInfo> curr_loc;

// Needed for the logging built-in.  Exported so that ZAM can make sure it's
// defined when compiling.
extern TypePtr log_ID_enum_type;

// Needed for a slight performance gain when dealing with "any" types.
extern TypePtr any_base_type;

// log_mgr->Write()
bool log_mgr_write(EnumVal* v, RecordVal* r);

// broker_mgr->FlushLogBuffers()
size_t broker_mgr_flush_log_buffers();

// session_mgr->FindConnection()
zeek::Connection* session_mgr_find_connection(Val* cid);

// Analyzer-Name op
StringVal* analyzer_name(zeek::EnumVal* v);

// Used with Is-Protocol-Analyzer op
plugin::Component* analyzer_mgr_lookup(EnumVal* v);

// Conn size analyzer accessors for byte thresholds.
//
// Note: The underlying API uses a bool parameter to distinguish between
// packet and byte thresholds. For now, only need bytes and seems less
// obfuscated to use individual functions.
zeek_uint_t conn_size_get_bytes_threshold(Val* cid, bool is_orig);
bool conn_size_set_bytes_threshold(zeek_uint_t threshold, Val* cid, bool is_orig);


// File analysis facade.
void file_mgr_set_handle(StringVal* h);
bool file_mgr_add_analyzer(StringVal* file_id, EnumVal* tag, RecordVal* args);
bool file_mgr_remove_analyzer(StringVal* file_id, EnumVal* tag, RecordVal* args);
bool file_mgr_analyzer_enabled(EnumVal* v);
zeek::StringVal* file_mgr_analyzer_name(EnumVal* v);
bool file_mgr_enable_reassembly(StringVal* file_id);
bool file_mgr_disable_reassembly(StringVal* file_id);
bool file_mgr_set_reassembly_buffer(StringVal* file_id, uint64_t max);

} // namespace ZAM

// True if a function with the given profile can be compiled to ZAM.
// If not, returns the reason in *reason, if non-nil.
class ProfileFunc;
extern bool is_ZAM_compilable(const ProfileFunc* pf, const char** reason = nullptr);

// True if a given type is one that we treat internally as an "any" type.
extern bool IsAny(const Type* t);

// Convenience functions for getting to these.
inline bool IsAny(const TypePtr& t) { return IsAny(t.get()); }

// Run-time checking for "any" type being consistent with
// expected typed.  Returns true if the type match is okay.
extern bool CheckAnyType(const TypePtr& any_type, const TypePtr& expected_type, const std::shared_ptr<ZAMLocInfo>& loc);

extern void ZAM_run_time_error(const char* msg);
extern void ZAM_run_time_error(std::shared_ptr<ZAMLocInfo> loc, const char* msg);
extern void ZAM_run_time_error(std::shared_ptr<ZAMLocInfo> loc, const char* msg, const Obj* o);
extern void ZAM_run_time_error(const Stmt* stmt, const char* msg);
extern void ZAM_run_time_error(const char* msg, const Obj* o);

extern bool ZAM_error;

extern void ZAM_run_time_warning(std::shared_ptr<ZAMLocInfo> loc, const char* msg);

extern StringVal* ZAM_to_lower(const StringVal* sv);
extern StringVal* ZAM_sub_bytes(const StringVal* s, zeek_uint_t start, zeek_int_t n);

extern StringValPtr ZAM_val_cat(const ValPtr& v);

} // namespace detail
} // namespace zeek
