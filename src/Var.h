// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "IntrusivePtr.h"
#include "ID.h"
#include "Type.h"

class EventHandlerPtr;

ZEEK_FORWARD_DECLARE_NAMESPACED(StringVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(TableVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(ListVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(FuncType, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(Stmt, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(Expr, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(Scope, zeek::detail);

namespace zeek::detail {
using StmtPtr = zeek::IntrusivePtr<zeek::detail::Stmt>;
}

typedef enum { VAR_REGULAR, VAR_CONST, VAR_REDEF, VAR_OPTION, } decl_type;

extern void add_global(const zeek::detail::IDPtr& id,
                       zeek::TypePtr t,
                       zeek::detail::InitClass c,
                       zeek::detail::ExprPtr init,
                       std::unique_ptr<std::vector<zeek::detail::AttrPtr>> attr,
                       decl_type dt);

extern zeek::detail::StmtPtr add_local(
	zeek::detail::IDPtr id,
	zeek::TypePtr t,
	zeek::detail::InitClass c,
	zeek::detail::ExprPtr init,
	std::unique_ptr<std::vector<zeek::detail::AttrPtr>> attr,
	decl_type dt);

extern zeek::detail::ExprPtr add_and_assign_local(
	zeek::detail::IDPtr id,
	zeek::detail::ExprPtr init,
	zeek::ValPtr val = nullptr);

extern void add_type(zeek::detail::ID* id, zeek::TypePtr t,
                     std::unique_ptr<std::vector<zeek::detail::AttrPtr>> attr);

extern void begin_func(zeek::detail::IDPtr id, const char* module_name,
                       zeek::FunctionFlavor flavor, bool is_redef,
                       zeek::FuncTypePtr t,
                       std::unique_ptr<std::vector<zeek::detail::AttrPtr>> attrs = nullptr);

extern void end_func(zeek::detail::StmtPtr body);

// Gather all IDs referenced inside a body that aren't part of a given scope.
extern id_list gather_outer_ids(zeek::detail::Scope* scope, zeek::detail::Stmt* body);

[[deprecated("Remove in v4.1.  Use zeek::id::find_val().")]]
extern zeek::Val* internal_val(const char* name);

[[deprecated("Remove in v4.1.  Use zeek::id::find_const().")]]
extern zeek::Val* internal_const_val(const char* name); // internal error if not const

[[deprecated("Remove in v4.1.  Use zeek::id::find() or zeek::id::find_val().")]]
extern zeek::Val* opt_internal_val(const char* name);	// returns nil if not defined

[[deprecated("Remove in v4.1.  Use zeek::id::find() or zeek::id::find_val().")]]
extern double opt_internal_double(const char* name);

[[deprecated("Remove in v4.1.  Use zeek::id::find() or zeek::id::find_val().")]]
extern bro_int_t opt_internal_int(const char* name);

[[deprecated("Remove in v4.1.  Use zeek::id::find() or zeek::id::find_val().")]]
extern bro_uint_t opt_internal_unsigned(const char* name);

[[deprecated("Remove in v4.1.  Use zeek::id::find() or zeek::id::find_val().")]]
extern zeek::StringVal* opt_internal_string(const char* name);

[[deprecated("Remove in v4.1.  Use zeek::id::find() or zeek::id::find_val().")]]
extern zeek::TableVal* opt_internal_table(const char* name);	// nil if not defined

[[deprecated("Remove in v4.1.  Use zeek::id::find(), zeek::id::find_val(), and/or TableVal::ToPureListVal().")]]
extern zeek::ListVal* internal_list_val(const char* name);

[[deprecated("Remove in v4.1.  Use zeek::id::find_type().")]]
extern zeek::Type* internal_type(const char* name);

[[deprecated("Remove in v4.1.  Use zeek::id::find_func().")]]
extern Func* internal_func(const char* name);

[[deprecated("Remove in v4.1.  Use event_registry->Register().")]]
extern EventHandlerPtr internal_handler(const char* name);
