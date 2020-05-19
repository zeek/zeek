// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "IntrusivePtr.h"
#include "ID.h"
#include "Type.h"

class FuncType;
class Scope;
class EventHandlerPtr;
class StringVal;
class TableVal;
class ListVal;

FORWARD_DECLARE_NAMESPACED(Stmt, zeek::detail);
FORWARD_DECLARE_NAMESPACED(Expr, zeek::detail);

typedef enum { VAR_REGULAR, VAR_CONST, VAR_REDEF, VAR_OPTION, } decl_type;

extern void add_global(const IntrusivePtr<zeek::detail::ID>& id,
                       IntrusivePtr<BroType> t,
                       zeek::detail::init_class c,
                       IntrusivePtr<zeek::detail::Expr> init,
                       std::unique_ptr<std::vector<IntrusivePtr<zeek::detail::Attr>>> attr,
                       decl_type dt);

extern IntrusivePtr<zeek::detail::Stmt> add_local(IntrusivePtr<zeek::detail::ID> id,
                                                  IntrusivePtr<BroType> t,
                                                  zeek::detail::init_class c,
                                                  IntrusivePtr<zeek::detail::Expr> init,
                                                  std::unique_ptr<std::vector<IntrusivePtr<zeek::detail::Attr>>> attr,
                                                  decl_type dt);

extern IntrusivePtr<zeek::detail::Expr> add_and_assign_local(IntrusivePtr<zeek::detail::ID> id,
                                               IntrusivePtr<zeek::detail::Expr> init,
                                               IntrusivePtr<Val> val = nullptr);

extern void add_type(zeek::detail::ID* id, IntrusivePtr<BroType> t,
                     std::unique_ptr<std::vector<IntrusivePtr<zeek::detail::Attr>>> attr);

extern void begin_func(IntrusivePtr<zeek::detail::ID> id, const char* module_name,
                       function_flavor flavor, bool is_redef,
                       IntrusivePtr<FuncType> t,
                       std::unique_ptr<std::vector<IntrusivePtr<zeek::detail::Attr>>> attrs = nullptr);

extern void end_func(IntrusivePtr<zeek::detail::Stmt> body);

// Gather all IDs referenced inside a body that aren't part of a given scope.
extern id_list gather_outer_ids(Scope* scope, zeek::detail::Stmt* body);

[[deprecated("Remove in v4.1.  Use zeek::id::find_val().")]]
extern Val* internal_val(const char* name);

[[deprecated("Remove in v4.1.  Use zeek::id::find_const().")]]
extern Val* internal_const_val(const char* name); // internal error if not const

[[deprecated("Remove in v4.1.  Use zeek::id::find() or zeek::id::find_val().")]]
extern Val* opt_internal_val(const char* name);	// returns nil if not defined

[[deprecated("Remove in v4.1.  Use zeek::id::find() or zeek::id::find_val().")]]
extern double opt_internal_double(const char* name);

[[deprecated("Remove in v4.1.  Use zeek::id::find() or zeek::id::find_val().")]]
extern bro_int_t opt_internal_int(const char* name);

[[deprecated("Remove in v4.1.  Use zeek::id::find() or zeek::id::find_val().")]]
extern bro_uint_t opt_internal_unsigned(const char* name);

[[deprecated("Remove in v4.1.  Use zeek::id::find() or zeek::id::find_val().")]]
extern StringVal* opt_internal_string(const char* name);

[[deprecated("Remove in v4.1.  Use zeek::id::find() or zeek::id::find_val().")]]
extern TableVal* opt_internal_table(const char* name);	// nil if not defined

[[deprecated("Remove in v4.1.  Use zeek::id::find(), zeek::id::find_val(), and/or TableVal::ToPureListVal().")]]
extern ListVal* internal_list_val(const char* name);

[[deprecated("Remove in v4.1.  Use zeek::id::find_type().")]]
extern BroType* internal_type(const char* name);

[[deprecated("Remove in v4.1.  Use zeek::id::find_func().")]]
extern Func* internal_func(const char* name);

[[deprecated("Remove in v4.1.  Use event_registry->Register().")]]
extern EventHandlerPtr internal_handler(const char* name);
