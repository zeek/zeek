// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "IntrusivePtr.h"
#include "ID.h"
#include "Type.h"

class Expr;
class FuncType;
class Stmt;
class Scope;
class EventHandlerPtr;
class StringVal;
class TableVal;
class ListVal;

typedef enum { VAR_REGULAR, VAR_CONST, VAR_REDEF, VAR_OPTION, } decl_type;

extern void add_global(ID* id, IntrusivePtr<BroType> t, init_class c,
                       IntrusivePtr<Expr> init, attr_list* attr, decl_type dt);

extern IntrusivePtr<Stmt> add_local(IntrusivePtr<ID> id,
                                    IntrusivePtr<BroType> t, init_class c,
                                    IntrusivePtr<Expr> init, attr_list* attr,
                                    decl_type dt);

extern IntrusivePtr<Expr> add_and_assign_local(IntrusivePtr<ID> id,
                                               IntrusivePtr<Expr> init,
                                               IntrusivePtr<Val> val = nullptr);

extern void add_type(ID* id, IntrusivePtr<BroType> t, attr_list* attr);

extern void begin_func(ID* id, const char* module_name, function_flavor flavor,
                       bool is_redef, IntrusivePtr<FuncType> t,
                       attr_list* attrs = nullptr);

extern void end_func(IntrusivePtr<Stmt> body);

// Gather all IDs referenced inside a body that aren't part of a given scope.
extern id_list gather_outer_ids(Scope* scope, Stmt* body);

[[deprecated("Remove in v4.1.  Use zeek::id::lookup_val().")]]
extern Val* internal_val(const char* name);

[[deprecated("Remove in v4.1.  Use zeek::id::lookup_const().")]]
extern Val* internal_const_val(const char* name); // internal error if not const

[[deprecated("Remove in v4.1.  Use zeek::id::lookup() or zeek::id::lookup_val().")]]
extern Val* opt_internal_val(const char* name);	// returns nil if not defined

extern double opt_internal_double(const char* name);
extern bro_int_t opt_internal_int(const char* name);
extern bro_uint_t opt_internal_unsigned(const char* name);
[[deprecated("Remove in v4.1.  Use zeek::id::lookup() or zeek::id::lookup_val().")]]
extern StringVal* opt_internal_string(const char* name);
[[deprecated("Remove in v4.1.  Use zeek::id::lookup() or zeek::id::lookup_val().")]]
extern TableVal* opt_internal_table(const char* name);	// nil if not defined

[[deprecated("Remove in v4.1.  Use zeek::id::lookup(), zeek::id::lookup_val(), and/or TableVal::ToPureListVal().")]]
extern ListVal* internal_list_val(const char* name);

[[deprecated("Remove in v4.1.  Use zeek::id::lookup_type().")]]
extern BroType* internal_type(const char* name);

[[deprecated("Remove in v4.1.  Use zeek::id::lookup_func().")]]
extern Func* internal_func(const char* name);

extern EventHandlerPtr internal_handler(const char* name);

extern int signal_val;	// 0 if no signal pending
