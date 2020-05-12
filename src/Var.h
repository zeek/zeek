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

[[deprecated("Remove in v4.1.  Use zeek::lookup_val().")]]
extern Val* internal_val(const char* name);

[[deprecated("Remove in v4.1.  Use zeek::lookup_const().")]]
extern Val* internal_const_val(const char* name); // internal error if not const

[[deprecated("Remove in v4.1.  Use lookup_ID() or zeek::lookup_val().")]]
extern Val* opt_internal_val(const char* name);	// returns nil if not defined

extern double opt_internal_double(const char* name);
extern bro_int_t opt_internal_int(const char* name);
extern bro_uint_t opt_internal_unsigned(const char* name);
[[deprecated("Remove in v4.1.  Use lookup_ID() or zeek::lookup_val().")]]
extern StringVal* opt_internal_string(const char* name);
[[deprecated("Remove in v4.1.  Use lookup_ID() or zeek::lookup_val().")]]
extern TableVal* opt_internal_table(const char* name);	// nil if not defined

[[deprecated("Remove in v4.1.  Use lookup_ID(), zeek::lookup_val(), and/or TableVal::ToPureListVal().")]]
extern ListVal* internal_list_val(const char* name);

[[deprecated("Remove in v4.1.  Use zeek::lookup_type().")]]
extern BroType* internal_type(const char* name);

[[deprecated("Remove in v4.1.  Use zeek::lookup_func().")]]
extern Func* internal_func(const char* name);

extern EventHandlerPtr internal_handler(const char* name);

extern int signal_val;	// 0 if no signal pending

namespace zeek {

/**
 * Lookup an ID by its name and return its type.  A fatal occurs if the ID
 * does not exist.
 * @param name  The identifier name to lookup
 * @return  The type of the identifier.
 */
const IntrusivePtr<BroType>& lookup_type(const char* name);

/**
 * Lookup an ID by its name and return its type (as cast to @c T).
 * A fatal occurs if the ID does not exist.
 * @param name  The identifier name to lookup
 * @return  The type of the identifier.
 */
template<class T>
IntrusivePtr<T> lookup_type(const char* name)
	{ return cast_intrusive<T>(lookup_type(name)); }

/**
 * Lookup an ID by its name and return its value.  A fatal occurs if the ID
 * does not exist.
 * @param name  The identifier name to lookup
 * @return  The current value of the identifier
 */
const IntrusivePtr<Val>& lookup_val(const char* name);

/**
 * Lookup an ID by its name and return its value (as cast to @c T).
 * A fatal occurs if the ID does not exist.
 * @param name  The identifier name to lookup
 * @return  The current value of the identifier.
 */
template<class T>
IntrusivePtr<T> lookup_val(const char* name)
	{ return cast_intrusive<T>(lookup_val(name)); }

/**
 * Lookup an ID by its name and return its value.  A fatal occurs if the ID
 * does not exist or if it is not "const".
 * @param name  The identifier name to lookup
 * @return  The current value of the identifier
 */
const IntrusivePtr<Val>& lookup_const(const char* name);

/**
 * Lookup an ID by its name and return the function it references.
 * A fatal occurs if the ID does not exist or if it is not a function.
 * @param name  The identifier name to lookup
 * @return  The current function value the identifier references.
 */
IntrusivePtr<Func> lookup_func(const char* name);

} // namespace zeek
