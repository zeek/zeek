// See the file "COPYING" in the main distribution directory for copyright.

#ifndef var_h
#define var_h

#include "ID.h"
#include "Expr.h"
#include "Type.h"

class Func;
class EventHandlerPtr;

typedef enum { VAR_REGULAR, VAR_CONST, VAR_REDEF, } decl_type;

extern void add_global(ID* id, BroType* t, init_class c, Expr* init,
			attr_list* attr, decl_type dt);
extern Stmt* add_local(ID* id, BroType* t, init_class c, Expr* init,
			attr_list* attr, decl_type dt);
extern Expr* add_and_assign_local(ID* id, Expr* init, Val* val = 0);

extern void add_type(ID* id, BroType* t, attr_list* attr);

extern void begin_func(ID* id, const char* module_name, function_flavor flavor,
		       int is_redef, FuncType* t);
extern void end_func(Stmt* body, attr_list* attrs = 0);

extern Val* internal_val(const char* name);
extern Val* internal_const_val(const char* name); // internal error if not const
extern Val* opt_internal_val(const char* name);	// returns nil if not defined
extern double opt_internal_double(const char* name);
extern bro_int_t opt_internal_int(const char* name);
extern bro_uint_t opt_internal_unsigned(const char* name);
extern StringVal* opt_internal_string(const char* name);
extern TableVal* opt_internal_table(const char* name);	// nil if not defined
extern ListVal* internal_list_val(const char* name);
extern BroType* internal_type(const char* name);
extern Func* internal_func(const char* name);
extern EventHandlerPtr internal_handler(const char* name);

extern int signal_val;	// 0 if no signal pending

#endif
