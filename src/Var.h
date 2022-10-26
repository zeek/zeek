// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/ID.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Type.h"

namespace zeek
	{

class EventHandlerPtr;
class StringVal;
class TableVal;
class ListVal;
class FuncType;

namespace detail
	{

class Expr;
class Scope;
class Stmt;
using StmtPtr = IntrusivePtr<Stmt>;
using ScopePtr = IntrusivePtr<Scope>;

enum DeclType
	{
	VAR_REGULAR,
	VAR_CONST,
	VAR_REDEF,
	VAR_OPTION,
	};

extern void add_global(const IDPtr& id, TypePtr t, InitClass c, ExprPtr init,
                       std::unique_ptr<std::vector<AttrPtr>> attr, DeclType dt);

extern StmtPtr add_local(IDPtr id, TypePtr t, InitClass c, ExprPtr init,
                         std::unique_ptr<std::vector<AttrPtr>> attr, DeclType dt);

extern ExprPtr add_and_assign_local(IDPtr id, ExprPtr init, ValPtr val = nullptr);

extern void add_type(ID* id, TypePtr t, std::unique_ptr<std::vector<AttrPtr>> attr);

extern void begin_func(IDPtr id, const char* module_name, FunctionFlavor flavor, bool is_redef,
                       FuncTypePtr t, std::unique_ptr<std::vector<AttrPtr>> attrs = nullptr);

extern void end_func(StmtPtr body, const char* module_name, bool free_of_conditionals);

// Gather all IDs referenced inside a body that aren't part of a given scope.
extern IDPList gather_outer_ids(ScopePtr scope, StmtPtr body);

	} // namespace detail
	} // namespace zeek
