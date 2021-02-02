// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/IntrusivePtr.h"
#include "zeek/ID.h"
#include "zeek/Type.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(EventHandlerPtr, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(StringVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(TableVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(ListVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(FuncType, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(Stmt, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(Expr, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(Scope, zeek::detail);

namespace zeek::detail {

using StmtPtr = IntrusivePtr<Stmt>;

enum DeclType { VAR_REGULAR, VAR_CONST, VAR_REDEF, VAR_OPTION, };

extern void add_global(const IDPtr& id, TypePtr t, InitClass c, ExprPtr init,
                       std::unique_ptr<std::vector<AttrPtr>> attr, DeclType dt);

extern StmtPtr add_local(IDPtr id, TypePtr t, InitClass c, ExprPtr init,
												 std::unique_ptr<std::vector<AttrPtr>> attr, DeclType dt);

extern ExprPtr add_and_assign_local(IDPtr id, ExprPtr init, ValPtr val = nullptr);

extern void add_type(ID* id, TypePtr t,
                     std::unique_ptr<std::vector<AttrPtr>> attr);

extern void begin_func(IDPtr id, const char* module_name, FunctionFlavor flavor,
                       bool is_redef, FuncTypePtr t,
                       std::unique_ptr<std::vector<AttrPtr>> attrs = nullptr);

extern void end_func(StmtPtr body);

// Gather all IDs referenced inside a body that aren't part of a given scope.
extern IDPList gather_outer_ids(Scope* scope, Stmt* body);

} // namespace zeek::detail
