// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/ASTMorpher.h"

#include "zeek/Expr.h"
#include "zeek/ID.h"
#include "zeek/Stmt.h"

namespace zeek::detail {

ExprPtr ASTMorpher::MorphExpr(const ExprPtr& e) { return e->Duplicate(this); }

StmtPtr ASTMorpher::MorphStmt(const StmtPtr& s) { return s->Duplicate(this); }

IDPtr ASTMorpher::MorphID(const IDPtr& id) { return id; }

static ASTMorpher identity_instance;
ASTMorpher* const identity_am = &identity_instance;

} // namespace zeek::detail
