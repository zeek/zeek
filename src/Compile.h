// See the file "COPYING" in the main distribution directory for copyright.

// Abstract class for compilation.  For concrete compilation, see ZAM.h

#pragma once

#include "Stmt.h"
#include "Val.h"
#include "Event.h"
#include "ReachingDefs.h"
#include "UseDefs.h"


class NameExpr;
class ConstExpr;
class FieldExpr;
class ListExpr;
class EventHandler;
class Stmt;
class SwitchStmt;
class CatchReturnStmt;

// Class representing a single compiled statement.  Designed to
// be fully opaque, but also effective without requiring pointer
// management.
class CompiledStmt {
protected:
	friend class ZAM;

	CompiledStmt(int _stmt_num)	{ stmt_num = _stmt_num; }

	int stmt_num;	// used for ZAM
};


class OpaqueVals;

// The (reduced) statement currently being compiled.  Used for both
// tracking "use" and "reaching" definitions, and for error messages.
extern const Stmt* curr_stmt;

class Compiler : public Stmt {
public:
	void SetCurrStmt(const Stmt* stmt)	{ curr_stmt = stmt; }

#include "CompilerBaseDefs.h"

	virtual const CompiledStmt InterpretExpr(const Expr* e) = 0;
	virtual const CompiledStmt InterpretExpr(const NameExpr* n,
							const Expr* e) = 0;

	virtual const CompiledStmt ConstructTable(const NameExpr* n,
							const Expr* e) = 0;
	virtual const CompiledStmt ConstructSet(const NameExpr* n,
							const Expr* e) = 0;
	virtual const CompiledStmt ConstructRecord(const NameExpr* n,
							const Expr* e) = 0;
	virtual const CompiledStmt ConstructVector(const NameExpr* n,
							const Expr* e) = 0;

	virtual const CompiledStmt ArithCoerce(const NameExpr* n,
							const Expr* e) = 0;
	virtual const CompiledStmt RecordCoerce(const NameExpr* n,
							const Expr* e) = 0;
	virtual const CompiledStmt TableCoerce(const NameExpr* n,
							const Expr* e) = 0;
	virtual const CompiledStmt VectorCoerce(const NameExpr* n,
							const Expr* e) = 0;

	virtual const CompiledStmt Is(const NameExpr* n, const Expr* e) = 0;

	virtual const CompiledStmt IfElse(const Expr* e, const Stmt* s1,
						const Stmt* s2) = 0;

	virtual const CompiledStmt While(const Stmt* cond_stmt,
					const Expr* cond, const Stmt* body) = 0;
	virtual const CompiledStmt Loop(const Stmt* body) = 0;

	virtual const CompiledStmt When(Expr* cond, const Stmt* body,
				const Expr* timeout, const Stmt* timeout_body,
				bool is_return) = 0;

	virtual const CompiledStmt Switch(const SwitchStmt* sw) = 0;

	virtual const CompiledStmt For(const ForStmt* f) = 0;

	virtual const CompiledStmt Call(const ExprStmt* e) = 0;
	virtual const CompiledStmt AssignToCall(const ExprStmt* e) = 0;

	virtual const CompiledStmt AssignVecElems(const Expr* e) = 0;
	virtual const CompiledStmt AssignTableElem(const Expr* e) = 0;

	virtual const CompiledStmt InitRecord(ID* id, RecordType* rt) = 0;
	virtual const CompiledStmt InitVector(ID* id, VectorType* vt) = 0;
	virtual const CompiledStmt InitTable(ID* id, TableType* tt,
						Attributes* attrs) = 0;

	virtual const CompiledStmt Return(const ReturnStmt* r) = 0;
	virtual const CompiledStmt CatchReturn(const CatchReturnStmt* cr) = 0;

	virtual const CompiledStmt Next() = 0;
	virtual const CompiledStmt Break() = 0;
	virtual const CompiledStmt FallThrough() = 0;

	virtual const CompiledStmt StartingBlock() = 0;
	virtual const CompiledStmt FinishBlock(const CompiledStmt start) = 0;

	virtual bool NullStmtOK() const = 0;

	virtual const CompiledStmt EmptyStmt() = 0;
	virtual const CompiledStmt ErrorStmt() = 0;

	virtual bool IsUnused(const ID* id, const Stmt* where) const = 0;

	// Called to synchronize any globals that have been modified
	// prior to switching to execution out of the current function
	// body (for a call or a return).  The argument is a statement
	// or expression, used to find reaching-defs.  A nil value
	// corresponds to "running off the end" (no explicit return).
	virtual void SyncGlobals(const BroObj* o) = 0;

	// Tells the compiler that the last statement(s) resulted in
	// an assignment to a global.  This enables the compiler to
	// manage the global's state.
	virtual const CompiledStmt AssignedToGlobal(const ID* global_id) = 0;

	// Returns a handle to state associated with building
	// up a list of values.
	virtual OpaqueVals* BuildVals(const IntrusivePtr<ListExpr>&) = 0;

	virtual void ProfileExecution() const = 0;

protected:
	TraversalCode Traverse(TraversalCallback* cb) const override;
};
