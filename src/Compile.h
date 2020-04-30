// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "Stmt.h"
#include "Val.h"


class NameExpr;
class ConstExpr;
class FieldExpr;
class ListExpr;

// Class representing a single compiled statement.  Designed to
// be fully opaque, but also effective without requiring pointer
// management.
class CompiledStmt {
protected:
	friend class AbstractMachine;

	CompiledStmt(int _stmt_num)	{ stmt_num = _stmt_num; }

	int stmt_num;	// used for AbstractMachine
};


class OpaqueVals;

class Compiler : public Stmt {
public:
#include "CompilerBaseDefs.h"

	virtual const CompiledStmt StartingBlock() = 0;
	virtual const CompiledStmt FinishBlock(const CompiledStmt start) = 0;
	virtual const CompiledStmt ErrorStmt() = 0;

	// Returns a handle to state associated with building
	// up a list of values.
	virtual OpaqueVals* BuildVals(const IntrusivePtr<ListExpr>&) = 0;

protected:
	TraversalCode Traverse(TraversalCallback* cb) const override;
};


class AbstractStmt;
union AS_ValUnion;

class AbstractMachine : public Compiler {
public:
	AbstractMachine(int frame_size);
	~AbstractMachine() override;

#include "CompilerSubDefs.h"

	const CompiledStmt StartingBlock() override;
	const CompiledStmt FinishBlock(const CompiledStmt start) override;
	const CompiledStmt ErrorStmt() override;

	OpaqueVals* BuildVals(const IntrusivePtr<ListExpr>&) override;

	int FrameSlot(const Expr* id);

	IntrusivePtr<Val> Exec(Frame* f, stmt_flow_type& flow) const override;

	void StmtDescribe(ODesc* d) const override;

	void Dump();

protected:
	int InternalBuildVals(const ListExpr*);

	const CompiledStmt CompileIndex(const NameExpr* n1, const NameExpr* n2,
					const ListExpr* l);

	void SyncGlobals();

	const CompiledStmt AddStmt(const AbstractStmt& stmt);

	int FrameSlot(const ID* id);

	int RegisterSlot();

	vector<AbstractStmt> stmts;
	AS_ValUnion* frame;
	int frame_size;
	bool error_seen = false;
};
