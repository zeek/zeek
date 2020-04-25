// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "Stmt.h"
#include "Val.h"


class NameExpr;
class ConstExpr;

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

	virtual const CompiledStmt AppendToVV(const NameExpr* n1,
						const NameExpr* n2) = 0;
	virtual const CompiledStmt AppendToVC(const NameExpr* n,
						const ConstExpr* c) = 0;

	virtual const CompiledStmt Print(OpaqueVals* v) = 0;

	virtual const CompiledStmt StartingBlock() = 0;
	virtual const CompiledStmt FinishBlock(const CompiledStmt start) = 0;

	// Returns a handle to state associated with building
	// up a list of values.
	virtual OpaqueVals* BuildVals(const IntrusivePtr<ListExpr>&) = 0;

	TraversalCode Traverse(TraversalCallback* cb) const override;
};


class AbstractStmt;
union AS_ValUnion;

class AbstractMachine : public Compiler {
public:
	AbstractMachine(int frame_size);
	~AbstractMachine() override;

#include "CompilerSubDefs.h"

	const CompiledStmt AppendToVV(const NameExpr* n1,
					const NameExpr* n2) override;
	const CompiledStmt AppendToVC(const NameExpr* n,
					const ConstExpr* c) override;

	const CompiledStmt Print(OpaqueVals* v) override;

	const CompiledStmt StartingBlock() override;
	const CompiledStmt FinishBlock(const CompiledStmt start) override;

	OpaqueVals* BuildVals(const IntrusivePtr<ListExpr>&) override;

	int FrameSlot(const Expr* id);

	IntrusivePtr<Val> Exec(Frame* f, stmt_flow_type& flow) const override;

	void StmtDescribe(ODesc* d) const override;

	void Dump();

protected:
	void SyncGlobals();

	const CompiledStmt AddStmt(const AbstractStmt& stmt);

	int FrameSlot(const ID* id);

	int RegisterSlot();

	vector<AbstractStmt> stmts;
	AS_ValUnion* frame;
	int frame_size;
};
