// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "Stmt.h"
#include "Val.h"


class NameExpr;
class ConstExpr;

class CompiledStmts : public Stmt {
public:
	virtual int ReturnV(NameExpr* n) = 0;
	virtual int ReturnC(ConstExpr* c) = 0;
	virtual int ReturnX() = 0;

	TraversalCode Traverse(TraversalCallback* cb) const override;
};


class AbstractStmt;

class AbstractMachine : public CompiledStmts {
public:
	AbstractMachine(int frame_size);
	~AbstractMachine() override;

	int ReturnV(NameExpr* n) override;
	int ReturnC(ConstExpr* c) override;
	int ReturnX() override;

	void StmtDescribe(ODesc* d) const override;

	IntrusivePtr<Val> Exec(Frame* f, stmt_flow_type& flow) const override;

protected:
	void SyncGlobals();
	int FrameSlot(const ID* id);
	int AddStmt(const AbstractStmt& stmt);

	vector<AbstractStmt> stmts;
	union BroValUnion* frame;
	int frame_size;
};
