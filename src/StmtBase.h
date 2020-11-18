// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

// Base class for Zeek statements.  We maintain it separately from
// the bulk of Stmt.h to allow Expr.h to include it, necessary for
// Expr.h to use StmtPtr.

#include "Obj.h"
#include "IntrusivePtr.h"
#include "StmtEnums.h"
#include "TraverseTypes.h"
#include "util.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(CompositeHash, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(Frame, zeek::detail);

namespace zeek::run_state { extern double network_time; }

namespace zeek {
class Val;
using ValPtr = IntrusivePtr<Val>;
}

namespace zeek::detail {

class StmtList;
class ForStmt;
class InitStmt;
class WhenStmt;
class SwitchStmt;

class EventExpr;
class ListExpr;

using EventExprPtr = IntrusivePtr<EventExpr>;
using ListExprPtr = IntrusivePtr<ListExpr>;

class Inliner;

class Stmt;
using StmtPtr = IntrusivePtr<Stmt>;

class Stmt : public Obj {
public:
	StmtTag Tag() const	{ return tag; }

	~Stmt() override;

	virtual ValPtr Exec(Frame* f, StmtFlowType& flow) const = 0;

	Stmt* Ref()			{ zeek::Ref(this); return this; }

	bool SetLocationInfo(const Location* loc) override
		{ return Stmt::SetLocationInfo(loc, loc); }
	bool SetLocationInfo(const Location* start, const Location* end) override;

	// True if the statement has no side effects, false otherwise.
	virtual bool IsPure() const;

	StmtList* AsStmtList();
	const StmtList* AsStmtList() const;

	ForStmt* AsForStmt();
	const ForStmt* AsForStmt() const;

	const InitStmt* AsInitStmt() const;
	const WhenStmt* AsWhenStmt() const;
	const SwitchStmt* AsSwitchStmt() const;

	void RegisterAccess() const	{ last_access = run_state::network_time; access_count++; }
	void AccessStats(ODesc* d) const;
	uint32_t GetAccessCount() const { return access_count; }

	void Describe(ODesc* d) const final;

	virtual void IncrBPCount()	{ ++breakpoint_count; }
	virtual void DecrBPCount();

	virtual unsigned int BPCount() const	{ return breakpoint_count; }

	virtual TraversalCode Traverse(TraversalCallback* cb) const = 0;

#include "script_opt/StmtOpt-Public.h"

protected:
	explicit Stmt(StmtTag arg_tag);

	void AddTag(ODesc* d) const;
	virtual void StmtDescribe(ODesc* d) const;
	void DescribeDone(ODesc* d) const;

	StmtTag tag;
	int breakpoint_count;	// how many breakpoints on this statement

	// FIXME: Learn the exact semantics of mutable.
	mutable double last_access;	// time of last execution
	mutable uint32_t access_count;	// number of executions

#include "script_opt/StmtOpt-Private.h"
};

} // namespace zeek::detail

using Stmt [[deprecated("Remove in v4.1. Use zeek::detail::Stmt instead.")]] = zeek::detail::Stmt;
