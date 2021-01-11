// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

// Base class for Zeek statements.  We maintain it separately from
// the bulk of Stmt.h to allow Expr.h to include it, necessary for
// Expr.h to use StmtPtr.

#include "zeek/Obj.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/StmtEnums.h"
#include "zeek/TraverseTypes.h"
#include "zeek/util.h"

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

	// Returns a duplicate of the statement.
	virtual StmtPtr Duplicate() = 0;

	// Recursively traverses the AST to inline eligible function calls.
	virtual void Inline(Inliner* inl)	{ }

	// Access to the original statement from which this one is derived,
	// or this one if we don't have an original.  Returns a bare pointer
	// rather than a StmtPtr to emphasize that the access is read-only.
	const Stmt* Original() const
		{ return original ? original->Original() : this; }

	// Designate the given Stmt node as the original for this one.
	void SetOriginal(StmtPtr _orig)
		{
		if ( ! original )
			original = std::move(_orig);
		}

	// A convenience function for taking a newly-created Stmt,
	// making it point to us as the successor, and returning it.
	//
	// Takes a Stmt* rather than a StmtPtr to de-clutter the calling
	// code, which is always passing in "new XyzStmt(...)".  This
	// call, as a convenient side effect, transforms that bare pointer
	// into a StmtPtr.
	virtual StmtPtr SetSucc(Stmt* succ)
		{
		succ->SetOriginal({NewRef{}, this});
		return {AdoptRef{}, succ};
		}

	const detail::Location* GetLocationInfo() const override
		{
		if ( original )
			return original->GetLocationInfo();
		else
			return Obj::GetLocationInfo();
		}

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

	// The original statement from which this statement was
	// derived, if any.  Used as an aid for generating meaningful
	// and correctly-localized error messages.
	StmtPtr original = nullptr;
};

} // namespace zeek::detail

using Stmt [[deprecated("Remove in v4.1. Use zeek::detail::Stmt instead.")]] = zeek::detail::Stmt;
