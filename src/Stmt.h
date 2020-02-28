// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

// BRO statements.

#include "BroList.h"
#include "Dict.h"
#include "ID.h"
#include "Obj.h"

#include "StmtEnums.h"

#include "TraverseTypes.h"

class StmtList;
class CompositeHash;
class EventExpr;
class ListExpr;
class ForStmt;
class Frame;

class Stmt : public BroObj {
public:
	BroStmtTag Tag() const	{ return tag; }

	~Stmt() override;

	virtual IntrusivePtr<Val> Exec(Frame* f, stmt_flow_type& flow) const = 0;

	Stmt* Ref()			{ ::Ref(this); return this; }

	bool SetLocationInfo(const Location* loc) override
		{ return Stmt::SetLocationInfo(loc, loc); }
	bool SetLocationInfo(const Location* start, const Location* end) override;

	// True if the statement has no side effects, false otherwise.
	virtual int IsPure() const;

	StmtList* AsStmtList()
		{
		CHECK_TAG(tag, STMT_LIST, "Stmt::AsStmtList", stmt_name)
		return (StmtList*) this;
		}

	const StmtList* AsStmtList() const
		{
		CHECK_TAG(tag, STMT_LIST, "Stmt::AsStmtList", stmt_name)
		return (const StmtList*) this;
		}

	ForStmt* AsForStmt()
		{
		CHECK_TAG(tag, STMT_FOR, "Stmt::AsForStmt", stmt_name)
		return (ForStmt*) this;
		}

	void RegisterAccess() const	{ last_access = network_time; access_count++; }
	void AccessStats(ODesc* d) const;
	uint32_t GetAccessCount() const { return access_count; }

	void Describe(ODesc* d) const override;

	virtual void IncrBPCount()	{ ++breakpoint_count; }
	virtual void DecrBPCount();

	virtual unsigned int BPCount() const	{ return breakpoint_count; }

	virtual TraversalCode Traverse(TraversalCallback* cb) const = 0;

protected:
	Stmt()	{}
	explicit Stmt(BroStmtTag arg_tag);

	void AddTag(ODesc* d) const;
	void DescribeDone(ODesc* d) const;

	BroStmtTag tag;
	int breakpoint_count;	// how many breakpoints on this statement

	// FIXME: Learn the exact semantics of mutable.
	mutable double last_access;	// time of last execution
	mutable uint32_t access_count;	// number of executions
};

class ExprListStmt : public Stmt {
public:
	const ListExpr* ExprList() const	{ return l.get(); }

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	ExprListStmt(BroStmtTag t, IntrusivePtr<ListExpr> arg_l);

	~ExprListStmt() override;

	IntrusivePtr<Val> Exec(Frame* f, stmt_flow_type& flow) const override;
	virtual IntrusivePtr<Val> DoExec(val_list* vals, stmt_flow_type& flow) const = 0;

	void Describe(ODesc* d) const override;
	void PrintVals(ODesc* d, val_list* vals, int offset) const;

	IntrusivePtr<ListExpr> l;
};

class PrintStmt : public ExprListStmt {
public:
	template<typename L>
	explicit PrintStmt(L&& l) : ExprListStmt(STMT_PRINT, std::forward<L>(l)) { }

protected:
	IntrusivePtr<Val> DoExec(val_list* vals, stmt_flow_type& flow) const override;
};

class ExprStmt : public Stmt {
public:
	explicit ExprStmt(IntrusivePtr<Expr> e);
	~ExprStmt() override;

	IntrusivePtr<Val> Exec(Frame* f, stmt_flow_type& flow) const override;

	const Expr* StmtExpr() const	{ return e.get(); }

	void Describe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	ExprStmt(BroStmtTag t, IntrusivePtr<Expr> e);

	virtual IntrusivePtr<Val> DoExec(Frame* f, Val* v, stmt_flow_type& flow) const;

	int IsPure() const override;

	IntrusivePtr<Expr> e;
};

class IfStmt : public ExprStmt {
public:
	IfStmt(IntrusivePtr<Expr> test, IntrusivePtr<Stmt> s1, IntrusivePtr<Stmt> s2);
	~IfStmt() override;

	const Stmt* TrueBranch() const	{ return s1.get(); }
	const Stmt* FalseBranch() const	{ return s2.get(); }

	void Describe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	IntrusivePtr<Val> DoExec(Frame* f, Val* v, stmt_flow_type& flow) const override;
	int IsPure() const override;

	IntrusivePtr<Stmt> s1;
	IntrusivePtr<Stmt> s2;
};

class Case : public BroObj {
public:
	Case(IntrusivePtr<ListExpr> c, id_list* types, IntrusivePtr<Stmt> arg_s);
	~Case() override;

	const ListExpr* ExprCases() const	{ return expr_cases.get(); }
	ListExpr* ExprCases()		{ return expr_cases.get(); }

	const id_list* TypeCases() const	{ return type_cases; }
	id_list* TypeCases()		{ return type_cases; }

	const Stmt* Body() const	{ return s.get(); }
	Stmt* Body()			{ return s.get(); }

	void Describe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const;

protected:
	IntrusivePtr<ListExpr> expr_cases;
	id_list* type_cases;
	IntrusivePtr<Stmt> s;
};

typedef PList<Case> case_list;

class SwitchStmt : public ExprStmt {
public:
	SwitchStmt(IntrusivePtr<Expr> index, case_list* cases);
	~SwitchStmt() override;

	const case_list* Cases() const	{ return cases; }

	void Describe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	IntrusivePtr<Val> DoExec(Frame* f, Val* v, stmt_flow_type& flow) const override;
	int IsPure() const override;

	// Initialize composite hash and case label map.
	void Init();

	// Adds an entry in case_label_value_map for the given value to associate it
	// with the given index in the cases list.  If the entry already exists,
	// returns false, else returns true.
	bool AddCaseLabelValueMapping(const Val* v, int idx);

	// Adds an entry in case_label_type_map for the given type (w/ ID) to
	// associate it with the given index in the cases list.  If an entry
	// for the type already exists, returns false; else returns true.
	bool AddCaseLabelTypeMapping(ID* t, int idx);

	// Returns index of a case label that matches the value, or
	// default_case_idx if no case label matches (which may be -1 if
	// there's no default label). The second tuple element is the ID of
	// the matching type-based case if it defines one.
	std::pair<int, ID*> FindCaseLabelMatch(const Val* v) const;

	case_list* cases;
	int default_case_idx;
	CompositeHash* comp_hash;
	PDict<int> case_label_value_map;
	std::vector<std::pair<ID*, int>> case_label_type_list;
};

class AddStmt : public ExprStmt {
public:
	explicit AddStmt(IntrusivePtr<Expr> e);

	int IsPure() const override;
	IntrusivePtr<Val> Exec(Frame* f, stmt_flow_type& flow) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;
};

class DelStmt : public ExprStmt {
public:
	explicit DelStmt(IntrusivePtr<Expr> e);

	int IsPure() const override;
	IntrusivePtr<Val> Exec(Frame* f, stmt_flow_type& flow) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;
};

class EventStmt : public ExprStmt {
public:
	explicit EventStmt(IntrusivePtr<EventExpr> e);

	IntrusivePtr<Val> Exec(Frame* f, stmt_flow_type& flow) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	IntrusivePtr<EventExpr> event_expr;
};

class WhileStmt : public Stmt {
public:

	WhileStmt(IntrusivePtr<Expr> loop_condition, IntrusivePtr<Stmt> body);
	~WhileStmt() override;

	int IsPure() const override;

	void Describe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	IntrusivePtr<Val> Exec(Frame* f, stmt_flow_type& flow) const override;

	IntrusivePtr<Expr> loop_condition;
	IntrusivePtr<Stmt> body;
};

class ForStmt : public ExprStmt {
public:
	ForStmt(id_list* loop_vars, IntrusivePtr<Expr> loop_expr);
	// Special constructor for key value for loop.
	ForStmt(id_list* loop_vars, IntrusivePtr<Expr> loop_expr, IntrusivePtr<ID> val_var);
	~ForStmt() override;

	void AddBody(IntrusivePtr<Stmt> arg_body)	{ body = std::move(arg_body); }

	const id_list* LoopVar() const	{ return loop_vars; }
	const Expr* LoopExpr() const	{ return e.get(); }
	const Stmt* LoopBody() const	{ return body.get(); }

	int IsPure() const override;

	void Describe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	IntrusivePtr<Val> DoExec(Frame* f, Val* v, stmt_flow_type& flow) const override;

	id_list* loop_vars;
	IntrusivePtr<Stmt> body;
	// Stores the value variable being used for a key value for loop.
	// Always set to nullptr unless special constructor is called.
	IntrusivePtr<ID> value_var;
};

class NextStmt : public Stmt {
public:
	NextStmt() : Stmt(STMT_NEXT)	{ }

	IntrusivePtr<Val> Exec(Frame* f, stmt_flow_type& flow) const override;
	int IsPure() const override;

	void Describe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
};

class BreakStmt : public Stmt {
public:
	BreakStmt() : Stmt(STMT_BREAK)	{ }

	IntrusivePtr<Val> Exec(Frame* f, stmt_flow_type& flow) const override;
	int IsPure() const override;

	void Describe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
};

class FallthroughStmt : public Stmt {
public:
	FallthroughStmt() : Stmt(STMT_FALLTHROUGH)	{ }

	IntrusivePtr<Val> Exec(Frame* f, stmt_flow_type& flow) const override;
	int IsPure() const override;

	void Describe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
};

class ReturnStmt : public ExprStmt {
public:
	explicit ReturnStmt(IntrusivePtr<Expr> e);

	IntrusivePtr<Val> Exec(Frame* f, stmt_flow_type& flow) const override;

	void Describe(ODesc* d) const override;
};

class StmtList : public Stmt {
public:
	StmtList();
	~StmtList() override;

	IntrusivePtr<Val> Exec(Frame* f, stmt_flow_type& flow) const override;

	const stmt_list& Stmts() const	{ return stmts; }
	stmt_list& Stmts()		{ return stmts; }

	void Describe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	int IsPure() const override;

	stmt_list stmts;
};

class EventBodyList : public StmtList {
public:
	EventBodyList() : StmtList()
		{ topmost = false; tag = STMT_EVENT_BODY_LIST; }

	IntrusivePtr<Val> Exec(Frame* f, stmt_flow_type& flow) const override;

	void Describe(ODesc* d) const override;

	// "Topmost" means that this is the main body of a function or event.
	// void SetTopmost(bool is_topmost)	{ topmost = is_topmost; }
	// bool IsTopmost()	{ return topmost; }

protected:
	bool topmost;
};

class InitStmt : public Stmt {
public:
	explicit InitStmt(id_list* arg_inits);

	~InitStmt() override;

	IntrusivePtr<Val> Exec(Frame* f, stmt_flow_type& flow) const override;

	const id_list* Inits() const	{ return inits; }

	void Describe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	id_list* inits;
};

class NullStmt : public Stmt {
public:
	NullStmt() : Stmt(STMT_NULL)	{ }

	IntrusivePtr<Val> Exec(Frame* f, stmt_flow_type& flow) const override;
	int IsPure() const override;

	void Describe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;
};

class WhenStmt : public Stmt {
public:
	// s2 is null if no timeout block given.
	WhenStmt(IntrusivePtr<Expr> cond,
	         IntrusivePtr<Stmt> s1, IntrusivePtr<Stmt> s2,
	         IntrusivePtr<Expr> timeout, bool is_return);
	~WhenStmt() override;

	IntrusivePtr<Val> Exec(Frame* f, stmt_flow_type& flow) const override;
	int IsPure() const override;

	const Expr* Cond() const	{ return cond.get(); }
	const Stmt* Body() const	{ return s1.get(); }
	const Expr* TimeoutExpr() const	{ return timeout.get(); }
	const Stmt* TimeoutBody() const	{ return s2.get(); }

	void Describe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	IntrusivePtr<Expr> cond;
	IntrusivePtr<Stmt> s1;
	IntrusivePtr<Stmt> s2;
	IntrusivePtr<Expr> timeout;
	bool is_return;
};
