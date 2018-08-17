// See the file "COPYING" in the main distribution directory for copyright.

#ifndef stmt_h
#define stmt_h

// BRO statements.

#include "BroList.h"
#include "Obj.h"
#include "Expr.h"
#include "Reporter.h"

#include "StmtEnums.h"

#include "TraverseTypes.h"

class StmtList;
class ForStmt;

declare(PDict, int);

class Stmt : public BroObj {
public:
	BroStmtTag Tag() const	{ return tag; }

	~Stmt() override;

	virtual Val* Exec(Frame* f, stmt_flow_type& flow) const = 0;

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
	uint32 GetAccessCount() const { return access_count; }

	void Describe(ODesc* d) const override;

	virtual void IncrBPCount()	{ ++breakpoint_count; }
	virtual void DecrBPCount()
		{
		if ( breakpoint_count )
			--breakpoint_count;
		else
			reporter->InternalError("breakpoint count decremented below 0");
		}

	virtual unsigned int BPCount() const	{ return breakpoint_count; }

	bool Serialize(SerialInfo* info) const;
	static Stmt* Unserialize(UnserialInfo* info, BroStmtTag want = STMT_ANY);

	virtual TraversalCode Traverse(TraversalCallback* cb) const = 0;

protected:
	Stmt()	{}
	explicit Stmt(BroStmtTag arg_tag);

	void AddTag(ODesc* d) const;
	void DescribeDone(ODesc* d) const;

	DECLARE_ABSTRACT_SERIAL(Stmt);

	BroStmtTag tag;
	int breakpoint_count;	// how many breakpoints on this statement

	// FIXME: Learn the exact semantics of mutable.
	mutable double last_access;	// time of last execution
	mutable uint32 access_count;	// number of executions
};

class ExprListStmt : public Stmt {
public:
	const ListExpr* ExprList() const	{ return l; }

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	ExprListStmt()	{ l = 0; }
	ExprListStmt(BroStmtTag t, ListExpr* arg_l);

	~ExprListStmt() override;

	Val* Exec(Frame* f, stmt_flow_type& flow) const override;
	virtual Val* DoExec(val_list* vals, stmt_flow_type& flow) const = 0;

	void Describe(ODesc* d) const override;
	void PrintVals(ODesc* d, val_list* vals, int offset) const;

	DECLARE_ABSTRACT_SERIAL(ExprListStmt);

	ListExpr* l;
};

class PrintStmt : public ExprListStmt {
public:
	explicit PrintStmt(ListExpr* l) : ExprListStmt(STMT_PRINT, l)	{ }

protected:
	friend class Stmt;
	PrintStmt()	{}

	Val* DoExec(val_list* vals, stmt_flow_type& flow) const override;

	DECLARE_SERIAL(PrintStmt);
};

class ExprStmt : public Stmt {
public:
	explicit ExprStmt(Expr* e);
	~ExprStmt() override;

	Val* Exec(Frame* f, stmt_flow_type& flow) const override;

	const Expr* StmtExpr() const	{ return e; }

	void Describe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	friend class Stmt;
	ExprStmt()	{ e = 0; }
	ExprStmt(BroStmtTag t, Expr* e);

	virtual Val* DoExec(Frame* f, Val* v, stmt_flow_type& flow) const;

	int IsPure() const override;

	DECLARE_SERIAL(ExprStmt);

	Expr* e;
};

class IfStmt : public ExprStmt {
public:
	IfStmt(Expr* test, Stmt* s1, Stmt* s2);
	~IfStmt() override;

	const Stmt* TrueBranch() const	{ return s1; }
	const Stmt* FalseBranch() const	{ return s2; }

	void Describe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	friend class Stmt;
	IfStmt()	{ s1 = s2 = 0; }

	Val* DoExec(Frame* f, Val* v, stmt_flow_type& flow) const override;
	int IsPure() const override;

	DECLARE_SERIAL(IfStmt);

	Stmt* s1;
	Stmt* s2;
};

class Case : public BroObj {
public:
	Case(ListExpr* c, id_list* types, Stmt* arg_s);
	~Case() override;

	const ListExpr* ExprCases() const	{ return expr_cases; }
	ListExpr* ExprCases()		{ return expr_cases; }

	const id_list* TypeCases() const	{ return type_cases; }
	id_list* TypeCases()		{ return type_cases; }

	const Stmt* Body() const	{ return s; }
	Stmt* Body()			{ return s; }

	void Describe(ODesc* d) const override;

	bool Serialize(SerialInfo* info) const;
	static Case* Unserialize(UnserialInfo* info);

	TraversalCode Traverse(TraversalCallback* cb) const;

protected:
	friend class Stmt;
	Case()	{ expr_cases = 0; type_cases = 0; s = 0; }

	DECLARE_SERIAL(Case);

	ListExpr* expr_cases;
	id_list* type_cases;
	Stmt* s;
};

class SwitchStmt : public ExprStmt {
public:
	SwitchStmt(Expr* index, case_list* cases);
	~SwitchStmt() override;

	const case_list* Cases() const	{ return cases; }

	void Describe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	friend class Stmt;
	SwitchStmt()	{ cases = 0; default_case_idx = -1; comp_hash = 0; }

	Val* DoExec(Frame* f, Val* v, stmt_flow_type& flow) const override;
	int IsPure() const override;

	DECLARE_SERIAL(SwitchStmt);

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
	PDict(int) case_label_value_map;
	std::vector<std::pair<ID*, int>> case_label_type_list;
};

class AddStmt : public ExprStmt {
public:
	explicit AddStmt(Expr* e);

	int IsPure() const override;
	Val* Exec(Frame* f, stmt_flow_type& flow) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	friend class Stmt;
	AddStmt()	{}

	DECLARE_SERIAL(AddStmt);
};

class DelStmt : public ExprStmt {
public:
	explicit DelStmt(Expr* e);

	int IsPure() const override;
	Val* Exec(Frame* f, stmt_flow_type& flow) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	friend class Stmt;
	DelStmt()	{}

	DECLARE_SERIAL(DelStmt);
};

class EventStmt : public ExprStmt {
public:
	explicit EventStmt(EventExpr* e);

	Val* Exec(Frame* f, stmt_flow_type& flow) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	friend class Stmt;
	EventStmt()	{ event_expr = 0; }

	DECLARE_SERIAL(EventStmt);

	EventExpr* event_expr;
};

class WhileStmt : public Stmt {
public:

	WhileStmt(Expr* loop_condition, Stmt* body);
	~WhileStmt() override;

	int IsPure() const override;

	void Describe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	friend class Stmt;

	WhileStmt()
		{ loop_condition = 0; body = 0; }

	Val* Exec(Frame* f, stmt_flow_type& flow) const override;

	DECLARE_SERIAL(WhileStmt);

	Expr* loop_condition;
	Stmt* body;
};

class ForStmt : public ExprStmt {
public:
	ForStmt(id_list* loop_vars, Expr* loop_expr);
	~ForStmt() override;

	void AddBody(Stmt* arg_body)	{ body = arg_body; }

	const id_list* LoopVar() const	{ return loop_vars; }
	const Expr* LoopExpr() const	{ return e; }
	const Stmt* LoopBody() const	{ return body; }

	int IsPure() const override;

	void Describe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	friend class Stmt;
	ForStmt()	{ loop_vars = 0; body = 0; }

	Val* DoExec(Frame* f, Val* v, stmt_flow_type& flow) const override;

	DECLARE_SERIAL(ForStmt);

	id_list* loop_vars;
	Stmt* body;
};

class NextStmt : public Stmt {
public:
	NextStmt() : Stmt(STMT_NEXT)	{ }

	Val* Exec(Frame* f, stmt_flow_type& flow) const override;
	int IsPure() const override;

	void Describe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	DECLARE_SERIAL(NextStmt);
};

class BreakStmt : public Stmt {
public:
	BreakStmt() : Stmt(STMT_BREAK)	{ }

	Val* Exec(Frame* f, stmt_flow_type& flow) const override;
	int IsPure() const override;

	void Describe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	DECLARE_SERIAL(BreakStmt);
};

class FallthroughStmt : public Stmt {
public:
	FallthroughStmt() : Stmt(STMT_FALLTHROUGH)	{ }

	Val* Exec(Frame* f, stmt_flow_type& flow) const override;
	int IsPure() const override;

	void Describe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	DECLARE_SERIAL(FallthroughStmt);
};

class ReturnStmt : public ExprStmt {
public:
	explicit ReturnStmt(Expr* e);

	Val* Exec(Frame* f, stmt_flow_type& flow) const override;

	void Describe(ODesc* d) const override;

protected:
	friend class Stmt;
	ReturnStmt()	{}

	DECLARE_SERIAL(ReturnStmt);
};

class StmtList : public Stmt {
public:
	StmtList();
	~StmtList() override;

	Val* Exec(Frame* f, stmt_flow_type& flow) const override;

	const stmt_list& Stmts() const	{ return stmts; }
	stmt_list& Stmts()		{ return stmts; }

	void Describe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	int IsPure() const override;

	DECLARE_SERIAL(StmtList);

	stmt_list stmts;
};

class EventBodyList : public StmtList {
public:
	EventBodyList() : StmtList()
		{ topmost = false; tag = STMT_EVENT_BODY_LIST; }

	Val* Exec(Frame* f, stmt_flow_type& flow) const override;

	void Describe(ODesc* d) const override;

	// "Topmost" means that this is the main body of a function or event.
	// void SetTopmost(bool is_topmost)	{ topmost = is_topmost; }
	// bool IsTopmost()	{ return topmost; }

protected:

	DECLARE_SERIAL(EventBodyList);

	bool topmost;
};

class InitStmt : public Stmt {
public:
	explicit InitStmt(id_list* arg_inits) : Stmt(STMT_INIT)
		{
		inits = arg_inits;
		if ( arg_inits && arg_inits->length() )
			SetLocationInfo((*arg_inits)[0]->GetLocationInfo());
		}

	~InitStmt() override;

	Val* Exec(Frame* f, stmt_flow_type& flow) const override;

	const id_list* Inits() const	{ return inits; }

	void Describe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	friend class Stmt;
	InitStmt()	{ inits = 0; }

	DECLARE_SERIAL(InitStmt);

	id_list* inits;
};

class NullStmt : public Stmt {
public:
	NullStmt() : Stmt(STMT_NULL)	{ }

	Val* Exec(Frame* f, stmt_flow_type& flow) const override;
	int IsPure() const override;

	void Describe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	DECLARE_SERIAL(NullStmt);
};

class WhenStmt : public Stmt {
public:
	// s2 is null if no timeout block given.
	WhenStmt(Expr* cond, Stmt* s1, Stmt* s2, Expr* timeout, bool is_return);
	~WhenStmt() override;

	Val* Exec(Frame* f, stmt_flow_type& flow) const override;
	int IsPure() const override;

	const Expr* Cond() const	{ return cond; }
	const Stmt* Body() const	{ return s1; }
	const Expr* TimeoutExpr() const	{ return timeout; }
	const Stmt* TimeoutBody() const	{ return s2; }

	void Describe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	WhenStmt()	{ cond = 0; s1 = s2 = 0; timeout = 0; is_return = 0; }

	DECLARE_SERIAL(WhenStmt);

	Expr* cond;
	Stmt* s1;
	Stmt* s2;
	Expr* timeout;
	bool is_return;
};

#endif
