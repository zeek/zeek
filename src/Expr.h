// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "BroList.h"
#include "IntrusivePtr.h"
#include "Timer.h"
#include "Type.h"
#include "EventHandler.h"
#include "TraverseTypes.h"
#include "Val.h"
#include "ZeekArgs.h"

#include <memory>
#include <string>
#include <vector>
#include <utility>
#include <optional>

using std::string;

enum BroExprTag : int {
	EXPR_ANY = -1,
	EXPR_NAME, EXPR_CONST,
	EXPR_CLONE,
	EXPR_INCR, EXPR_DECR,
	EXPR_NOT, EXPR_COMPLEMENT,
	EXPR_POSITIVE, EXPR_NEGATE,
	EXPR_ADD, EXPR_SUB, EXPR_ADD_TO, EXPR_APPEND_TO, EXPR_REMOVE_FROM,
	EXPR_TIMES, EXPR_DIVIDE, EXPR_MOD,
	EXPR_AND, EXPR_OR, EXPR_XOR,
	EXPR_AND_AND, EXPR_OR_OR,
	EXPR_LT, EXPR_LE, EXPR_EQ, EXPR_NE, EXPR_GE, EXPR_GT,
	EXPR_COND,
	EXPR_REF,
	EXPR_ASSIGN,
	EXPR_INDEX,
	EXPR_FIELD, EXPR_HAS_FIELD,
	EXPR_RECORD_CONSTRUCTOR,
	EXPR_TABLE_CONSTRUCTOR,
	EXPR_SET_CONSTRUCTOR,
	EXPR_VECTOR_CONSTRUCTOR,
	EXPR_FIELD_ASSIGN,
	EXPR_IN,
	EXPR_LIST,
	EXPR_CALL,
	EXPR_LAMBDA,
	EXPR_EVENT,
	EXPR_SCHEDULE,
	EXPR_ARITH_COERCE,
	EXPR_RECORD_COERCE,
	EXPR_TABLE_COERCE,
	EXPR_VECTOR_COERCE,
	EXPR_SIZE,
	EXPR_FLATTEN,
	EXPR_CAST,
	EXPR_IS,
	EXPR_INDEX_SLICE_ASSIGN,
#define NUM_EXPRS (int(EXPR_INDEX_SLICE_ASSIGN) + 1)
};

extern const char* expr_name(BroExprTag t);

template <class T> class IntrusivePtr;
class Stmt;
class Frame;
class Scope;
class ListExpr;
class NameExpr;
class IndexExpr;
class AssignExpr;
class FieldExpr;
class HasFieldExpr;
class FieldAssignExpr;
class CallExpr;
class EventExpr;
class RefExpr;
class AddToExpr;
class AppendToExpr;
class RemoveFromExpr;
class NegExpr;
class ConstExpr;
class CondExpr;

struct function_ingredients;

class ReductionContext;


class Expr : public BroObj {
public:
	~Expr()	{ Unref(original); }

	BroType* Type() const		{ return type.get(); }
	IntrusivePtr<BroType> TypeIP() const		{ return type; }
	BroExprTag Tag() const	{ return tag; }

	Expr* Ref()			{ ::Ref(this); return this; }

	// Evaluates the expression and returns a corresponding Val*,
	// or nil if the expression's value isn't fixed.
	virtual IntrusivePtr<Val> Eval(Frame* f) const = 0;

	// Same, but the context is that we are adding an element
	// into the given aggregate of the given type.  Note that
	// return type is void since it's updating an existing
	// value, rather than creating a new one.
	virtual void EvalIntoAggregate(const BroType* t, Val* aggr, Frame* f)
			const;

	// Assign to the given value, if appropriate.
	virtual void Assign(Frame* f, IntrusivePtr<Val> v);

	// Returns an expression corresponding to a temporary
	// that's been assigned to this expression via red_stmt.
	Expr* AssignToTemporary(ReductionContext* c,
				IntrusivePtr<Stmt>& red_stmt);

	// Returns the type corresponding to this expression interpreted
	// as an initialization.  Returns nil if the initialization is illegal.
	virtual IntrusivePtr<BroType> InitType() const;

	// Returns true if this expression, interpreted as an initialization,
	// constitutes a record element, false otherwise.  If the TypeDecl*
	// is non-nil and the expression is a record element, fills in the
	// TypeDecl with a description of the element.
	virtual bool IsRecordElement(TypeDecl* td) const;

	// Returns a value corresponding to this expression interpreted
	// as an initialization, or nil if the expression is inconsistent
	// with the given type.  If "aggr" is non-nil, then this expression
	// is an element of the given aggregate, and it is added to it
	// accordingly.
	virtual IntrusivePtr<Val> InitVal(const BroType* t, IntrusivePtr<Val> aggr) const;

	// This used to be framed as "true if the expression has no side
	// effects, false otherwise", but that's not quite right, since
	// for identifiers it's only true if they're constant.  So this
	// is more like "has no variable elements".
	virtual bool IsPure() const;

	// True if the expression has no side effects, false otherwise.
	virtual bool HasNoSideEffects() const	{ return IsPure(); }

	// True if the expression is in fully reduced form: a singleton
	// or an assignment to an operator with singleton operands.
	virtual bool IsReduced() const;

	// True if the expression's operands are singletons.
	virtual bool HasReducedOps() const;

	// Returns a set of predecessor statements in red_stmt (which might
	// be nil if no reduction necessary), and the reduced version of
	// the expression, suitable for replacing previous uses.
	virtual Expr* Reduce(ReductionContext* c, IntrusivePtr<Stmt>& red_stmt);
	virtual Expr* ReduceToSingleton(ReductionContext* c,
					IntrusivePtr<Stmt>& red_stmt)
		{ return Reduce(c, red_stmt); }

	// Similar, but for use as the LHS of an assignment.  The expression
	// itself doesn't transform.
	virtual IntrusivePtr<Stmt> ReduceToLHS(ReductionContext* c);

	// True if the expression can serve as an operand to a reduced
	// expression.
	bool IsSingleton() const
		{ return tag == EXPR_NAME || tag == EXPR_CONST; }

	// True if the expression is a constant, false otherwise.
	bool IsConst() const	{ return tag == EXPR_CONST; }

	// True if the expression is in error (to alleviate error propagation).
	bool IsError() const;

	// Mark expression as in error.
	void SetError();
	void SetError(const char* msg);

	// Returns the expression's constant value, or complains
	// if it's not a constant.
	inline Val* ExprVal() const;

	// Returns the expressions operands, or nil if it doesn't
	// have one.
	virtual IntrusivePtr<Expr> GetOp1() const;
	virtual IntrusivePtr<Expr> GetOp2() const;
	virtual IntrusivePtr<Expr> GetOp3() const;

	// True if the expression is a constant zero, false otherwise.
	bool IsZero() const;

	// True if the expression is a constant one, false otherwise.
	bool IsOne() const;

	// True if the expression supports the "add" or "delete" operations,
	// false otherwise.
	virtual bool CanAdd() const;
	virtual bool CanDel() const;

	virtual void Add(Frame* f);	// perform add operation
	virtual void Delete(Frame* f);	// perform delete operation

	// Return the expression converted to L-value form.  If expr
	// cannot be used as an L-value, reports an error and returns
	// the current value of expr (this is the default method).
	virtual IntrusivePtr<Expr> MakeLvalue();

	// Marks the expression as one requiring (or at least appearing
	// with) parentheses.  Used for pretty-printing.
	void MarkParen()		{ paren = true; }
	bool IsParen() const		{ return paren; }

#undef ACCESSOR
#define ACCESSOR(tag, ctype, name) \
        ctype* name() \
                { \
                CHECK_TAG(Tag(), tag, "Expr::ACCESSOR", expr_name) \
                return (ctype*) this; \
                }

#undef CONST_ACCESSOR
#define CONST_ACCESSOR(tag, ctype, name) \
        const ctype* name() const \
                { \
                CHECK_TAG(Tag(), tag, "Expr::CONST_ACCESSOR", expr_name) \
                return (const ctype*) this; \
                }

#undef ACCESSORS
#define ACCESSORS(tag, ctype, name) \
	ACCESSOR(tag, ctype, name) \
	CONST_ACCESSOR(tag, ctype, name)

	ACCESSORS(EXPR_LIST, ListExpr, AsListExpr);
	ACCESSORS(EXPR_NAME, NameExpr, AsNameExpr);
	ACCESSORS(EXPR_ASSIGN, AssignExpr, AsAssignExpr);
	ACCESSORS(EXPR_FIELD, FieldExpr, AsFieldExpr);
	ACCESSORS(EXPR_FIELD_ASSIGN, FieldAssignExpr, AsFieldAssignExpr);
	ACCESSORS(EXPR_INDEX, IndexExpr, AsIndexExpr);
	ACCESSORS(EXPR_REF, RefExpr, AsRefExpr);
	ACCESSORS(EXPR_EVENT, EventExpr, AsEventExpr);

	CONST_ACCESSOR(EXPR_HAS_FIELD, HasFieldExpr, AsHasFieldExpr);
	CONST_ACCESSOR(EXPR_CALL, CallExpr, AsCallExpr);
	CONST_ACCESSOR(EXPR_ADD_TO, AddToExpr, AsAddToExpr);
	CONST_ACCESSOR(EXPR_APPEND_TO, AppendToExpr, AsAppendToExpr);
	CONST_ACCESSOR(EXPR_CONST, ConstExpr, AsConstExpr);
	CONST_ACCESSOR(EXPR_COND, CondExpr, AsCondExpr);

#undef ACCESSORS
#undef ACCESSOR
#undef CONST_ACCESSOR

	void SetOriginal(Expr* _orig)
		{
		if ( ! original )
			original = _orig->Ref();
		}

	void Describe(ODesc* d) const override;

	virtual TraversalCode Traverse(TraversalCallback* cb) const = 0;

protected:
	// The following doesn't appear to be used.
	// Expr() = default;
	explicit Expr(BroExprTag arg_tag);

	const Expr* Original() const
		{
		if ( original )
			return original->Original();
		else
			return this;
		}

	Val* MakeZero(TypeTag t) const;
	ConstExpr* MakeZeroExpr(TypeTag t) const;

	virtual void ExprDescribe(ODesc* d) const = 0;
	void AddTag(ODesc* d) const;

	// Puts the expression in canonical form.
	virtual void Canonicize();

	Expr* TransformMe(Expr* new_me, ReductionContext* c,
				IntrusivePtr<Stmt>& red_stmt);

	void SetType(IntrusivePtr<BroType> t);

	// Reports the given error and sets the expression's type to
	// TYPE_ERROR.
	void ExprError(const char msg[]);

	// These two functions both call Reporter::RuntimeError or Reporter::ExprRuntimeError,
	// both of which are marked as [[noreturn]].
	[[noreturn]] void RuntimeError(const std::string& msg) const;
	[[noreturn]] void RuntimeErrorWithCallStack(const std::string& msg) const;

	Expr* original;
	BroExprTag tag;
	IntrusivePtr<BroType> type;
	bool paren;
};

class NameExpr : public Expr {
public:
	explicit NameExpr(IntrusivePtr<ID> id, bool const_init = false);

	ID* Id() const		{ return id.get(); }

	IntrusivePtr<Val> Eval(Frame* f) const override;
	void Assign(Frame* f, IntrusivePtr<Val> v) override;
	IntrusivePtr<Stmt> ReduceToLHS(ReductionContext* c) override;
	IntrusivePtr<Expr> MakeLvalue() override;
	bool IsPure() const override;
	bool HasNoSideEffects() const override	{ return true; }

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	void ExprDescribe(ODesc* d) const override;

	IntrusivePtr<ID> id;
	bool in_const_init;
};

class ConstExpr : public Expr {
public:
	explicit ConstExpr(IntrusivePtr<Val> val);

	Val* Value() const	{ return val.get(); }
	IntrusivePtr<Val> ValuePtr() const	{ return val; }

	IntrusivePtr<Val> Eval(Frame* f) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	void ExprDescribe(ODesc* d) const override;
	IntrusivePtr<Val> val;
};

class UnaryExpr : public Expr {
public:
	Expr* Op() const	{ return op.get(); }

	IntrusivePtr<Expr> GetOp1() const override final	{ return op; }

	// UnaryExpr::Eval correctly handles vector types.  Any child
	// class that overrides Eval() should be modified to handle
	// vectors correctly as necessary.
	IntrusivePtr<Val> Eval(Frame* f) const override;

	bool IsPure() const override;
	bool HasNoSideEffects() const override;
	bool IsReduced() const override;
	bool HasReducedOps() const override;
	Expr* Reduce(ReductionContext* c, IntrusivePtr<Stmt>& red_stmt) override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	UnaryExpr(BroExprTag arg_tag, IntrusivePtr<Expr> arg_op);

	void ExprDescribe(ODesc* d) const override;

	// Returns the expression folded using the given constant.
	virtual IntrusivePtr<Val> Fold(Val* v) const;

	IntrusivePtr<Expr> op;
};

class BinaryExpr : public Expr {
public:
	Expr* Op1() const	{ return op1.get(); }
	Expr* Op2() const	{ return op2.get(); }

	IntrusivePtr<Expr> GetOp1() const override final	{ return op1; }
	IntrusivePtr<Expr> GetOp2() const override final	{ return op2; }

	bool IsPure() const override;
	bool HasNoSideEffects() const override;
	bool IsReduced() const override;
	bool HasReducedOps() const override;
	Expr* Reduce(ReductionContext* c, IntrusivePtr<Stmt>& red_stmt) override;

	// BinaryExpr::Eval correctly handles vector types.  Any child
	// class that overrides Eval() should be modified to handle
	// vectors correctly as necessary.
	IntrusivePtr<Val> Eval(Frame* f) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	BinaryExpr(BroExprTag arg_tag,
	           IntrusivePtr<Expr> arg_op1, IntrusivePtr<Expr> arg_op2)
		: Expr(arg_tag), op1(std::move(arg_op1)), op2(std::move(arg_op2))
		{
		if ( ! (op1 && op2) )
			return;
		if ( op1->IsError() || op2->IsError() )
			SetError();
		}

	// Returns the expression folded using the given constants.
	virtual IntrusivePtr<Val> Fold(Val* v1, Val* v2) const;

	// Same for when the constants are strings.
	virtual IntrusivePtr<Val> StringFold(Val* v1, Val* v2) const;

	// Same for when the constants are patterns.
	virtual IntrusivePtr<Val> PatternFold(Val* v1, Val* v2) const;

	// Same for when the constants are sets.
	virtual IntrusivePtr<Val> SetFold(Val* v1, Val* v2) const;

	// Same for when the constants are addresses or subnets.
	virtual IntrusivePtr<Val> AddrFold(Val* v1, Val* v2) const;
	virtual IntrusivePtr<Val> SubNetFold(Val* v1, Val* v2) const;

	bool BothConst() const	{ return op1->IsConst() && op2->IsConst(); }

	// Exchange op1 and op2.
	void SwapOps();

	// Promote the operands to the given type tag, if necessary.
	void PromoteOps(TypeTag t);

	// Promote the expression to the given type tag (i.e., promote
	// operands and also set expression's type).
	void PromoteType(TypeTag t, bool is_vector);

	void ExprDescribe(ODesc* d) const override;

	IntrusivePtr<Expr> op1;
	IntrusivePtr<Expr> op2;
};

class CloneExpr : public UnaryExpr {
public:
	explicit CloneExpr(IntrusivePtr<Expr> op);
	IntrusivePtr<Val> Eval(Frame* f) const override;

protected:
	IntrusivePtr<Val> Fold(Val* v) const override;
};

class IncrExpr : public UnaryExpr {
public:
	IncrExpr(BroExprTag tag, IntrusivePtr<Expr> op);

	IntrusivePtr<Val> Eval(Frame* f) const override;
	IntrusivePtr<Val> DoSingleEval(Frame* f, Val* v) const;
	Expr* Reduce(ReductionContext* c, IntrusivePtr<Stmt>& red_stmt) override;
	bool IsPure() const override;
	bool HasNoSideEffects() const override;
};

class ComplementExpr : public UnaryExpr {
public:
	explicit ComplementExpr(IntrusivePtr<Expr> op);

protected:
	IntrusivePtr<Val> Fold(Val* v) const override;
	Expr* Reduce(ReductionContext* c, IntrusivePtr<Stmt>& red_stmt) override;
};

class NotExpr : public UnaryExpr {
public:
	explicit NotExpr(IntrusivePtr<Expr> op);

protected:
	IntrusivePtr<Val> Fold(Val* v) const override;
	Expr* Reduce(ReductionContext* c, IntrusivePtr<Stmt>& red_stmt) override;
};

class PosExpr : public UnaryExpr {
public:
	explicit PosExpr(IntrusivePtr<Expr> op);

protected:
	IntrusivePtr<Val> Fold(Val* v) const override;
	Expr* Reduce(ReductionContext* c, IntrusivePtr<Stmt>& red_stmt) override;
};

class NegExpr : public UnaryExpr {
public:
	explicit NegExpr(IntrusivePtr<Expr> op);

protected:
	IntrusivePtr<Val> Fold(Val* v) const override;
	Expr* Reduce(ReductionContext* c, IntrusivePtr<Stmt>& red_stmt) override;
};

class SizeExpr : public UnaryExpr {
public:
	explicit SizeExpr(IntrusivePtr<Expr> op);
	IntrusivePtr<Val> Eval(Frame* f) const override;

protected:
	IntrusivePtr<Val> Fold(Val* v) const override;
};

class AddExpr : public BinaryExpr {
public:
	AddExpr(IntrusivePtr<Expr> op1, IntrusivePtr<Expr> op2);
	void Canonicize() override;

	Expr* Reduce(ReductionContext* c, IntrusivePtr<Stmt>& red_stmt) override;
	Expr* BuildSub(const IntrusivePtr<Expr>& op1,
			const IntrusivePtr<Expr>& op2);
};

class AddToExpr : public BinaryExpr {
public:
	AddToExpr(IntrusivePtr<Expr> op1, IntrusivePtr<Expr> op2);
	IntrusivePtr<Val> Eval(Frame* f) const override;

	Expr* Reduce(ReductionContext* c, IntrusivePtr<Stmt>& red_stmt) override;
};

class AppendToExpr : public BinaryExpr {
public:
	AppendToExpr(IntrusivePtr<Expr> op1, IntrusivePtr<Expr> op2);
	IntrusivePtr<Val> Eval(Frame* f) const override;
};

class RemoveFromExpr : public BinaryExpr {
public:
	RemoveFromExpr(IntrusivePtr<Expr> op1, IntrusivePtr<Expr> op2);
	IntrusivePtr<Val> Eval(Frame* f) const override;

	Expr* Reduce(ReductionContext* c, IntrusivePtr<Stmt>& red_stmt) override;
};

class SubExpr : public BinaryExpr {
public:
	SubExpr(IntrusivePtr<Expr> op1, IntrusivePtr<Expr> op2);

	Expr* Reduce(ReductionContext* c, IntrusivePtr<Stmt>& red_stmt) override;
};

class TimesExpr : public BinaryExpr {
public:
	TimesExpr(IntrusivePtr<Expr> op1, IntrusivePtr<Expr> op2);
	void Canonicize() override;

	Expr* Reduce(ReductionContext* c, IntrusivePtr<Stmt>& red_stmt) override;
};

class DivideExpr : public BinaryExpr {
public:
	DivideExpr(IntrusivePtr<Expr> op1, IntrusivePtr<Expr> op2);

protected:
	IntrusivePtr<Val> AddrFold(Val* v1, Val* v2) const override;

	Expr* Reduce(ReductionContext* c, IntrusivePtr<Stmt>& red_stmt) override;
};

class ModExpr : public BinaryExpr {
public:
	ModExpr(IntrusivePtr<Expr> op1, IntrusivePtr<Expr> op2);
};

class BoolExpr : public BinaryExpr {
public:
	BoolExpr(BroExprTag tag, IntrusivePtr<Expr> op1, IntrusivePtr<Expr> op2);

	IntrusivePtr<Val> Eval(Frame* f) const override;
	IntrusivePtr<Val> DoSingleEval(Frame* f, IntrusivePtr<Val> v1, Expr* op2) const;

	Expr* Reduce(ReductionContext* c, IntrusivePtr<Stmt>& red_stmt) override;
	bool IsTrue(const IntrusivePtr<Expr>& e) const;
	bool IsFalse(const IntrusivePtr<Expr>& e) const;
};

class BitExpr : public BinaryExpr {
public:
	BitExpr(BroExprTag tag, IntrusivePtr<Expr> op1, IntrusivePtr<Expr> op2);

	Expr* Reduce(ReductionContext* c, IntrusivePtr<Stmt>& red_stmt) override;
};

class EqExpr : public BinaryExpr {
public:
	EqExpr(BroExprTag tag, IntrusivePtr<Expr> op1, IntrusivePtr<Expr> op2);
	void Canonicize() override;

protected:
	IntrusivePtr<Val> Fold(Val* v1, Val* v2) const override;
	Expr* Reduce(ReductionContext* c, IntrusivePtr<Stmt>& red_stmt) override;
};

class RelExpr : public BinaryExpr {
public:
	RelExpr(BroExprTag tag, IntrusivePtr<Expr> op1, IntrusivePtr<Expr> op2);
	void Canonicize() override;
	Expr* Reduce(ReductionContext* c, IntrusivePtr<Stmt>& red_stmt) override;
};

class CondExpr : public Expr {
public:
	CondExpr(IntrusivePtr<Expr> op1, IntrusivePtr<Expr> op2, IntrusivePtr<Expr> op3);

	const Expr* Op1() const	{ return op1.get(); }
	const Expr* Op2() const	{ return op2.get(); }
	const Expr* Op3() const	{ return op3.get(); }

	IntrusivePtr<Expr> GetOp1() const override final	{ return op1; }
	IntrusivePtr<Expr> GetOp2() const override final	{ return op2; }
	IntrusivePtr<Expr> GetOp3() const override final	{ return op3; }

	IntrusivePtr<Val> Eval(Frame* f) const override;
	bool IsPure() const override;
	bool IsReduced() const override;
	bool HasReducedOps() const override;
	Expr* Reduce(ReductionContext* c, IntrusivePtr<Stmt>& red_stmt) override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	void ExprDescribe(ODesc* d) const override;

	IntrusivePtr<Expr> op1;
	IntrusivePtr<Expr> op2;
	IntrusivePtr<Expr> op3;
};

class RefExpr : public UnaryExpr {
public:
	explicit RefExpr(IntrusivePtr<Expr> op);

	void Assign(Frame* f, IntrusivePtr<Val> v) override;
	IntrusivePtr<Expr> MakeLvalue() override;

	bool IsReduced() const override;
	bool HasReducedOps() const override;
	Expr* Reduce(ReductionContext* c, IntrusivePtr<Stmt>& red_stmt) override;
	IntrusivePtr<Stmt> ReduceToLHS(ReductionContext* c) override;
};

class AssignExpr : public BinaryExpr {
public:
	// If val is given, evaluating this expression will always yield the val
	// yet still perform the assignment.  Used for triggers.
	AssignExpr(IntrusivePtr<Expr> op1, IntrusivePtr<Expr> op2, bool is_init,
	           IntrusivePtr<Val> val = nullptr, attr_list* attrs = nullptr,
		   bool typecheck = true);

	IntrusivePtr<Val> Eval(Frame* f) const override;
	void EvalIntoAggregate(const BroType* t, Val* aggr, Frame* f) const override;
	IntrusivePtr<BroType> InitType() const override;
	bool IsRecordElement(TypeDecl* td) const override;
	IntrusivePtr<Val> InitVal(const BroType* t, IntrusivePtr<Val> aggr) const override;
	bool IsPure() const override;
	bool HasNoSideEffects() const override;
	bool IsReduced() const override;
	bool HasReducedOps() const override;
	Expr* Reduce(ReductionContext* c, IntrusivePtr<Stmt>& red_stmt) override;
	Expr* ReduceToSingleton(ReductionContext* c,
				IntrusivePtr<Stmt>& red_stmt) override;

	// Whether this is an assignment to a temporary.
	bool IsTemp() const	{ return is_temp; }
	void SetIsTemp()	{ is_temp = true; }

protected:
	bool TypeCheck(attr_list* attrs = 0);
	bool TypeCheckArithmetics(TypeTag bt1, TypeTag bt2);

	bool is_init;
	bool is_temp;
	IntrusivePtr<Val> val;	// optional
};

class IndexSliceAssignExpr : public AssignExpr {
public:
	IndexSliceAssignExpr(IntrusivePtr<Expr> op1,
	                     IntrusivePtr<Expr> op2, bool is_init);
	IntrusivePtr<Val> Eval(Frame* f) const override;
};

class IndexExpr : public BinaryExpr {
public:
	IndexExpr(IntrusivePtr<Expr> op1,
	          IntrusivePtr<ListExpr> op2, bool is_slice = false);

	bool CanAdd() const override;
	bool CanDel() const override;

	void Add(Frame* f) override;
	void Delete(Frame* f) override;

	void Assign(Frame* f, IntrusivePtr<Val> v) override;
	bool HasReducedOps() const override;
	IntrusivePtr<Stmt> ReduceToLHS(ReductionContext* c) override;
	IntrusivePtr<Stmt> ReduceToSingletons(ReductionContext* c);
	IntrusivePtr<Expr> MakeLvalue() override;

	// Need to override Eval since it can take a vector arg but does
	// not necessarily return a vector.
	IntrusivePtr<Val> Eval(Frame* f) const override;

	bool IsSlice() const { return is_slice; }

protected:
	IntrusivePtr<Val> Fold(Val* v1, Val* v2) const override;

	void ExprDescribe(ODesc* d) const override;

	bool is_slice;
};

class FieldExpr : public UnaryExpr {
public:
	FieldExpr(IntrusivePtr<Expr> op, const char* field_name);
	~FieldExpr() override;

	int Field() const	{ return field; }
	const char* FieldName() const	{ return field_name; }

	bool CanDel() const override;

	void Assign(Frame* f, IntrusivePtr<Val> v) override;
	IntrusivePtr<Stmt> ReduceToLHS(ReductionContext* c) override;
	IntrusivePtr<Stmt> ReduceToSingletons(ReductionContext* c);
	void Delete(Frame* f) override;

	IntrusivePtr<Expr> MakeLvalue() override;

protected:
	IntrusivePtr<Val> Fold(Val* v) const override;

	void ExprDescribe(ODesc* d) const override;

	const char* field_name;
	const TypeDecl* td;
	int field; // -1 = attributes
};

// "rec?$fieldname" is true if the value of $fieldname in rec is not nil.
// "rec?$$attrname" is true if the attribute attrname is not nil.
class HasFieldExpr : public UnaryExpr {
public:
	HasFieldExpr(IntrusivePtr<Expr> op, const char* field_name);
	~HasFieldExpr() override;

	const char* FieldName() const	{ return field_name; }

protected:
	IntrusivePtr<Val> Fold(Val* v) const override;

	void ExprDescribe(ODesc* d) const override;

	const char* field_name;
	int field;
};

class RecordConstructorExpr : public UnaryExpr {
public:
	explicit RecordConstructorExpr(IntrusivePtr<ListExpr> constructor_list);
	~RecordConstructorExpr() override;

protected:
	IntrusivePtr<Val> InitVal(const BroType* t, IntrusivePtr<Val> aggr) const override;
	IntrusivePtr<Val> Fold(Val* v) const override;

	void ExprDescribe(ODesc* d) const override;
};

class TableConstructorExpr : public UnaryExpr {
public:
	TableConstructorExpr(IntrusivePtr<ListExpr> constructor_list, attr_list* attrs,
	                     IntrusivePtr<BroType> arg_type = nullptr);
	~TableConstructorExpr() override { Unref(attrs); }

	Attributes* Attrs() { return attrs; }

	IntrusivePtr<Val> Eval(Frame* f) const override;

protected:
	IntrusivePtr<Val> InitVal(const BroType* t, IntrusivePtr<Val> aggr) const override;

	void ExprDescribe(ODesc* d) const override;

	Attributes* attrs;
};

class SetConstructorExpr : public UnaryExpr {
public:
	SetConstructorExpr(IntrusivePtr<ListExpr> constructor_list, attr_list* attrs,
	                   IntrusivePtr<BroType> arg_type = nullptr);
	~SetConstructorExpr() override { Unref(attrs); }

	Attributes* Attrs() { return attrs; }

	IntrusivePtr<Val> Eval(Frame* f) const override;

protected:
	IntrusivePtr<Val> InitVal(const BroType* t, IntrusivePtr<Val> aggr) const override;

	void ExprDescribe(ODesc* d) const override;

	Attributes* attrs;
};

class VectorConstructorExpr : public UnaryExpr {
public:
	explicit VectorConstructorExpr(IntrusivePtr<ListExpr> constructor_list,
	                               IntrusivePtr<BroType> arg_type = nullptr);

	IntrusivePtr<Val> Eval(Frame* f) const override;

protected:
	IntrusivePtr<Val> InitVal(const BroType* t, IntrusivePtr<Val> aggr) const override;

	void ExprDescribe(ODesc* d) const override;
};

class FieldAssignExpr : public UnaryExpr {
public:
	FieldAssignExpr(const char* field_name, IntrusivePtr<Expr> value);

	const char* FieldName() const	{ return field_name.c_str(); }

	void EvalIntoAggregate(const BroType* t, Val* aggr, Frame* f) const override;
	Expr* Reduce(ReductionContext* c, IntrusivePtr<Stmt>& red_stmt) override;

	bool IsRecordElement(TypeDecl* td) const override;

protected:
	void ExprDescribe(ODesc* d) const override;

	string field_name;
};

class ArithCoerceExpr : public UnaryExpr {
public:
	ArithCoerceExpr(IntrusivePtr<Expr> op, TypeTag t);

protected:
	IntrusivePtr<Val> FoldSingleVal(Val* v, InternalTypeTag t) const;
	IntrusivePtr<Val> Fold(Val* v) const override;
};

class RecordCoerceExpr : public UnaryExpr {
public:
	RecordCoerceExpr(IntrusivePtr<Expr> op, IntrusivePtr<RecordType> r);
	~RecordCoerceExpr() override;

protected:
	IntrusivePtr<Val> InitVal(const BroType* t, IntrusivePtr<Val> aggr) const override;
	IntrusivePtr<Val> Fold(Val* v) const override;

	// For each super-record slot, gives subrecord slot with which to
	// fill it.
	int* map;
	int map_size;	// equivalent to Type()->AsRecordType()->NumFields()
};

class TableCoerceExpr : public UnaryExpr {
public:
	TableCoerceExpr(IntrusivePtr<Expr> op, IntrusivePtr<TableType> r);
	~TableCoerceExpr() override;

protected:
	IntrusivePtr<Val> Fold(Val* v) const override;
};

class VectorCoerceExpr : public UnaryExpr {
public:
	VectorCoerceExpr(IntrusivePtr<Expr> op, IntrusivePtr<VectorType> v);
	~VectorCoerceExpr() override;

protected:
	IntrusivePtr<Val> Fold(Val* v) const override;
};

// An internal operator for flattening array indices that are records
// into a list of individual values.
class FlattenExpr : public UnaryExpr {
public:
	explicit FlattenExpr(IntrusivePtr<Expr> op);

protected:
	IntrusivePtr<Val> Fold(Val* v) const override;

	int num_fields;
};

class ScheduleTimer : public Timer {
public:
	ScheduleTimer(const EventHandlerPtr& event, zeek::Args args, double t);
	~ScheduleTimer() override;

	void Dispatch(double t, bool is_expire) override;

protected:
	EventHandlerPtr event;
	zeek::Args args;
};

class ScheduleExpr : public Expr {
public:
	ScheduleExpr(IntrusivePtr<Expr> when, IntrusivePtr<EventExpr> event);

	bool IsPure() const override;
	bool IsReduced() const override;
	bool HasReducedOps() const override;
	Expr* Reduce(ReductionContext* c, IntrusivePtr<Stmt>& red_stmt) override;

	IntrusivePtr<Val> Eval(Frame* f) const override;

	Expr* When() const	{ return when.get(); }
	EventExpr* Event() const	{ return event.get(); }

	IntrusivePtr<Expr> GetOp1() const override final;
	IntrusivePtr<Expr> GetOp2() const override final;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	void ExprDescribe(ODesc* d) const override;

	IntrusivePtr<Expr> when;
	IntrusivePtr<EventExpr> event;
};

class InExpr : public BinaryExpr {
public:
	InExpr(IntrusivePtr<Expr> op1, IntrusivePtr<Expr> op2);

protected:
	IntrusivePtr<Val> Fold(Val* v1, Val* v2) const override;

};

class CallExpr : public Expr {
public:
	CallExpr(IntrusivePtr<Expr> func, IntrusivePtr<ListExpr> args,
	         bool in_hook = false);

	Expr* Func() const	{ return func.get(); }
	ListExpr* Args() const	{ return args.get(); }

	bool IsPure() const override;
	bool IsReduced() const override;
	bool HasReducedOps() const override;
	Expr* Reduce(ReductionContext* c, IntrusivePtr<Stmt>& red_stmt) override;

	IntrusivePtr<Val> Eval(Frame* f) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	void ExprDescribe(ODesc* d) const override;

	IntrusivePtr<Expr> func;
	IntrusivePtr<ListExpr> args;
};


/**
 * Class that represents an anonymous function expression in Zeek.
 * On evaluation, captures the frame that it is evaluated in. This becomes
 * the closure for the instance of the function that it creates.
 */
class LambdaExpr : public Expr {
public:
	LambdaExpr(std::unique_ptr<function_ingredients> ingredients,
		   id_list outer_ids);

	IntrusivePtr<Val> Eval(Frame* f) const override;
	TraversalCode Traverse(TraversalCallback* cb) const override;

	Scope* GetScope() const;

protected:
	void ExprDescribe(ODesc* d) const override;

private:
	std::unique_ptr<function_ingredients> ingredients;

	id_list outer_ids;
	std::string my_name;
};

class ListExpr : public Expr {
public:
	ListExpr();
	explicit ListExpr(IntrusivePtr<Expr> e);
	~ListExpr() override;

	void Append(IntrusivePtr<Expr> e);

	const expr_list& Exprs() const	{ return exprs; }
	expr_list& Exprs()		{ return exprs; }

	// True if the entire list represents pure values / reduced expressions.
	bool IsPure() const override;
	bool IsReduced() const override;
	bool HasReducedOps() const override;
	Expr* Reduce(ReductionContext* c, IntrusivePtr<Stmt>& red_stmt) override;

	IntrusivePtr<Val> Eval(Frame* f) const override;

	IntrusivePtr<BroType> InitType() const override;
	IntrusivePtr<Val> InitVal(const BroType* t, IntrusivePtr<Val> aggr) const override;
	IntrusivePtr<Expr> MakeLvalue() override;
	void Assign(Frame* f, IntrusivePtr<Val> v) override;
	IntrusivePtr<Stmt> ReduceToLHS(ReductionContext* c) override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	IntrusivePtr<Val> AddSetInit(const BroType* t, IntrusivePtr<Val> aggr) const;

	void ExprDescribe(ODesc* d) const override;

	expr_list exprs;
};

class EventExpr : public Expr {
public:
	EventExpr(const char* name, IntrusivePtr<ListExpr> args);

	const char* Name() const	{ return name.c_str(); }
	ListExpr* Args() const		{ return args.get(); }
	EventHandlerPtr Handler()  const	{ return handler; }

	IntrusivePtr<Val> Eval(Frame* f) const override;

	bool IsReduced() const override;
	bool HasReducedOps() const override;
	Expr* Reduce(ReductionContext* c, IntrusivePtr<Stmt>& red_stmt) override;

	IntrusivePtr<Expr> GetOp1() const override final	{ return args; }

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	void ExprDescribe(ODesc* d) const override;

	string name;
	EventHandlerPtr handler;
	IntrusivePtr<ListExpr> args;
};


class RecordAssignExpr : public ListExpr {
public:
	RecordAssignExpr(const IntrusivePtr<Expr>& record, const IntrusivePtr<Expr>& init_list, bool is_init);
};

class CastExpr : public UnaryExpr {
public:
	CastExpr(IntrusivePtr<Expr> op, IntrusivePtr<BroType> t);

protected:
	IntrusivePtr<Val> Eval(Frame* f) const override;
	void ExprDescribe(ODesc* d) const override;
};

class IsExpr : public UnaryExpr {
public:
	IsExpr(IntrusivePtr<Expr> op, IntrusivePtr<BroType> t);

protected:
	IntrusivePtr<Val> Fold(Val* v) const override;
	void ExprDescribe(ODesc* d) const override;

private:
	IntrusivePtr<BroType> t;
};

inline Val* Expr::ExprVal() const
	{
	if ( ! IsConst() )
		BadTag("ExprVal::Val", expr_name(tag), expr_name(EXPR_CONST));
	return ((ConstExpr*) this)->Value();
	}

// Decides whether to return an AssignExpr or a RecordAssignExpr.
IntrusivePtr<Expr> get_assign_expr(IntrusivePtr<Expr> op1,
                                   IntrusivePtr<Expr> op2, bool is_init);

// Helper function for making an assignment to an LHS that's
// a temporary.
IntrusivePtr<Expr> get_temp_assign_expr(IntrusivePtr<Expr> op1,
					   IntrusivePtr<Expr> op2);

// Type-check the given expression(s) against the given type(s).  Complain
// if the expression cannot match the given type, returning 0.  If it can
// match, promote it as necessary (modifying the ref parameter accordingly)
// and return 1.
//
// The second, third, and fourth forms are for promoting a list of
// expressions (which is updated in place) to either match a list of
// types or a single type.
//
// Note, the type is not "const" because it can be ref'd.

/**
 * Returns nullptr if the expression cannot match or a promoted
 * expression.
 */
extern IntrusivePtr<Expr> check_and_promote_expr(Expr* e, BroType* t);

extern bool check_and_promote_exprs(ListExpr* elements, TypeList* types);
extern bool check_and_promote_args(ListExpr* args, RecordType* types);
extern bool check_and_promote_exprs_to_type(ListExpr* elements, BroType* type);

// Returns a ListExpr simplified down to a list a values, or nil
// if they couldn't all be reduced.
std::optional<std::vector<IntrusivePtr<Val>>> eval_list(Frame* f, const ListExpr* l);

// Returns true if e1 is "greater" than e2 - here "greater" is just
// a heuristic, used with commutative operators to put them into
// a canonical form.
extern bool expr_greater(const Expr* e1, const Expr* e2);

// Returns true if e1 and e2 are both singletons and further they represent
// equivalent singletons.
extern bool same_singletons(IntrusivePtr<Expr> e1, IntrusivePtr<Expr> e2);

// True if the given Val* has a vector type
inline bool is_vector(Expr* e)	{ return e->Type()->Tag() == TYPE_VECTOR; }
