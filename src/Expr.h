// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>
#include <string>
#include <vector>
#include <utility>
#include <optional>

#include "zeek/ZeekList.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/StmtBase.h"
#include "zeek/Timer.h"
#include "zeek/Type.h"
#include "zeek/EventHandler.h"
#include "zeek/TraverseTypes.h"
#include "zeek/Val.h"
#include "zeek/ZeekArgs.h"

namespace zeek {
template <class T> class IntrusivePtr;

namespace detail {

class Frame;
class Scope;
struct function_ingredients;
using IDPtr = IntrusivePtr<ID>;
using ScopePtr = IntrusivePtr<Scope>;

enum BroExprTag : int {
	EXPR_ANY = -1,
	EXPR_NAME, EXPR_CONST,
	EXPR_CLONE,
	EXPR_INCR, EXPR_DECR,
	EXPR_NOT, EXPR_COMPLEMENT,
	EXPR_POSITIVE, EXPR_NEGATE,
	EXPR_ADD, EXPR_SUB, EXPR_ADD_TO, EXPR_REMOVE_FROM,
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
	EXPR_CAST,
	EXPR_IS,
	EXPR_INDEX_SLICE_ASSIGN,
	EXPR_INLINE,

	// The following types of expressions are only created for
	// ASTs transformed to reduced form; they aren't germane for
	// ASTs produced by parsing .zeek script files.
	EXPR_INDEX_ASSIGN, EXPR_FIELD_LHS_ASSIGN,
	EXPR_APPEND_TO,
	EXPR_TO_ANY_COERCE, EXPR_FROM_ANY_COERCE, EXPR_FROM_ANY_VEC_COERCE,
	EXPR_ANY_INDEX,

	EXPR_NOP,

#define NUM_EXPRS (int(EXPR_NOP) + 1)
};

extern const char* expr_name(BroExprTag t);

class AddToExpr;
class AnyIndexExpr;
class AssignExpr;
class CallExpr;
class ConstExpr;
class EventExpr;
class FieldAssignExpr;
class FieldExpr;
class FieldLHSAssignExpr;
class ForExpr;
class HasFieldExpr;
class IndexAssignExpr;
class IndexExpr;
class InlineExpr;
class IsExpr;
class LambdaExpr;
class ListExpr;
class NameExpr;
class RecordCoerceExpr;
class RecordConstructorExpr;
class RefExpr;
class SetConstructorExpr;
class TableConstructorExpr;

class Expr;
using CallExprPtr = IntrusivePtr<CallExpr>;
using ConstExprPtr = IntrusivePtr<ConstExpr>;
using EventExprPtr = IntrusivePtr<EventExpr>;
using ExprPtr = IntrusivePtr<Expr>;
using NameExprPtr = IntrusivePtr<NameExpr>;
using RefExprPtr = IntrusivePtr<RefExpr>;

class Stmt;
using StmtPtr = IntrusivePtr<Stmt>;

class ExprOptInfo;

class Expr : public Obj {
public:
	const TypePtr& GetType() const
		{ return type; }

	template <class T>
	IntrusivePtr<T> GetType() const
		{ return cast_intrusive<T>(type); }

	BroExprTag Tag() const	{ return tag; }

	Expr* Ref()			{ zeek::Ref(this); return this; }
	ExprPtr ThisPtr()		{ return {NewRef{}, this}; }

	// Evaluates the expression and returns a corresponding Val*,
	// or nil if the expression's value isn't fixed.
	virtual ValPtr Eval(Frame* f) const = 0;

	// Same, but the context is that we are adding an element
	// into the given aggregate of the given type.  Note that
	// return type is void since it's updating an existing
	// value, rather than creating a new one.
	virtual void EvalIntoAggregate(const zeek::Type* t, Val* aggr, Frame* f) const;

	// Assign to the given value, if appropriate.
	virtual void Assign(Frame* f, ValPtr v);

	// Returns the type corresponding to this expression interpreted
	// as an initialization.  Returns nil if the initialization is illegal.
	virtual TypePtr InitType() const;

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
	virtual ValPtr InitVal(const zeek::Type* t, ValPtr aggr) const;

	// True if the expression has no side effects, false otherwise.
	virtual bool IsPure() const;

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
	virtual ExprPtr MakeLvalue();

	// Invert the sense of the operation.  Returns true if the expression
	// was invertible (currently only true for relational/equality
	// expressions), false otherwise.
	virtual bool InvertSense();

	// Marks the expression as one requiring (or at least appearing
	// with) parentheses.  Used for pretty-printing.
	void MarkParen()		{ paren = true; }
	bool IsParen() const		{ return paren; }

#define ZEEK_EXPR_ACCESSOR_DECLS(ctype) \
	const ctype* As ## ctype () const; \
	ctype* As ## ctype (); \
	IntrusivePtr<ctype> As ## ctype ## Ptr ();

	ZEEK_EXPR_ACCESSOR_DECLS(AddToExpr)
	ZEEK_EXPR_ACCESSOR_DECLS(AnyIndexExpr)
	ZEEK_EXPR_ACCESSOR_DECLS(AssignExpr)
	ZEEK_EXPR_ACCESSOR_DECLS(CallExpr)
	ZEEK_EXPR_ACCESSOR_DECLS(ConstExpr)
	ZEEK_EXPR_ACCESSOR_DECLS(EventExpr)
	ZEEK_EXPR_ACCESSOR_DECLS(FieldAssignExpr)
	ZEEK_EXPR_ACCESSOR_DECLS(FieldExpr)
	ZEEK_EXPR_ACCESSOR_DECLS(FieldLHSAssignExpr)
	ZEEK_EXPR_ACCESSOR_DECLS(ForExpr)
	ZEEK_EXPR_ACCESSOR_DECLS(HasFieldExpr)
	ZEEK_EXPR_ACCESSOR_DECLS(IndexAssignExpr)
	ZEEK_EXPR_ACCESSOR_DECLS(IndexExpr)
	ZEEK_EXPR_ACCESSOR_DECLS(InlineExpr)
	ZEEK_EXPR_ACCESSOR_DECLS(IsExpr)
	ZEEK_EXPR_ACCESSOR_DECLS(LambdaExpr)
	ZEEK_EXPR_ACCESSOR_DECLS(ListExpr)
	ZEEK_EXPR_ACCESSOR_DECLS(NameExpr)
	ZEEK_EXPR_ACCESSOR_DECLS(RecordCoerceExpr)
	ZEEK_EXPR_ACCESSOR_DECLS(RecordConstructorExpr)
	ZEEK_EXPR_ACCESSOR_DECLS(RefExpr)
	ZEEK_EXPR_ACCESSOR_DECLS(SetConstructorExpr)
	ZEEK_EXPR_ACCESSOR_DECLS(TableConstructorExpr)

	void Describe(ODesc* d) const override final;

	virtual TraversalCode Traverse(TraversalCallback* cb) const = 0;

	// Returns a duplicate of the expression.
	virtual ExprPtr Duplicate() = 0;

	// Recursively traverses the AST to inline eligible function calls.
	virtual ExprPtr Inline(Inliner* inl)	{ return ThisPtr(); }

	// True if the expression can serve as an operand to a reduced
	// expression.
	bool IsSingleton(Reducer* r) const
		{
		return (tag == EXPR_NAME && IsReduced(r)) || tag == EXPR_CONST;
		}

	// True if the expression has no side effects, false otherwise.
	virtual bool HasNoSideEffects() const	{ return IsPure(); }

	// True if the expression is in fully reduced form: a singleton
	// or an assignment to an operator with singleton operands.
	virtual bool IsReduced(Reducer* c) const;

	// True if the expression's operands are singletons.
	virtual bool HasReducedOps(Reducer* c) const;

	// True if (a) the expression has at least one operand, and (b) all
	// of its operands are constant.
	bool HasConstantOps() const
		{
		return GetOp1() && GetOp1()->IsConst() &&
			(! GetOp2() ||
			 (GetOp2()->IsConst() &&
			  (! GetOp3() || GetOp3()->IsConst())));
		}

	// True if the expression is reduced to a form that can be
	// used in a conditional.
	bool IsReducedConditional(Reducer* c) const;

	// True if the expression is reduced to a form that can be
	// used in a field assignment.
	bool IsReducedFieldAssignment(Reducer* c) const;

	// True if this expression can be the RHS for a field assignment.
	bool IsFieldAssignable(const Expr* e) const;

	// True if the expression will transform to one of another type
	// upon reduction, for non-constant operands.  "Transform" means
	// something beyond assignment to a temporary.  Necessary so that
	// we know to fully reduce such expressions if they're the RHS
	// of an assignment.
	virtual bool WillTransform(Reducer* c) const	{ return false; }

	// The same, but for the expression when used in a conditional context.
	virtual bool WillTransformInConditional(Reducer* c) const
		{ return false; }

	// Returns the current expression transformed into "new_me".
	ExprPtr TransformMe(ExprPtr new_me, Reducer* c, StmtPtr& red_stmt);

	// Returns a set of predecessor statements in red_stmt (which might
	// be nil if no reduction necessary), and the reduced version of
	// the expression, suitable for replacing previous uses.  The
	// second version always yields a singleton suitable for use
	// as an operand.  The first version does this too except
	// for assignment statements; thus, its form is not guarantee
	// suitable for use as an operand.
	virtual ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt);
	virtual ExprPtr ReduceToSingleton(Reducer* c, StmtPtr& red_stmt)
		{ return Reduce(c, red_stmt); }

	// Reduces the expression to one whose operands are singletons.
	// Returns a predecessor statement (which might be a StmtList), if any.
	virtual StmtPtr ReduceToSingletons(Reducer* c);

	// Reduces the expression to one that can appear as a conditional.
	ExprPtr ReduceToConditional(Reducer* c, StmtPtr& red_stmt);

	// Reduces the expression to one that can appear as a field
	// assignment.
	ExprPtr ReduceToFieldAssignment(Reducer* c, StmtPtr& red_stmt);

	// Helper function for factoring out complexities related to
	// index-based assignment.
	void AssignToIndex(ValPtr v1, ValPtr v2, ValPtr v3) const;

	// Returns a new expression corresponding to a temporary
	// that's been assigned to the given expression via red_stmt.
	ExprPtr AssignToTemporary(ExprPtr e, Reducer* c, StmtPtr& red_stmt);
	// Same but for this expression.
	ExprPtr AssignToTemporary(Reducer* c, StmtPtr& red_stmt)
		{ return AssignToTemporary(ThisPtr(), c, red_stmt); }

	// If the expression always evaluates to the same value, returns
	// that value.  Otherwise, returns nullptr.
	virtual ValPtr FoldVal() const	{ return nullptr; }

	// Returns a Val or a constant Expr corresponding to zero.
	ValPtr MakeZero(TypeTag t) const;
	ConstExprPtr MakeZeroExpr(TypeTag t) const;

	// Returns the expression's operands, or nil if it doesn't
	// have the given operand.
	virtual ExprPtr GetOp1() const;
	virtual ExprPtr GetOp2() const;
	virtual ExprPtr GetOp3() const;

	// Sets the operands to new values.
	virtual void SetOp1(ExprPtr new_op);
	virtual void SetOp2(ExprPtr new_op);
	virtual void SetOp3(ExprPtr new_op);

	// Helper function to reduce boring code runs.
	StmtPtr MergeStmts(StmtPtr s1, StmtPtr s2, StmtPtr s3 = nullptr) const;

	// Access to the original expression from which this one is derived,
	// or this one if we don't have an original.  Returns a bare pointer
	// rather than an ExprPtr to emphasize that the access is read-only.
	const Expr* Original() const
		{ return original ? original->Original() : this; }

	// Designate the given Expr node as the original for this one.
	void SetOriginal(ExprPtr _orig)
		{
		if ( ! original )
			original = std::move(_orig);
		}

	// A convenience function for taking a newly-created Expr,
	// making it point to us as the successor, and returning it.
	//
	// Takes an Expr* rather than a ExprPtr to de-clutter the calling
	// code, which is always passing in "new XyzExpr(...)".  This
	// call, as a convenient side effect, transforms that bare pointer
	// into an ExprPtr.
	virtual ExprPtr SetSucc(Expr* succ)
		{
		succ->SetOriginal(ThisPtr());
		if ( IsParen() )
			succ->MarkParen();
		return {AdoptRef{}, succ};
		}

	const detail::Location* GetLocationInfo() const override
		{
		if ( original )
			return original->GetLocationInfo();
		else
			return Obj::GetLocationInfo();
		}

	// Access script optimization information associated with
	// this statement.
	ExprOptInfo* GetOptInfo() const		{ return opt_info; }

	~Expr() override;

protected:
	Expr() = default;
	explicit Expr(BroExprTag arg_tag);

	virtual void ExprDescribe(ODesc* d) const = 0;
	void AddTag(ODesc* d) const;

	// Puts the expression in canonical form.
	virtual void Canonicize();

	void SetType(TypePtr t);

	// Reports the given error and sets the expression's type to
	// TYPE_ERROR.
	void ExprError(const char msg[]);

	// These two functions both call Reporter::RuntimeError or Reporter::ExprRuntimeError,
	// both of which are marked as [[noreturn]].
	[[noreturn]] void RuntimeError(const std::string& msg) const;
	[[noreturn]] void RuntimeErrorWithCallStack(const std::string& msg) const;

	BroExprTag tag;
	bool paren;
	TypePtr type;

	// The original expression from which this statement was
	// derived, if any.  Used as an aid for generating meaningful
	// and correctly-localized error messages.
	ExprPtr original = nullptr;

	// Information associated with the Expr for purposes of
	// script optimization.
	ExprOptInfo* opt_info;
};

class NameExpr final : public Expr {
public:
	explicit NameExpr(IDPtr id, bool const_init = false);

	ID* Id() const		{ return id.get(); }
	const IDPtr& IdPtr() const;

	ValPtr Eval(Frame* f) const override;
	void Assign(Frame* f, ValPtr v) override;
	ExprPtr MakeLvalue() override;
	bool IsPure() const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

	// Optimization-related:
	ExprPtr Duplicate() override;
	bool HasNoSideEffects() const override	{ return true; }
	bool IsReduced(Reducer* c) const override;
	bool HasReducedOps(Reducer* c) const override	{ return IsReduced(c); }
	bool WillTransform(Reducer* c) const override	{ return ! IsReduced(c); }
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
	ValPtr FoldVal() const override;

protected:
	void ExprDescribe(ODesc* d) const override;

	// Returns true if our identifier is a global with a constant value
	// that can be propagated; used for optimization.
	bool FoldableGlobal() const;

	IDPtr id;
	bool in_const_init;
};

class ConstExpr final : public Expr {
public:
	explicit ConstExpr(ValPtr val);

	Val* Value() const	{ return val.get(); }
	ValPtr ValuePtr() const	{ return val; }

	ValPtr Eval(Frame* f) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

	// Optimization-related:
	ExprPtr Duplicate() override;
	ValPtr FoldVal() const override	{ return val; }

protected:
	void ExprDescribe(ODesc* d) const override;
	ValPtr val;
};

class UnaryExpr : public Expr {
public:
	Expr* Op() const	{ return op.get(); }

	// UnaryExpr::Eval correctly handles vector types.  Any child
	// class that overrides Eval() should be modified to handle
	// vectors correctly as necessary.
	ValPtr Eval(Frame* f) const override;

	bool IsPure() const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

	// Optimization-related:
	ExprPtr Inline(Inliner* inl) override;

	bool HasNoSideEffects() const override;
	bool IsReduced(Reducer* c) const override;
	bool HasReducedOps(Reducer* c) const override;
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

	ExprPtr GetOp1() const override final	{ return op; }
	void SetOp1(ExprPtr _op) override final	{ op = std::move(_op); }

protected:
	UnaryExpr(BroExprTag arg_tag, ExprPtr arg_op);

	void ExprDescribe(ODesc* d) const override;

	// Returns the expression folded using the given constant.
	virtual ValPtr Fold(Val* v) const;

	ExprPtr op;
};

class BinaryExpr : public Expr {
public:
	Expr* Op1() const	{ return op1.get(); }
	Expr* Op2() const	{ return op2.get(); }

	bool IsPure() const override;

	// BinaryExpr::Eval correctly handles vector types.  Any child
	// class that overrides Eval() should be modified to handle
	// vectors correctly as necessary.
	ValPtr Eval(Frame* f) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

	// Optimization-related:
	ExprPtr Inline(Inliner* inl) override;

	bool HasNoSideEffects() const override;
	bool IsReduced(Reducer* c) const override;
	bool HasReducedOps(Reducer* c) const override;
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

	ExprPtr GetOp1() const override final	{ return op1; }
	ExprPtr GetOp2() const override final	{ return op2; }

	void SetOp1(ExprPtr _op) override final	{ op1 = std::move(_op); }
	void SetOp2(ExprPtr _op) override final	{ op2 = std::move(_op); }

protected:
	BinaryExpr(BroExprTag arg_tag,
	           ExprPtr arg_op1, ExprPtr arg_op2)
		: Expr(arg_tag), op1(std::move(arg_op1)), op2(std::move(arg_op2))
		{
		if ( ! (op1 && op2) )
			return;
		if ( op1->IsError() || op2->IsError() )
			SetError();
		}

	// Returns the expression folded using the given constants.
	virtual ValPtr Fold(Val* v1, Val* v2) const;

	// Same for when the constants are strings.
	virtual ValPtr StringFold(Val* v1, Val* v2) const;

	// Same for when the constants are patterns.
	virtual ValPtr PatternFold(Val* v1, Val* v2) const;

	// Same for when the constants are sets.
	virtual ValPtr SetFold(Val* v1, Val* v2) const;

	// Same for when the constants are addresses or subnets.
	virtual ValPtr AddrFold(Val* v1, Val* v2) const;
	virtual ValPtr SubNetFold(Val* v1, Val* v2) const;

	bool BothConst() const	{ return op1->IsConst() && op2->IsConst(); }

	// Exchange op1 and op2.
	void SwapOps();

	// Promote the operands to the given type tag, if necessary.
	void PromoteOps(TypeTag t);

	// Promote the expression to the given type tag (i.e., promote
	// operands and also set expression's type).
	void PromoteType(TypeTag t, bool is_vector);

	// Promote one of the operands to be "double" (if not already),
	// to make it suitable for combining with the other "interval"
	// operand, yielding an "interval" type.
	void PromoteForInterval(ExprPtr& op);

	void ExprDescribe(ODesc* d) const override;

	ExprPtr op1;
	ExprPtr op2;
};

class CloneExpr final : public UnaryExpr {
public:
	explicit CloneExpr(ExprPtr op);
	ValPtr Eval(Frame* f) const override;

	// Optimization-related:
	ExprPtr Duplicate() override;

protected:
	ValPtr Fold(Val* v) const override;
};

class IncrExpr final : public UnaryExpr {
public:
	IncrExpr(BroExprTag tag, ExprPtr op);

	ValPtr Eval(Frame* f) const override;
	ValPtr DoSingleEval(Frame* f, Val* v) const;
	bool IsPure() const override;

	// Optimization-related:
	ExprPtr Duplicate() override;
	bool HasNoSideEffects() const override;
	bool WillTransform(Reducer* c) const override	{ return true; }
	bool IsReduced(Reducer* c) const override;
	bool HasReducedOps(Reducer* c) const override	{ return false; }
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
	ExprPtr ReduceToSingleton(Reducer* c, StmtPtr& red_stmt) override;
};

class ComplementExpr final : public UnaryExpr {
public:
	explicit ComplementExpr(ExprPtr op);

	// Optimization-related:
	ExprPtr Duplicate() override;
	bool WillTransform(Reducer* c) const override;
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

protected:
	ValPtr Fold(Val* v) const override;
};

class NotExpr final : public UnaryExpr {
public:
	explicit NotExpr(ExprPtr op);

	// Optimization-related:
	ExprPtr Duplicate() override;
	bool WillTransform(Reducer* c) const override;
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

protected:
	ValPtr Fold(Val* v) const override;
};

class PosExpr final : public UnaryExpr {
public:
	explicit PosExpr(ExprPtr op);

	// Optimization-related:
	ExprPtr Duplicate() override;
	bool WillTransform(Reducer* c) const override;
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

protected:
	ValPtr Fold(Val* v) const override;
};

class NegExpr final : public UnaryExpr {
public:
	explicit NegExpr(ExprPtr op);

	// Optimization-related:
	ExprPtr Duplicate() override;
	bool WillTransform(Reducer* c) const override;
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

protected:
	ValPtr Fold(Val* v) const override;
};

class SizeExpr final : public UnaryExpr {
public:
	explicit SizeExpr(ExprPtr op);
	ValPtr Eval(Frame* f) const override;

	// Optimization-related:
	ExprPtr Duplicate() override;

protected:
	ValPtr Fold(Val* v) const override;
};

class AddExpr final : public BinaryExpr {
public:
	AddExpr(ExprPtr op1, ExprPtr op2);
	void Canonicize() override;

	// Optimization-related:
	ExprPtr Duplicate() override;
	bool WillTransform(Reducer* c) const override;
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

protected:
	ExprPtr BuildSub(const ExprPtr& op1, const ExprPtr& op2);
};

class AddToExpr final : public BinaryExpr {
public:
	AddToExpr(ExprPtr op1, ExprPtr op2);
	ValPtr Eval(Frame* f) const override;

	// Optimization-related:
	ExprPtr Duplicate() override;
	bool WillTransform(Reducer* c) const override	{ return true; }
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
};

class RemoveFromExpr final : public BinaryExpr {
public:
	RemoveFromExpr(ExprPtr op1, ExprPtr op2);
	ValPtr Eval(Frame* f) const override;

	// Optimization-related:
	ExprPtr Duplicate() override;
	bool WillTransform(Reducer* c) const override	{ return true; }
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
};

class SubExpr final : public BinaryExpr {
public:
	SubExpr(ExprPtr op1, ExprPtr op2);

	// Optimization-related:
	ExprPtr Duplicate() override;
	bool WillTransform(Reducer* c) const override;
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
};

class TimesExpr final : public BinaryExpr {
public:
	TimesExpr(ExprPtr op1, ExprPtr op2);
	void Canonicize() override;

	// Optimization-related:
	ExprPtr Duplicate() override;
	bool WillTransform(Reducer* c) const override;
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
};

class DivideExpr final : public BinaryExpr {
public:
	DivideExpr(ExprPtr op1, ExprPtr op2);

	// Optimization-related:
	ExprPtr Duplicate() override;
	bool WillTransform(Reducer* c) const override;
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

protected:
	ValPtr AddrFold(Val* v1, Val* v2) const override;
};

class ModExpr final : public BinaryExpr {
public:
	ModExpr(ExprPtr op1, ExprPtr op2);

	// Optimization-related:
	ExprPtr Duplicate() override;
};

class BoolExpr final : public BinaryExpr {
public:
	BoolExpr(BroExprTag tag, ExprPtr op1, ExprPtr op2);

	ValPtr Eval(Frame* f) const override;
	ValPtr DoSingleEval(Frame* f, ValPtr v1, Expr* op2) const;

	// Optimization-related:
	ExprPtr Duplicate() override;
	bool WillTransform(Reducer* c) const override;
	bool WillTransformInConditional(Reducer* c) const override;
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

protected:
	bool IsTrue(const ExprPtr& e) const;
	bool IsFalse(const ExprPtr& e) const;
};

class BitExpr final : public BinaryExpr {
public:
	BitExpr(BroExprTag tag, ExprPtr op1, ExprPtr op2);

	// Optimization-related:
	ExprPtr Duplicate() override;
	bool WillTransform(Reducer* c) const override;
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
};

class EqExpr final : public BinaryExpr {
public:
	EqExpr(BroExprTag tag, ExprPtr op1, ExprPtr op2);
	void Canonicize() override;

	// Optimization-related:
	ExprPtr Duplicate() override;
	bool WillTransform(Reducer* c) const override;
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
	bool InvertSense() override;

protected:
	ValPtr Fold(Val* v1, Val* v2) const override;
};

class RelExpr final : public BinaryExpr {
public:
	RelExpr(BroExprTag tag, ExprPtr op1, ExprPtr op2);
	void Canonicize() override;

	// Optimization-related:
	ExprPtr Duplicate() override;
	bool WillTransform(Reducer* c) const override;
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
	bool InvertSense() override;
};

class CondExpr final : public Expr {
public:
	CondExpr(ExprPtr op1, ExprPtr op2, ExprPtr op3);

	const Expr* Op1() const	{ return op1.get(); }
	const Expr* Op2() const	{ return op2.get(); }
	const Expr* Op3() const	{ return op3.get(); }

	ValPtr Eval(Frame* f) const override;
	bool IsPure() const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

	// Optimization-related:
	ExprPtr Duplicate() override;
	ExprPtr Inline(Inliner* inl) override;

	bool WillTransform(Reducer* c) const override;
	bool IsReduced(Reducer* c) const override;
	bool HasReducedOps(Reducer* c) const override;
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
	StmtPtr ReduceToSingletons(Reducer* c) override;

	ExprPtr GetOp1() const override final	{ return op1; }
	ExprPtr GetOp2() const override final	{ return op2; }
	ExprPtr GetOp3() const override final	{ return op3; }

	void SetOp1(ExprPtr _op) override final	{ op1 = std::move(_op); }
	void SetOp2(ExprPtr _op) override final	{ op2 = std::move(_op); }
	void SetOp3(ExprPtr _op) override final	{ op3 = std::move(_op); }

protected:
	void ExprDescribe(ODesc* d) const override;

	ExprPtr op1;
	ExprPtr op2;
	ExprPtr op3;
};

class RefExpr final : public UnaryExpr {
public:
	explicit RefExpr(ExprPtr op);

	void Assign(Frame* f, ValPtr v) override;
	ExprPtr MakeLvalue() override;

	// Optimization-related:
	ExprPtr Duplicate() override;

	bool WillTransform(Reducer* c) const override;
	bool IsReduced(Reducer* c) const override;
	bool HasReducedOps(Reducer* c) const override;
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

	// Reduce to simplifed LHS form, i.e., a reference to only a name.
	StmtPtr ReduceToLHS(Reducer* c);
};

class AssignExpr : public BinaryExpr {
public:
	// If val is given, evaluating this expression will always yield the val
	// yet still perform the assignment.  Used for triggers.
	AssignExpr(ExprPtr op1, ExprPtr op2, bool is_init,
	           ValPtr val = nullptr,
	           const AttributesPtr& attrs = nullptr,
		   bool type_check = true);

	ValPtr Eval(Frame* f) const override;
	void EvalIntoAggregate(const zeek::Type* t, Val* aggr, Frame* f) const override;
	TypePtr InitType() const override;
	bool IsRecordElement(TypeDecl* td) const override;
	ValPtr InitVal(const zeek::Type* t, ValPtr aggr) const override;
	bool IsPure() const override;

	// Optimization-related:
	ExprPtr Duplicate() override;

	bool HasNoSideEffects() const override;
	bool WillTransform(Reducer* c) const override	{ return true; }
	bool IsReduced(Reducer* c) const override;
	bool HasReducedOps(Reducer* c) const override;
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
	ExprPtr ReduceToSingleton(Reducer* c, StmtPtr& red_stmt) override;

	// Whether this is an assignment to a temporary.
	bool IsTemp() const	{ return is_temp; }
	void SetIsTemp()	{ is_temp = true; }

protected:
	bool TypeCheck(const AttributesPtr& attrs = nullptr);
	bool TypeCheckArithmetics(TypeTag bt1, TypeTag bt2);

	bool is_init;
	bool is_temp = false; // Optimization related

	ValPtr val;	// optional

};

class IndexSliceAssignExpr final : public AssignExpr {
public:
	IndexSliceAssignExpr(ExprPtr op1,
	                     ExprPtr op2, bool is_init);
	ValPtr Eval(Frame* f) const override;

	// Optimization-related:
	ExprPtr Duplicate() override;
};

class IndexExpr : public BinaryExpr {
public:
	IndexExpr(ExprPtr op1,
	          ListExprPtr op2, bool is_slice = false);

	bool CanAdd() const override;
	bool CanDel() const override;

	void Add(Frame* f) override;
	void Delete(Frame* f) override;

	void Assign(Frame* f, ValPtr v) override;
	ExprPtr MakeLvalue() override;

	// Need to override Eval since it can take a vector arg but does
	// not necessarily return a vector.
	ValPtr Eval(Frame* f) const override;

	bool IsSlice() const { return is_slice; }

	// Optimization-related:
	ExprPtr Duplicate() override;

	bool HasReducedOps(Reducer* c) const override;
	StmtPtr ReduceToSingletons(Reducer* c) override;

protected:
	ValPtr Fold(Val* v1, Val* v2) const override;

	void ExprDescribe(ODesc* d) const override;

	bool is_slice;
};

// The following execute the heart of IndexExpr functionality for
// vector slices and strings.

// Extracts a slice of a vector, where the span of the slice is specified
// by a list of (exactly) two values.  This is how the interpreter develops
// the components of a slice.
extern VectorValPtr index_slice(VectorVal* vect, const ListVal* lv);

// Lower-level access to the slice, where its span is expressed
// directly as integers.
extern VectorValPtr index_slice(VectorVal* vect, int first, int last);

// Returns a subset of a string, with the span specified by a list of
// (exactly) two values.
extern StringValPtr index_string(const String* s, const ListVal* lv);

// Returns a vector indexed by a boolean vector.
extern VectorValPtr vector_bool_select(VectorTypePtr vt, const VectorVal* v1,
                                       const VectorVal* v2);

// Returns a vector indexed by a numeric vector (which specifies the
// indices to select).
extern VectorValPtr vector_int_select(VectorTypePtr vt, const VectorVal* v1,
                                      const VectorVal* v2);

class IndexExprWhen final : public IndexExpr {
public:
	static inline std::vector<ValPtr> results = {};
	static inline int evaluating = 0;

	static void StartEval()
		{ ++evaluating; }

	static void EndEval()
		{ --evaluating; }

	static std::vector<ValPtr> TakeAllResults()
		{
		auto rval = std::move(results);
		results = {};
		return rval;
		}

	IndexExprWhen(ExprPtr op1, ListExprPtr op2, bool is_slice = false)
	    : IndexExpr(std::move(op1), std::move(op2), is_slice)
		{ }

	ValPtr Eval(Frame* f) const override
		{
		auto v = IndexExpr::Eval(f);

		if ( v && evaluating > 0 )
			results.emplace_back(v);

		return v;
		}

	// Optimization-related:
	ExprPtr Duplicate() override;
};

class FieldExpr final : public UnaryExpr {
public:
	FieldExpr(ExprPtr op, const char* field_name);
	~FieldExpr() override;

	int Field() const	{ return field; }
	const char* FieldName() const	{ return field_name; }

	bool CanDel() const override;

	void Assign(Frame* f, ValPtr v) override;
	void Delete(Frame* f) override;

	ExprPtr MakeLvalue() override;

	// Optimization-related:
	ExprPtr Duplicate() override;

protected:
	ValPtr Fold(Val* v) const override;

	void ExprDescribe(ODesc* d) const override;

	const char* field_name;
	const TypeDecl* td;
	int field; // -1 = attributes
};

// "rec?$fieldname" is true if the value of $fieldname in rec is not nil.
// "rec?$$attrname" is true if the attribute attrname is not nil.
class HasFieldExpr final : public UnaryExpr {
public:
	HasFieldExpr(ExprPtr op, const char* field_name);
	~HasFieldExpr() override;

	const char* FieldName() const	{ return field_name; }
	int Field() const		{ return field; }

	// Optimization-related:
	ExprPtr Duplicate() override;

protected:
	ValPtr Fold(Val* v) const override;

	void ExprDescribe(ODesc* d) const override;

	const char* field_name;
	int field;
};

class RecordConstructorExpr final : public Expr {
public:
	explicit RecordConstructorExpr(ListExprPtr constructor_list);

        // This form is used to construct records of a known (ultimate) type.
	explicit RecordConstructorExpr(RecordTypePtr known_rt,
	                               ListExprPtr constructor_list);

	ListExprPtr Op() const    { return op; }
	const auto& Map() const	{ return map; }

	ValPtr Eval(Frame* f) const override;

	bool IsPure() const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

	// Optimization-related:
	ExprPtr Duplicate() override;

	bool HasReducedOps(Reducer* c) const override;
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
	StmtPtr ReduceToSingletons(Reducer* c) override;

protected:
	ValPtr InitVal(const zeek::Type* t, ValPtr aggr) const override;

	void ExprDescribe(ODesc* d) const override;

	ListExprPtr op;
	std::optional<std::vector<int>> map;
};

class TableConstructorExpr final : public UnaryExpr {
public:
	TableConstructorExpr(ListExprPtr constructor_list,
	                     std::unique_ptr<std::vector<AttrPtr>> attrs,
	                     TypePtr arg_type = nullptr,
	                     AttributesPtr arg_attrs = nullptr);

	const AttributesPtr& GetAttrs() const
		{ return attrs; }

	ValPtr Eval(Frame* f) const override;

	// Optimization-related:
	ExprPtr Duplicate() override;

	bool HasReducedOps(Reducer* c) const override;
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
	StmtPtr ReduceToSingletons(Reducer* c) override;

protected:
	ValPtr InitVal(const zeek::Type* t, ValPtr aggr) const override;

	void ExprDescribe(ODesc* d) const override;

	AttributesPtr attrs;
};

class SetConstructorExpr final : public UnaryExpr {
public:
	SetConstructorExpr(ListExprPtr constructor_list,
	                   std::unique_ptr<std::vector<AttrPtr>> attrs,
	                   TypePtr arg_type = nullptr,
			   AttributesPtr arg_attrs = nullptr);

	const AttributesPtr& GetAttrs() const
		{ return attrs; }

	ValPtr Eval(Frame* f) const override;

	// Optimization-related:
	ExprPtr Duplicate() override;

	bool HasReducedOps(Reducer* c) const override;
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
	StmtPtr ReduceToSingletons(Reducer* c) override;

protected:
	ValPtr InitVal(const zeek::Type* t, ValPtr aggr) const override;

	void ExprDescribe(ODesc* d) const override;

	AttributesPtr attrs;
};

class VectorConstructorExpr final : public UnaryExpr {
public:
	explicit VectorConstructorExpr(ListExprPtr constructor_list,
	                               TypePtr arg_type = nullptr);

	ValPtr Eval(Frame* f) const override;

	// Optimization-related:
	ExprPtr Duplicate() override;

	bool HasReducedOps(Reducer* c) const override;

protected:
	ValPtr InitVal(const zeek::Type* t, ValPtr aggr) const override;

	void ExprDescribe(ODesc* d) const override;
};

class FieldAssignExpr final : public UnaryExpr {
public:
	FieldAssignExpr(const char* field_name, ExprPtr value);

	const char* FieldName() const	{ return field_name.c_str(); }

	// When these are first constructed, we don't know the type.
	// The following method coerces/promotes the assignment expression
	// as needed, once we do know the type.
	//
	// Returns true on success, false if the types were incompatible
	// (in which case an error is reported).
	bool PromoteTo(TypePtr t);

	void EvalIntoAggregate(const zeek::Type* t, Val* aggr, Frame* f) const override;
	bool IsRecordElement(TypeDecl* td) const override;

	// Optimization-related:
	ExprPtr Duplicate() override;

	bool WillTransform(Reducer* c) const override	{ return true; }
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

protected:
	void ExprDescribe(ODesc* d) const override;

	std::string field_name;
};

class ArithCoerceExpr final : public UnaryExpr {
public:
	ArithCoerceExpr(ExprPtr op, TypeTag t);

	// Optimization-related:
	ExprPtr Duplicate() override;

	bool WillTransform(Reducer* c) const override;
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

protected:
	ValPtr FoldSingleVal(ValPtr v, const TypePtr& t) const;
	ValPtr Fold(Val* v) const override;
};

class RecordCoerceExpr final : public UnaryExpr {
public:
	RecordCoerceExpr(ExprPtr op, RecordTypePtr r);

	// Optimization-related:
	ExprPtr Duplicate() override;

	const std::vector<int>& Map() const	{ return map; }

protected:
	ValPtr InitVal(const zeek::Type* t, ValPtr aggr) const override;
	ValPtr Fold(Val* v) const override;

	// For each super-record slot, gives subrecord slot with which to
	// fill it.
	std::vector<int> map;
};

extern RecordValPtr coerce_to_record(RecordTypePtr rt, Val* v,
					const std::vector<int>& map);

class TableCoerceExpr final : public UnaryExpr {
public:
	TableCoerceExpr(ExprPtr op, TableTypePtr r);
	~TableCoerceExpr() override;

	// Optimization-related:
	ExprPtr Duplicate() override;

protected:
	ValPtr Fold(Val* v) const override;
};

class VectorCoerceExpr final : public UnaryExpr {
public:
	VectorCoerceExpr(ExprPtr op, VectorTypePtr v);
	~VectorCoerceExpr() override;

	// Optimization-related:
	ExprPtr Duplicate() override;

protected:
	ValPtr Fold(Val* v) const override;
};

class ScheduleTimer final : public Timer {
public:
	ScheduleTimer(const EventHandlerPtr& event, zeek::Args args, double t);
	~ScheduleTimer() override;

	void Dispatch(double t, bool is_expire) override;

protected:
	EventHandlerPtr event;
	zeek::Args args;
};

class ScheduleExpr final : public Expr {
public:
	ScheduleExpr(ExprPtr when, EventExprPtr event);

	bool IsPure() const override;

	ValPtr Eval(Frame* f) const override;

	Expr* When() const	{ return when.get(); }
	EventExpr* Event() const	{ return event.get(); }

	TraversalCode Traverse(TraversalCallback* cb) const override;

	// Optimization-related:
	ExprPtr Duplicate() override;
	ExprPtr Inline(Inliner* inl) override;

	bool IsReduced(Reducer* c) const override;
	bool HasReducedOps(Reducer* c) const override;
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

	ExprPtr GetOp1() const override final;
	ExprPtr GetOp2() const override final;

	void SetOp1(ExprPtr _op) override final;
	void SetOp2(ExprPtr _op) override final;

protected:
	void ExprDescribe(ODesc* d) const override;

	ExprPtr when;
	EventExprPtr event;
};

class InExpr final : public BinaryExpr {
public:
	InExpr(ExprPtr op1, ExprPtr op2);

	// Optimization-related:
	ExprPtr Duplicate() override;

	bool HasReducedOps(Reducer* c) const override;

protected:
	ValPtr Fold(Val* v1, Val* v2) const override;

};

class CallExpr final : public Expr {
public:
	CallExpr(ExprPtr func, ListExprPtr args,
	         bool in_hook = false);

	Expr* Func() const	{ return func.get(); }
	ListExpr* Args() const	{ return args.get(); }
	ListExprPtr ArgsPtr() const	{ return args; }

	bool IsPure() const override;

	ValPtr Eval(Frame* f) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

	// Optimization-related:
	ExprPtr Duplicate() override;
	ExprPtr Inline(Inliner* inl) override;

	bool IsReduced(Reducer* c) const override;
	bool HasReducedOps(Reducer* c) const override;
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
	StmtPtr ReduceToSingletons(Reducer* c) override;

protected:
	void ExprDescribe(ODesc* d) const override;

	ExprPtr func;
	ListExprPtr args;
};


/**
 * Class that represents an anonymous function expression in Zeek.
 * On evaluation, captures the frame that it is evaluated in. This becomes
 * the closure for the instance of the function that it creates.
 */
class LambdaExpr final : public Expr {
public:
	LambdaExpr(std::unique_ptr<function_ingredients> ingredients,
	           IDPList outer_ids);

	const std::string& Name() const	{ return my_name; }
	const IDPList& OuterIDs() const	{ return outer_ids; }
	const function_ingredients& Ingredients() const	{ return *ingredients; }

	ValPtr Eval(Frame* f) const override;
	TraversalCode Traverse(TraversalCallback* cb) const override;

	ScopePtr GetScope() const;

	// Optimization-related:
	ExprPtr Duplicate() override;
	ExprPtr Inline(Inliner* inl) override;

	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

protected:
	void ExprDescribe(ODesc* d) const override;

private:
	void CheckCaptures();

	std::unique_ptr<function_ingredients> ingredients;

	IDPList outer_ids;
	bool capture_by_ref;	// if true, use deprecated reference semantics

	std::string my_name;
};

// This comes before EventExpr so that EventExpr::GetOp1 can return its
// arguments as convertible to ExprPtr.
class ListExpr : public Expr {
public:
	ListExpr();
	explicit ListExpr(ExprPtr e);
	~ListExpr() override;

	void Append(ExprPtr e);

	const ExprPList& Exprs() const	{ return exprs; }
	ExprPList& Exprs()		{ return exprs; }

	// True if the entire list represents pure values.
	bool IsPure() const override;

	ValPtr Eval(Frame* f) const override;

	TypePtr InitType() const override;
	ValPtr InitVal(const zeek::Type* t, ValPtr aggr) const override;
	ExprPtr MakeLvalue() override;
	void Assign(Frame* f, ValPtr v) override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

	// Optimization-related:
	ExprPtr Duplicate() override;
	ExprPtr Inline(Inliner* inl) override;

	bool IsReduced(Reducer* c) const override;
	bool HasReducedOps(Reducer* c) const override;
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
	StmtPtr ReduceToSingletons(Reducer* c) override;

protected:
	ValPtr AddSetInit(const zeek::Type* t, ValPtr aggr) const;

	void ExprDescribe(ODesc* d) const override;

	ExprPList exprs;
};

class EventExpr final : public Expr {
public:
	EventExpr(const char* name, ListExprPtr args);

	const char* Name() const	{ return name.c_str(); }
	ListExpr* Args() const		{ return args.get(); }
	EventHandlerPtr Handler()  const	{ return handler; }

	ValPtr Eval(Frame* f) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

	// Optimization-related:
	ExprPtr Duplicate() override;
	ExprPtr Inline(Inliner* inl) override;

	bool IsReduced(Reducer* c) const override;
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
	StmtPtr ReduceToSingletons(Reducer* c) override;

	ExprPtr GetOp1() const override final	{ return args; }
	void SetOp1(ExprPtr _op) override final
		{ args = {NewRef{}, _op->AsListExpr()}; }

protected:
	void ExprDescribe(ODesc* d) const override;

	std::string name;
	EventHandlerPtr handler;
	ListExprPtr args;
};


class RecordAssignExpr final : public ListExpr {
public:
	RecordAssignExpr(const ExprPtr& record, const ExprPtr& init_list, bool is_init);
};

class CastExpr final : public UnaryExpr {
public:
	CastExpr(ExprPtr op, TypePtr t);

	// Optimization-related:
	ExprPtr Duplicate() override;

protected:
	ValPtr Fold(Val* v) const override;
	void ExprDescribe(ODesc* d) const override;
};

// Returns the value 'v' cast to type 't'.  On an error, returns nil
// and populates "error" with an error message.
extern ValPtr cast_value(ValPtr v, const TypePtr& t, std::string& error);

class IsExpr final : public UnaryExpr {
public:
	IsExpr(ExprPtr op, TypePtr t);

	const TypePtr& TestType() const	{ return t; }

	// Optimization-related:
	ExprPtr Duplicate() override;

protected:
	ValPtr Fold(Val* v) const override;
	void ExprDescribe(ODesc* d) const override;

private:
	TypePtr t;
};


class InlineExpr : public Expr {
public:
	InlineExpr(ListExprPtr arg_args, std::vector<IDPtr> params, StmtPtr body,
	           int frame_offset, TypePtr ret_type);

	bool IsPure() const override;

	ListExprPtr Args() const	{ return args; }
	StmtPtr Body() const		{ return body; }

	ValPtr Eval(Frame* f) const override;

	ExprPtr Duplicate() override;

	bool IsReduced(Reducer* c) const override;
	bool HasReducedOps(Reducer* c) const override	{ return false; }
	bool WillTransform(Reducer* c) const override	{ return true; }
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	void ExprDescribe(ODesc* d) const override;

	std::vector<IDPtr> params;
	int frame_offset;
	ListExprPtr args;
	StmtPtr body;
};

// A companion to AddToExpr that's for vector-append, instantiated during
// the reduction process.
class AppendToExpr : public BinaryExpr {
public:
	AppendToExpr(ExprPtr op1, ExprPtr op2);
	ValPtr Eval(Frame* f) const override;

	bool IsReduced(Reducer* c) const override;
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

	ExprPtr Duplicate() override;
};

// An internal class for reduced form.
class IndexAssignExpr : public BinaryExpr {
public:
	// "op1[op2] = op3", all reduced.
	IndexAssignExpr(ExprPtr op1, ExprPtr op2, ExprPtr op3);

	ValPtr Eval(Frame* f) const override;

	ExprPtr Duplicate() override;

	bool IsReduced(Reducer* c) const override;
	bool HasReducedOps(Reducer* c) const override;
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
	ExprPtr ReduceToSingleton(Reducer* c, StmtPtr& red_stmt) override;

	ExprPtr GetOp3() const override final	{ return op3; }
	void SetOp3(ExprPtr _op) override final { op3 = std::move(_op); }

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	void ExprDescribe(ODesc* d) const override;

	ExprPtr op3;	// assignment RHS
};

// An internal class for reduced form.
class FieldLHSAssignExpr : public BinaryExpr {
public:
	// "op1$field = RHS", where RHS is reduced with respect to
	// ReduceToFieldAssignment().
	FieldLHSAssignExpr(ExprPtr op1, ExprPtr op2, const char* field_name,
				int field);

	const char* FieldName() const	{ return field_name; }
	int Field() const		{ return field; }

	ValPtr Eval(Frame* f) const override;

	ExprPtr Duplicate() override;

	bool IsReduced(Reducer* c) const override;
	bool HasReducedOps(Reducer* c) const override;
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
	ExprPtr ReduceToSingleton(Reducer* c, StmtPtr& red_stmt) override;

protected:
	void ExprDescribe(ODesc* d) const override;

	const char* field_name;
	int field;
};

// Expression to explicitly capture conversion to an "any" type, rather
// than it occurring implicitly during script interpretation.
class CoerceToAnyExpr : public UnaryExpr {
public:
	CoerceToAnyExpr(ExprPtr op);

protected:
	ValPtr Fold(Val* v) const override;

	ExprPtr Duplicate() override;
};

// Same, but for conversion from an "any" type.
class CoerceFromAnyExpr : public UnaryExpr {
public:
	CoerceFromAnyExpr(ExprPtr op, TypePtr to_type);

protected:
	ValPtr Fold(Val* v) const override;

	ExprPtr Duplicate() override;
};

// ... and for conversion from a "vector of any" type.
class CoerceFromAnyVecExpr : public UnaryExpr {
public:
	// to_type is yield type, not VectorType.
	CoerceFromAnyVecExpr(ExprPtr op, TypePtr to_type);

	// Can't use UnaryExpr's Eval() because it will do folding
	// over the individual vector elements.
	ValPtr Eval(Frame* f) const override;

protected:
	ExprPtr Duplicate() override;
};

// Expression used to explicitly capture [a, b, c, ...] = x assignments.
class AnyIndexExpr : public UnaryExpr {
public:
	AnyIndexExpr(ExprPtr op, int index);

	int Index() const	{ return index; }

protected:
	ValPtr Fold(Val* v) const override;

	void ExprDescribe(ODesc* d) const override;

	ExprPtr Duplicate() override;
	ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

	int index;
};

// Used internally for optimization, when a placeholder is needed.
class NopExpr : public Expr {
public:
	explicit NopExpr() : Expr(EXPR_NOP) { }

	ValPtr Eval(Frame* f) const override;

	ExprPtr Duplicate() override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	void ExprDescribe(ODesc* d) const override;
};


// Assigns v1[v2] = v3.  Returns an error message, or nullptr on success.
// Factored out so that compiled code can call it as well as the interpreter.
extern const char* assign_to_index(ValPtr v1, ValPtr v2, ValPtr v3,
					bool& iterators_invalidated);


inline Val* Expr::ExprVal() const
	{
	if ( ! IsConst() )
		BadTag("ExprVal::Val", expr_name(tag), expr_name(EXPR_CONST));
	return ((ConstExpr*) this)->Value();
	}

// Decides whether to return an AssignExpr or a RecordAssignExpr.
ExprPtr get_assign_expr(
	ExprPtr op1,
	ExprPtr op2, bool is_init);

/**
 * Type-check the given expression(s) against the given type(s).  Complain
 * if the expression cannot match the given type, returning nullptr;
 * otherwise, returns an expression reflecting the promotion.
 *
 * The second, third, and fourth forms are for promoting a list of
 * expressions (which is updated in place) to either match a list of
 * types or a single type.
 *
 * Note, the type is not "const" because it can be ref'd.
 */
extern ExprPtr check_and_promote_expr(ExprPtr e, TypePtr t);

extern bool check_and_promote_exprs(ListExpr* elements, TypeList* types);
extern bool check_and_promote_args(ListExpr* args, const RecordType* types);
extern bool check_and_promote_exprs_to_type(ListExpr* elements, TypePtr type);

// Returns a ListExpr simplified down to a list a values, or nil
// if they couldn't all be reduced.
std::optional<std::vector<ValPtr>> eval_list(Frame* f, const ListExpr* l);

// Returns true if e1 is "greater" than e2 - here "greater" is just
// a heuristic, used with commutative operators to put them into
// a canonical form.
extern bool expr_greater(const Expr* e1, const Expr* e2);

// True if the given Expr* has a vector type
inline bool is_vector(Expr* e)	{ return e->GetType()->Tag() == TYPE_VECTOR; }
inline bool is_vector(const ExprPtr& e)	{ return is_vector(e.get()); }

} // namespace detail
} // namespace zeek
