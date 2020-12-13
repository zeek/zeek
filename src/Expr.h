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

ZEEK_FORWARD_DECLARE_NAMESPACED(Frame, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(Scope, zeek::detail);

namespace zeek::detail { struct function_ingredients; }
using function_ingredients [[deprecated("Remove in v4.1. Use zeek::detail::function_ingredients.")]] = zeek::detail::function_ingredients;

namespace zeek {
template <class T> class IntrusivePtr;

namespace detail {

using IDPtr = IntrusivePtr<ID>;

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
	EXPR_NOP,

#define NUM_EXPRS (int(EXPR_NOP) + 1)
};

extern const char* expr_name(BroExprTag t);

class ListExpr;
class NameExpr;
class ConstExpr;
class IndexExpr;
class AssignExpr;
class CallExpr;
class EventExpr;
class Stmt;

class Expr;
using ExprPtr = IntrusivePtr<Expr>;
using EventExprPtr = IntrusivePtr<EventExpr>;
using StmtPtr = IntrusivePtr<Stmt>;

class Expr : public Obj {
public:
	[[deprecated("Remove in v4.1.  Use GetType().")]]
	zeek::Type* Type() const		{ return type.get(); }

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

	// Marks the expression as one requiring (or at least appearing
	// with) parentheses.  Used for pretty-printing.
	void MarkParen()		{ paren = true; }
	bool IsParen() const		{ return paren; }

#define ZEEK_EXPR_ACCESSOR_DECLS(ctype) \
	const ctype* As ## ctype () const; \
	ctype* As ## ctype (); \
	IntrusivePtr<ctype> As ## ctype ## Ptr ();

	ZEEK_EXPR_ACCESSOR_DECLS(ListExpr)
	ZEEK_EXPR_ACCESSOR_DECLS(NameExpr)
	ZEEK_EXPR_ACCESSOR_DECLS(ConstExpr)
	ZEEK_EXPR_ACCESSOR_DECLS(CallExpr)
	ZEEK_EXPR_ACCESSOR_DECLS(AssignExpr)
	ZEEK_EXPR_ACCESSOR_DECLS(IndexExpr)
	ZEEK_EXPR_ACCESSOR_DECLS(EventExpr)

	void Describe(ODesc* d) const override final;

	virtual TraversalCode Traverse(TraversalCallback* cb) const = 0;

	// Returns a duplicate of the expression.
	virtual ExprPtr Duplicate() = 0;

	// Recursively traverses the AST to inline eligible function calls.
	virtual ExprPtr Inline(Inliner* inl)	{ return ThisPtr(); }

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
	TypePtr type;
	bool paren;

	// The original expression from which this statement was
	// derived, if any.  Used as an aid for generating meaningful
	// and correctly-localized error messages.
	ExprPtr original = nullptr;
};

class NameExpr final : public Expr {
public:
	explicit NameExpr(IDPtr id, bool const_init = false);

	ID* Id() const		{ return id.get(); }

	ValPtr Eval(Frame* f) const override;
	void Assign(Frame* f, ValPtr v) override;
	ExprPtr MakeLvalue() override;
	bool IsPure() const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

	// Optimization-related:
	ExprPtr Duplicate() override;

protected:
	void ExprDescribe(ODesc* d) const override;

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
};

class ComplementExpr final : public UnaryExpr {
public:
	explicit ComplementExpr(ExprPtr op);

	// Optimization-related:
	ExprPtr Duplicate() override;

protected:
	ValPtr Fold(Val* v) const override;
};

class NotExpr final : public UnaryExpr {
public:
	explicit NotExpr(ExprPtr op);

	// Optimization-related:
	ExprPtr Duplicate() override;

protected:
	ValPtr Fold(Val* v) const override;
};

class PosExpr final : public UnaryExpr {
public:
	explicit PosExpr(ExprPtr op);

	// Optimization-related:
	ExprPtr Duplicate() override;

protected:
	ValPtr Fold(Val* v) const override;
};

class NegExpr final : public UnaryExpr {
public:
	explicit NegExpr(ExprPtr op);

	// Optimization-related:
	ExprPtr Duplicate() override;

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
};

class AddToExpr final : public BinaryExpr {
public:
	AddToExpr(ExprPtr op1, ExprPtr op2);
	ValPtr Eval(Frame* f) const override;

	// Optimization-related:
	ExprPtr Duplicate() override;
};

class RemoveFromExpr final : public BinaryExpr {
public:
	RemoveFromExpr(ExprPtr op1, ExprPtr op2);
	ValPtr Eval(Frame* f) const override;

	// Optimization-related:
	ExprPtr Duplicate() override;
};

class SubExpr final : public BinaryExpr {
public:
	SubExpr(ExprPtr op1, ExprPtr op2);

	// Optimization-related:
	ExprPtr Duplicate() override;
};

class TimesExpr final : public BinaryExpr {
public:
	TimesExpr(ExprPtr op1, ExprPtr op2);
	void Canonicize() override;

	// Optimization-related:
	ExprPtr Duplicate() override;
};

class DivideExpr final : public BinaryExpr {
public:
	DivideExpr(ExprPtr op1, ExprPtr op2);

	// Optimization-related:
	ExprPtr Duplicate() override;

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
};

class BitExpr final : public BinaryExpr {
public:
	BitExpr(BroExprTag tag, ExprPtr op1, ExprPtr op2);

	// Optimization-related:
	ExprPtr Duplicate() override;
};

class EqExpr final : public BinaryExpr {
public:
	EqExpr(BroExprTag tag, ExprPtr op1, ExprPtr op2);
	void Canonicize() override;

	// Optimization-related:
	ExprPtr Duplicate() override;

protected:
	ValPtr Fold(Val* v1, Val* v2) const override;
};

class RelExpr final : public BinaryExpr {
public:
	RelExpr(BroExprTag tag, ExprPtr op1, ExprPtr op2);
	void Canonicize() override;

	// Optimization-related:
	ExprPtr Duplicate() override;
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
};

class AssignExpr : public BinaryExpr {
public:
	// If val is given, evaluating this expression will always yield the val
	// yet still perform the assignment.  Used for triggers.
	AssignExpr(ExprPtr op1, ExprPtr op2, bool is_init,
	           ValPtr val = nullptr,
	           const AttributesPtr& attrs = nullptr);

	ValPtr Eval(Frame* f) const override;
	void EvalIntoAggregate(const zeek::Type* t, Val* aggr, Frame* f) const override;
	TypePtr InitType() const override;
	bool IsRecordElement(TypeDecl* td) const override;
	ValPtr InitVal(const zeek::Type* t, ValPtr aggr) const override;
	bool IsPure() const override;

	void SetOp2(ExprPtr e)
		{
		op2 = std::move(e);
		}

	// Optimization-related:
	ExprPtr Duplicate() override;

protected:
	bool TypeCheck(const AttributesPtr& attrs = nullptr);
	bool TypeCheckArithmetics(TypeTag bt1, TypeTag bt2);

	bool is_init;
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

	TraversalCode Traverse(TraversalCallback* cb) const override;

	bool IsSlice() const { return is_slice; }

	// Optimization-related:
	ExprPtr Duplicate() override;

protected:
	ValPtr Fold(Val* v1, Val* v2) const override;

	void ExprDescribe(ODesc* d) const override;

	bool is_slice;
};

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
	~RecordConstructorExpr() override;

	ListExpr* Op() const	{ return op.get(); }

	ValPtr Eval(Frame* f) const override;

	bool IsPure() const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

	// Optimization-related:
	ExprPtr Duplicate() override;

protected:
	ValPtr InitVal(const zeek::Type* t, ValPtr aggr) const override;

	void ExprDescribe(ODesc* d) const override;

	ListExprPtr op;
};

class TableConstructorExpr final : public UnaryExpr {
public:
	TableConstructorExpr(ListExprPtr constructor_list,
	                     std::unique_ptr<std::vector<AttrPtr>> attrs,
	                     TypePtr arg_type = nullptr,
	                     AttributesPtr arg_attrs = nullptr);

	[[deprecated("Remove in v4.1.  Use GetAttrs().")]]
	Attributes* Attrs() { return attrs.get(); }

	const AttributesPtr& GetAttrs() const
		{ return attrs; }

	ValPtr Eval(Frame* f) const override;

	// Optimization-related:
	ExprPtr Duplicate() override;

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

	[[deprecated("Remove in v4.1.  Use GetAttrs().")]]
	Attributes* Attrs() { return attrs.get(); }

	const AttributesPtr& GetAttrs() const
		{ return attrs; }

	ValPtr Eval(Frame* f) const override;

	// Optimization-related:
	ExprPtr Duplicate() override;

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

protected:
	ValPtr InitVal(const zeek::Type* t, ValPtr aggr) const override;

	void ExprDescribe(ODesc* d) const override;
};

class FieldAssignExpr final : public UnaryExpr {
public:
	FieldAssignExpr(const char* field_name, ExprPtr value);

	const char* FieldName() const	{ return field_name.c_str(); }

	void EvalIntoAggregate(const zeek::Type* t, Val* aggr, Frame* f) const override;
	bool IsRecordElement(TypeDecl* td) const override;

	// Optimization-related:
	ExprPtr Duplicate() override;

protected:
	void ExprDescribe(ODesc* d) const override;

	std::string field_name;
};

class ArithCoerceExpr final : public UnaryExpr {
public:
	ArithCoerceExpr(ExprPtr op, TypeTag t);

	// Optimization-related:
	ExprPtr Duplicate() override;

protected:
	ValPtr FoldSingleVal(Val* v, InternalTypeTag t) const;
	ValPtr Fold(Val* v) const override;
};

class RecordCoerceExpr final : public UnaryExpr {
public:
	RecordCoerceExpr(ExprPtr op, RecordTypePtr r);
	~RecordCoerceExpr() override;

	// Optimization-related:
	ExprPtr Duplicate() override;

protected:
	ValPtr InitVal(const zeek::Type* t, ValPtr aggr) const override;
	ValPtr Fold(Val* v) const override;

	// For each super-record slot, gives subrecord slot with which to
	// fill it.
	int* map;
	int map_size;	// equivalent to Type()->AsRecordType()->NumFields()
};

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

protected:
	ValPtr Fold(Val* v1, Val* v2) const override;

};

class CallExpr final : public Expr {
public:
	CallExpr(ExprPtr func, ListExprPtr args,
	         bool in_hook = false);

	Expr* Func() const	{ return func.get(); }
	ListExpr* Args() const	{ return args.get(); }

	bool IsPure() const override;

	ValPtr Eval(Frame* f) const override;

	TraversalCode Traverse(TraversalCallback* cb) const override;

	// Optimization-related:
	ExprPtr Duplicate() override;
	ExprPtr Inline(Inliner* inl) override;

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

	ValPtr Eval(Frame* f) const override;
	TraversalCode Traverse(TraversalCallback* cb) const override;

	Scope* GetScope() const;

	// Optimization-related:
	ExprPtr Duplicate() override;
	ExprPtr Inline(Inliner* inl) override;

protected:
	void ExprDescribe(ODesc* d) const override;

private:
	std::unique_ptr<function_ingredients> ingredients;

	IDPList outer_ids;
	std::string my_name;
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

protected:
	void ExprDescribe(ODesc* d) const override;

	std::string name;
	EventHandlerPtr handler;
	ListExprPtr args;
};

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

protected:
	ValPtr AddSetInit(const zeek::Type* t, ValPtr aggr) const;

	void ExprDescribe(ODesc* d) const override;

	ExprPList exprs;
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
	ValPtr Eval(Frame* f) const override;
	void ExprDescribe(ODesc* d) const override;
};

class IsExpr final : public UnaryExpr {
public:
	IsExpr(ExprPtr op, TypePtr t);

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

	TraversalCode Traverse(TraversalCallback* cb) const override;

protected:
	void ExprDescribe(ODesc* d) const override;

	std::vector<IDPtr> params;
	int frame_offset;
	ListExprPtr args;
	StmtPtr body;
};


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
extern ExprPtr check_and_promote_expr(Expr* e, Type* t);

extern bool check_and_promote_exprs(ListExpr* elements, TypeList* types);
extern bool check_and_promote_args(ListExpr* args, RecordType* types);
extern bool check_and_promote_exprs_to_type(ListExpr* elements, Type* type);

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

using Expr [[deprecated("Remove in v4.1. Use zeek::detail::Expr instead.")]] = zeek::detail::Expr;
using NameExpr [[deprecated("Remove in v4.1. Use zeek::detail::NameExpr instead.")]] = zeek::detail::NameExpr;
using ConstExpr [[deprecated("Remove in v4.1. Use zeek::detail::ConstExpr instead.")]] = zeek::detail::ConstExpr;
using UnaryExpr [[deprecated("Remove in v4.1. Use zeek::detail::UnaryExpr instead.")]] = zeek::detail::UnaryExpr;
using BinaryExpr [[deprecated("Remove in v4.1. Use zeek::detail::BinaryExpr instead.")]] = zeek::detail::BinaryExpr;
using CloneExpr [[deprecated("Remove in v4.1. Use zeek::detail::CloneExpr instead.")]] = zeek::detail::CloneExpr;
using IncrExpr [[deprecated("Remove in v4.1. Use zeek::detail::IncrExpr instead.")]] = zeek::detail::IncrExpr;
using ComplementExpr [[deprecated("Remove in v4.1. Use zeek::detail::ComplementExpr instead.")]] = zeek::detail::ComplementExpr;
using NotExpr [[deprecated("Remove in v4.1. Use zeek::detail::NotExpr instead.")]] = zeek::detail::NotExpr;
using PosExpr [[deprecated("Remove in v4.1. Use zeek::detail::PosExpr instead.")]] = zeek::detail::PosExpr;
using NegExpr [[deprecated("Remove in v4.1. Use zeek::detail::NegExpr instead.")]] = zeek::detail::NegExpr;
using SizeExpr [[deprecated("Remove in v4.1. Use zeek::detail::SizeExpr instead.")]] = zeek::detail::SizeExpr;
using AddExpr [[deprecated("Remove in v4.1. Use zeek::detail::AddExpr instead.")]] = zeek::detail::AddExpr;
using AddToExpr [[deprecated("Remove in v4.1. Use zeek::detail::AddToExpr instead.")]] = zeek::detail::AddToExpr;
using RemoveFromExpr [[deprecated("Remove in v4.1. Use zeek::detail::RemoveFromExpr instead.")]] = zeek::detail::RemoveFromExpr;
using SubExpr [[deprecated("Remove in v4.1. Use zeek::detail::SubExpr instead.")]] = zeek::detail::SubExpr;
using TimesExpr [[deprecated("Remove in v4.1. Use zeek::detail::TimesExpr instead.")]] = zeek::detail::TimesExpr;
using DivideExpr [[deprecated("Remove in v4.1. Use zeek::detail::DivideExpr instead.")]] = zeek::detail::DivideExpr;
using ModExpr [[deprecated("Remove in v4.1. Use zeek::detail::ModExpr instead.")]] = zeek::detail::ModExpr;
using BoolExpr [[deprecated("Remove in v4.1. Use zeek::detail::BoolExpr instead.")]] = zeek::detail::BoolExpr;
using BitExpr [[deprecated("Remove in v4.1. Use zeek::detail::BitExpr instead.")]] = zeek::detail::BitExpr;
using EqExpr [[deprecated("Remove in v4.1. Use zeek::detail::EqExpr instead.")]] = zeek::detail::EqExpr;
using RelExpr [[deprecated("Remove in v4.1. Use zeek::detail::RelExpr instead.")]] = zeek::detail::RelExpr;
using CondExpr [[deprecated("Remove in v4.1. Use zeek::detail::CondExpr instead.")]] = zeek::detail::CondExpr;
using RefExpr [[deprecated("Remove in v4.1. Use zeek::detail::RefExpr instead.")]] = zeek::detail::RefExpr;
using AssignExpr [[deprecated("Remove in v4.1. Use zeek::detail::AssignExpr instead.")]] = zeek::detail::AssignExpr;
using IndexSliceAssignExpr [[deprecated("Remove in v4.1. Use zeek::detail::IndexSliceAssignExpr instead.")]] = zeek::detail::IndexSliceAssignExpr;
using IndexExpr [[deprecated("Remove in v4.1. Use zeek::detail::IndexExpr instead.")]] = zeek::detail::IndexExpr;
using FieldExpr [[deprecated("Remove in v4.1. Use zeek::detail::FieldExpr instead.")]] = zeek::detail::FieldExpr;
using HasFieldExpr [[deprecated("Remove in v4.1. Use zeek::detail::HasFieldExpr instead.")]] = zeek::detail::HasFieldExpr;
using RecordConstructorExpr [[deprecated("Remove in v4.1. Use zeek::detail::RecordConstructorExpr instead.")]] = zeek::detail::RecordConstructorExpr;
using TableConstructorExpr [[deprecated("Remove in v4.1. Use zeek::detail::TableConstructorExpr instead.")]] = zeek::detail::TableConstructorExpr;
using SetConstructorExpr [[deprecated("Remove in v4.1. Use zeek::detail::SetConstructorExpr instead.")]] = zeek::detail::SetConstructorExpr;
using VectorConstructorExpr [[deprecated("Remove in v4.1. Use zeek::detail::VectorConstructorExpr instead.")]] = zeek::detail::VectorConstructorExpr;
using FieldAssignExpr [[deprecated("Remove in v4.1. Use zeek::detail::FieldAssignExpr instead.")]] = zeek::detail::FieldAssignExpr;
using ArithCoerceExpr [[deprecated("Remove in v4.1. Use zeek::detail::ArithCoerceExpr instead.")]] = zeek::detail::ArithCoerceExpr;
using RecordCoerceExpr [[deprecated("Remove in v4.1. Use zeek::detail::RecordCoerceExpr instead.")]] = zeek::detail::RecordCoerceExpr;
using TableCoerceExpr [[deprecated("Remove in v4.1. Use zeek::detail::TableCoerceExpr instead.")]] = zeek::detail::TableCoerceExpr;
using VectorCoerceExpr [[deprecated("Remove in v4.1. Use zeek::detail::VectorCoerceExpr instead.")]] = zeek::detail::VectorCoerceExpr;
using ScheduleTimer [[deprecated("Remove in v4.1. Use zeek::detail::ScheduleTimer instead.")]] = zeek::detail::ScheduleTimer;
using ScheduleExpr [[deprecated("Remove in v4.1. Use zeek::detail::ScheduleExpr instead.")]] = zeek::detail::ScheduleExpr;
using InExpr [[deprecated("Remove in v4.1. Use zeek::detail::InExpr instead.")]] = zeek::detail::InExpr;
using CallExpr [[deprecated("Remove in v4.1. Use zeek::detail::CallExpr instead.")]] = zeek::detail::CallExpr;
using LambdaExpr [[deprecated("Remove in v4.1. Use zeek::detail::LambdaExpr instead.")]] = zeek::detail::LambdaExpr;
using EventExpr [[deprecated("Remove in v4.1. Use zeek::detail::EventExpr instead.")]] = zeek::detail::EventExpr;
using ListExpr [[deprecated("Remove in v4.1. Use zeek::detail::ListExpr instead.")]] = zeek::detail::ListExpr;
using RecordAssignExpr [[deprecated("Remove in v4.1. Use zeek::detail::RecordAssignExpr instead.")]] = zeek::detail::RecordAssignExpr;
using CastExpr [[deprecated("Remove in v4.1. Use zeek::detail::CastExpr instead.")]] = zeek::detail::CastExpr;
using IsExpr [[deprecated("Remove in v4.1. Use zeek::detail::IsExpr instead.")]] = zeek::detail::IsExpr;
