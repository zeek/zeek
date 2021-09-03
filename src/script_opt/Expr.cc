// See the file "COPYING" in the main distribution directory for copyright.

// Optimization-related methods for Expr classes.

#include "zeek/Expr.h"
#include "zeek/Stmt.h"
#include "zeek/Func.h"
#include "zeek/Frame.h"
#include "zeek/Scope.h"
#include "zeek/Desc.h"
#include "zeek/Traverse.h"
#include "zeek/Reporter.h"
#include "zeek/script_opt/Inline.h"
#include "zeek/script_opt/Reduce.h"


namespace zeek::detail {

static bool same_singletons(ExprPtr e1, ExprPtr e2);


ConstExpr* Expr::AsConstExpr()
	{
	CHECK_TAG(tag, EXPR_CONST, "ExprVal::AsConstExpr", expr_name)
	return (ConstExpr*) this;
	}

const FieldExpr* Expr::AsFieldExpr() const
	{
	CHECK_TAG(tag, EXPR_FIELD, "ExprVal::AsFieldExpr", expr_name)
	return (const FieldExpr*) this;
	}

FieldExpr* Expr::AsFieldExpr()
	{
	CHECK_TAG(tag, EXPR_FIELD, "ExprVal::AsFieldExpr", expr_name)
	return (FieldExpr*) this;
	}

IntrusivePtr<FieldAssignExpr> Expr::AsFieldAssignExprPtr()
	{
	CHECK_TAG(tag, EXPR_FIELD_ASSIGN, "ExprVal::AsFieldAssignExpr", expr_name)
	return {NewRef{}, (FieldAssignExpr*) this};
	}

const IndexAssignExpr* Expr::AsIndexAssignExpr() const
	{
	CHECK_TAG(tag, EXPR_INDEX_ASSIGN, "ExprVal::AsIndexAssignExpr", expr_name)
	return (const IndexAssignExpr*) this;
	}

const FieldLHSAssignExpr* Expr::AsFieldLHSAssignExpr() const
	{
	CHECK_TAG(tag, EXPR_FIELD_LHS_ASSIGN, "ExprVal::AsFieldLHSAssignExpr", expr_name)
	return (const FieldLHSAssignExpr*) this;
	}

HasFieldExpr* Expr::AsHasFieldExpr()
	{
	CHECK_TAG(tag, EXPR_HAS_FIELD, "ExprVal::AsHasFieldExpr", expr_name)
	return (HasFieldExpr*) this;
	}

const HasFieldExpr* Expr::AsHasFieldExpr() const
	{
	CHECK_TAG(tag, EXPR_HAS_FIELD, "ExprVal::AsHasFieldExpr", expr_name)
	return (const HasFieldExpr*) this;
	}

const AddToExpr* Expr::AsAddToExpr() const
	{
	CHECK_TAG(tag, EXPR_ADD_TO, "ExprVal::AsAddToExpr", expr_name)
	return (const AddToExpr*) this;
	}

const IsExpr* Expr::AsIsExpr() const
	{
	CHECK_TAG(tag, EXPR_IS, "ExprVal::AsIsExpr", expr_name)
	return (const IsExpr*) this;
	}

CallExpr* Expr::AsCallExpr()
	{
	CHECK_TAG(tag, EXPR_CALL, "ExprVal::AsCallExpr", expr_name)
	return (CallExpr*) this;
	}

FieldAssignExpr* Expr::AsFieldAssignExpr()
	{
	CHECK_TAG(tag, EXPR_FIELD_ASSIGN, "ExprVal::AsFieldAssignExpr", expr_name)
	return (FieldAssignExpr*) this;
	}

const RecordCoerceExpr* Expr::AsRecordCoerceExpr() const
	{
	CHECK_TAG(tag, EXPR_RECORD_COERCE, "ExprVal::AsRecordCoerceExpr", expr_name)
	return (const RecordCoerceExpr*) this;
	}

const RecordConstructorExpr* Expr::AsRecordConstructorExpr() const
	{
	CHECK_TAG(tag, EXPR_RECORD_CONSTRUCTOR, "ExprVal::AsRecordConstructorExpr", expr_name)
	return (const RecordConstructorExpr*) this;
	}

const TableConstructorExpr* Expr::AsTableConstructorExpr() const
	{
	CHECK_TAG(tag, EXPR_TABLE_CONSTRUCTOR, "ExprVal::AsTableConstructorExpr", expr_name)
	return (const TableConstructorExpr*) this;
	}

const SetConstructorExpr* Expr::AsSetConstructorExpr() const
	{
	CHECK_TAG(tag, EXPR_SET_CONSTRUCTOR, "ExprVal::AsSetConstructorExpr", expr_name)
	return (const SetConstructorExpr*) this;
	}

RefExpr* Expr::AsRefExpr()
	{
	CHECK_TAG(tag, EXPR_REF, "ExprVal::AsRefExpr", expr_name)
	return (RefExpr*) this;
	}

const InlineExpr* Expr::AsInlineExpr() const
	{
	CHECK_TAG(tag, EXPR_INLINE, "ExprVal::AsInlineExpr", expr_name)
	return (const InlineExpr*) this;
	}

AnyIndexExpr* Expr::AsAnyIndexExpr()
	{
	CHECK_TAG(tag, EXPR_ANY_INDEX, "ExprVal::AsAnyIndexExpr", expr_name)
	return (AnyIndexExpr*) this;
	}

const AnyIndexExpr* Expr::AsAnyIndexExpr() const
	{
	CHECK_TAG(tag, EXPR_ANY_INDEX, "ExprVal::AsAnyIndexExpr", expr_name)
	return (const AnyIndexExpr*) this;
	}

LambdaExpr* Expr::AsLambdaExpr()
	{
	CHECK_TAG(tag, EXPR_LAMBDA, "ExprVal::AsLambdaExpr", expr_name)
	return (LambdaExpr*) this;
	}

const LambdaExpr* Expr::AsLambdaExpr() const
	{
	CHECK_TAG(tag, EXPR_LAMBDA, "ExprVal::AsLambdaExpr", expr_name)
	return (const LambdaExpr*) this;
	}

ExprPtr Expr::GetOp1() const { return nullptr; }
ExprPtr Expr::GetOp2() const { return nullptr; }
ExprPtr Expr::GetOp3() const { return nullptr; }

void Expr::SetOp1(ExprPtr) { }
void Expr::SetOp2(ExprPtr) { }
void Expr::SetOp3(ExprPtr) { }

bool Expr::IsReduced(Reducer* c) const
	{
	return true;
	}

bool Expr::HasReducedOps(Reducer* c) const
	{
	return true;
	}

bool Expr::IsReducedConditional(Reducer* c) const
	{
	switch ( tag ) {
	case EXPR_CONST:
		return true;

	case EXPR_NAME:
		return IsReduced(c);

	case EXPR_IN:
		{
		auto op1 = GetOp1();
		auto op2 = GetOp2();

		if ( op1->Tag() != EXPR_NAME && op1->Tag() != EXPR_LIST )
			return NonReduced(this);

		if ( op2->GetType()->Tag() != TYPE_TABLE || ! op2->IsReduced(c) )
			return NonReduced(this);

		if ( op1->Tag() == EXPR_LIST )
			{
			auto l1 = op1->AsListExpr();
			auto& l1_e = l1->Exprs();

			if ( l1_e.length() < 1 || l1_e.length() > 2 )
				return NonReduced(this);
			}

		return true;
		}

	case EXPR_EQ:
	case EXPR_NE:
	case EXPR_LE:
	case EXPR_GE:
	case EXPR_LT:
	case EXPR_GT:
	case EXPR_HAS_FIELD:
		return HasReducedOps(c);

	default:
		return false;
	}
	}

bool Expr::IsReducedFieldAssignment(Reducer* c) const
	{
	if ( ! IsFieldAssignable(this) )
		return false;

	if ( tag == EXPR_CONST )
		return true;

	if ( tag == EXPR_NAME )
		return IsReduced(c);

	return HasReducedOps(c);
	}

bool Expr::IsFieldAssignable(const Expr* e) const
	{
	switch ( e->Tag() ) {
	case EXPR_NAME:
	case EXPR_CONST:
	case EXPR_NOT:
	case EXPR_COMPLEMENT:
	case EXPR_POSITIVE:
	case EXPR_NEGATE:
	case EXPR_ADD:
	case EXPR_SUB:
	case EXPR_TIMES:
	case EXPR_DIVIDE:
	case EXPR_MOD:
	case EXPR_AND:
	case EXPR_OR:
	case EXPR_XOR:
	case EXPR_FIELD:
	case EXPR_HAS_FIELD:
	case EXPR_IN:
	case EXPR_SIZE:
		return true;

	// These would not be hard to add in principle, but at the expense
	// of some added complexity in the templator.  Seems unlikely the
	// actual performance gain would make that worth it.
	// case EXPR_LT:
	// case EXPR_LE:
	// case EXPR_EQ:
	// case EXPR_NE:
	// case EXPR_GE:
	// case EXPR_GT:

	// These could be added if we subsetted them to versions for
	// which we know it's safe to evaluate both operands.  Again
	// likely not worth it.
	// case EXPR_AND_AND:
	// case EXPR_OR_OR:

	default:
		return false;
	}
	}

ExprPtr Expr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	red_stmt = nullptr;
	return ThisPtr();
	}

StmtPtr Expr::ReduceToSingletons(Reducer* c)
	{
	auto op1 = GetOp1();
	auto op2 = GetOp2();
	auto op3 = GetOp3();

	StmtPtr red1_stmt;
	StmtPtr red2_stmt;
	StmtPtr red3_stmt;

	if ( op1 && ! op1->IsSingleton(c) )
		SetOp1(op1->ReduceToSingleton(c, red1_stmt));
	if ( op2 && ! op2->IsSingleton(c) )
		SetOp2(op2->ReduceToSingleton(c, red2_stmt));
	if ( op3 && ! op3->IsSingleton(c) )
		SetOp3(op3->ReduceToSingleton(c, red3_stmt));

	return MergeStmts(red1_stmt, red2_stmt, red3_stmt);
	}

ExprPtr Expr::ReduceToConditional(Reducer* c, StmtPtr& red_stmt)
	{
	switch ( tag ) {
	case EXPR_CONST:
		return ThisPtr();

	case EXPR_NAME:
		if ( c->Optimizing() )
			return ThisPtr();

		return Reduce(c, red_stmt);

	case EXPR_IN:
		{
		// This is complicated because there are lots of forms
		// of "in" expressions, and we're only interested in
		// those with 1 or 2 indices, into a table.
		auto op1 = GetOp1();
		auto op2 = GetOp2();

		if ( c->Optimizing() )
			return Reduce(c, red_stmt);

		if ( op2->GetType()->Tag() != TYPE_TABLE )
			// Not a table de-reference.
			return Reduce(c, red_stmt);

		if ( op1->Tag() == EXPR_LIST )
			{
			auto l1 = op1->AsListExpr();
			auto& l1_e = l1->Exprs();

			if ( l1_e.length() < 1 || l1_e.length() > 2 )
				// Wrong number of indices.
				return Reduce(c, red_stmt);
			}

		if ( ! op1->IsReduced(c) || ! op2->IsReduced(c) )
			{
			auto red2_stmt = ReduceToSingletons(c);
			auto res = ReduceToConditional(c, red_stmt);
			red_stmt = MergeStmts(red2_stmt, red_stmt);
			return res;
			}

		return ThisPtr();
		}

	case EXPR_EQ:
	case EXPR_NE:
	case EXPR_LE:
	case EXPR_GE:
	case EXPR_LT:
	case EXPR_GT:
		red_stmt = ReduceToSingletons(c);

		if ( GetOp1()->IsConst() && GetOp2()->IsConst() )
			// Fold!
			{
			StmtPtr fold_stmts;
			auto new_me = Reduce(c, fold_stmts);
			red_stmt = MergeStmts(red_stmt, fold_stmts);

			return new_me;
			}

		return ThisPtr();

	case EXPR_HAS_FIELD:
		red_stmt = ReduceToSingletons(c);
		return ThisPtr();

	default:
		return Reduce(c, red_stmt);
	}
	}

ExprPtr Expr::ReduceToFieldAssignment(Reducer* c, StmtPtr& red_stmt)
	{
	if ( ! IsFieldAssignable(this) || tag == EXPR_NAME )
		return ReduceToSingleton(c, red_stmt);

	red_stmt = ReduceToSingletons(c);

	return ThisPtr();
	}

ExprPtr Expr::AssignToTemporary(ExprPtr e, Reducer* c, StmtPtr& red_stmt)
	{
	auto result_tmp = c->GenTemporaryExpr(GetType(), e);

	auto a_e = make_intrusive<AssignExpr>(result_tmp->MakeLvalue(), e,
						false, nullptr, nullptr, false);
	a_e->SetIsTemp();
	a_e->SetOriginal(ThisPtr());

	auto a_e_s = make_intrusive<ExprStmt>(a_e);
	red_stmt = MergeStmts(red_stmt, a_e_s);

	// Important: our result is not result_tmp, but a duplicate of it.
	// This is important because subsequent passes that associate
	// information with Expr's need to not mis-associate that
	// information with both the assignment creating the temporary,
	// and the subsequent use of the temporary.
	return result_tmp->Duplicate();
	}

ExprPtr Expr::TransformMe(ExprPtr new_me, Reducer* c, StmtPtr& red_stmt)
	{
	if ( new_me == this )
		return new_me;

	new_me->SetOriginal(ThisPtr());

	// Unlike for Stmt's, we assume that new_me has already
	// been reduced, so no need to do so further.
	return new_me;
	}

StmtPtr Expr::MergeStmts(StmtPtr s1, StmtPtr s2, StmtPtr s3) const
	{
	int nums = (s1 != nullptr) + (s2 != nullptr) + (s3 != nullptr);

	if ( nums > 1 )
		return make_intrusive<StmtList>(s1, s2, s3);
	else if ( s1 )
		return s1;
	else if ( s2 )
		return s2;
	else if ( s3 )
		return s3;
	else
		return nullptr;
	}

ValPtr Expr::MakeZero(TypeTag t) const
	{
	switch ( t ) {
	case TYPE_BOOL:		return val_mgr->False();
	case TYPE_INT:		return val_mgr->Int(0);
	case TYPE_COUNT:	return val_mgr->Count(0);

	case TYPE_DOUBLE:	return make_intrusive<DoubleVal>(0.0);
	case TYPE_TIME:		return make_intrusive<TimeVal>(0.0);
	case TYPE_INTERVAL:	return make_intrusive<IntervalVal>(0.0, 1.0);

	default:
		reporter->InternalError("bad call to MakeZero");
	}
	}

ConstExprPtr Expr::MakeZeroExpr(TypeTag t) const
	{
	return make_intrusive<ConstExpr>(MakeZero(t));
	}


ExprPtr NameExpr::Duplicate()
	{
	return SetSucc(new NameExpr(id, in_const_init));
	}

bool NameExpr::IsReduced(Reducer* c) const
	{
	if ( FoldableGlobal() )
		return false;

	return c->NameIsReduced(this);
	}

ExprPtr NameExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	red_stmt = nullptr;

	if ( c->Optimizing() )
		return ThisPtr();

	if ( FoldableGlobal() )
		{
		ValPtr v = id->GetVal();
		ASSERT(v);
		return TransformMe(make_intrusive<ConstExpr>(v), c, red_stmt);
		}

	return c->UpdateName({NewRef{}, this});
	}

ValPtr NameExpr::FoldVal() const
	{
	if ( ! id->IsConst() || id->GetAttr(ATTR_REDEF) ||
	     id->GetType()->Tag() == TYPE_FUNC )
		return nullptr;

	return id->GetVal();
	}

bool NameExpr::FoldableGlobal() const
	{
	return id->IsGlobal() && id->IsConst() &&
	       is_atomic_type(id->GetType()) &&
		// Make sure constant can't be changed on the command line
		// or such.
		! id->GetAttr(ATTR_REDEF);
	}


ExprPtr ConstExpr::Duplicate()
	{
	return SetSucc(new ConstExpr(val));
	}


ExprPtr UnaryExpr::Inline(Inliner* inl)
	{
	op = op->Inline(inl);
	return ThisPtr();
	}

bool UnaryExpr::HasNoSideEffects() const
	{
	return op->HasNoSideEffects();
	}

bool UnaryExpr::IsReduced(Reducer* c) const
	{
	return NonReduced(this);
	}

bool UnaryExpr::HasReducedOps(Reducer* c) const
	{
	return op->IsSingleton(c);
	}

ExprPtr UnaryExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	if ( c->Optimizing() )
		op = c->UpdateExpr(op);

	red_stmt = nullptr;

	if ( ! op->IsSingleton(c) )
		op = op->ReduceToSingleton(c, red_stmt);

	auto op_val = op->FoldVal();
	if ( op_val )
		{
		auto fold = Fold(op_val.get());
		return TransformMe(make_intrusive<ConstExpr>(fold), c, red_stmt);
		}

	if ( c->Optimizing() )
		return ThisPtr();
	else
		return AssignToTemporary(c, red_stmt);
	}


ExprPtr BinaryExpr::Inline(Inliner* inl)
	{
	op1 = op1->Inline(inl);
	op2 = op2->Inline(inl);

	return ThisPtr();
	}

bool BinaryExpr::HasNoSideEffects() const
	{
	return op1->HasNoSideEffects() && op2->HasNoSideEffects();
	}

bool BinaryExpr::IsReduced(Reducer* c) const
	{
	return NonReduced(this);
	}

bool BinaryExpr::HasReducedOps(Reducer* c) const
	{
	return op1->IsSingleton(c) && op2->IsSingleton(c);
	}

ExprPtr BinaryExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	if ( c->Optimizing() )
		{
		op1 = c->UpdateExpr(op1);
		op2 = c->UpdateExpr(op2);
		}

	red_stmt = nullptr;

	if ( ! op1->IsSingleton(c) )
		op1 = op1->ReduceToSingleton(c, red_stmt);

	StmtPtr red2_stmt;
	if ( ! op2->IsSingleton(c) )
		op2 = op2->ReduceToSingleton(c, red2_stmt);

	red_stmt = MergeStmts(red_stmt, red2_stmt);

	auto op1_fold_val = op1->FoldVal();
	auto op2_fold_val = op2->FoldVal();
	if ( op1_fold_val && op2_fold_val )
		{
		auto fold = Fold(op1_fold_val.get(), op2_fold_val.get());
		return TransformMe(make_intrusive<ConstExpr>(fold), c, red_stmt);
		}

	if ( c->Optimizing() )
		return ThisPtr();
	else
		return AssignToTemporary(c, red_stmt);
	}


ExprPtr CloneExpr::Duplicate()
	{
	// oh the irony
	return SetSucc(new CloneExpr(op->Duplicate()));
	}


ExprPtr IncrExpr::Duplicate()
	{
	return SetSucc(new IncrExpr(tag, op->Duplicate()));
	}

bool IncrExpr::HasNoSideEffects() const
	{
	return false;
	}

bool IncrExpr::IsReduced(Reducer* c) const
	{
	auto ref_op = op->AsRefExprPtr();
	auto target = ref_op->GetOp1();

	if ( target->Tag() != EXPR_NAME ||
	     ! IsIntegral(target->GetType()->Tag()) )
		return NonReduced(this);

	return ref_op->IsReduced(c);
	}

ExprPtr IncrExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	if ( op->Tag() != EXPR_REF )
		Internal("confusion in IncrExpr::Reduce");

	auto ref_op = op->AsRefExprPtr();
	auto target = ref_op->GetOp1();

	if ( target->Tag() == EXPR_NAME &&
	     IsIntegral(target->GetType()->Tag()) )
		{
		if ( c->Optimizing() )
			op = c->UpdateExpr(op);
		else
			op = op->Reduce(c, red_stmt);

		return ThisPtr();
		}

	// First reduce the target's operands to singletons, so that when
	// we re-use it in the assignment below, it has reduced operands.
	auto init_red_stmt = target->ReduceToSingletons(c);

	// Now reduce it all the way to a single value, to use for the
	// increment.
	auto orig_target = target;
	StmtPtr target_stmt;
	target = target->ReduceToSingleton(c, target_stmt);

	auto incr_const = make_intrusive<ConstExpr>(val_mgr->Count(1));
	incr_const->SetOriginal(ThisPtr());

	ExprPtr incr_expr;

	if ( Tag() == EXPR_INCR )
		incr_expr = make_intrusive<AddExpr>(target, incr_const);
	else
		incr_expr = make_intrusive<SubExpr>(target, incr_const);

	incr_expr->SetOriginal(ThisPtr());
	StmtPtr incr_stmt;
	auto incr_expr2 = incr_expr->Reduce(c, incr_stmt);

	StmtPtr assign_stmt;
	auto rhs = incr_expr2->AssignToTemporary(c, assign_stmt);

	// Build a duplicate version of the original to use as the result.
	if ( orig_target->Tag() == EXPR_NAME )
		orig_target = orig_target->Duplicate();

	else if ( orig_target->Tag() == EXPR_INDEX )
		{
		auto dup1 = orig_target->GetOp1()->Duplicate();
		auto dup2 = orig_target->GetOp2()->Duplicate();
		auto index = dup2->AsListExprPtr();
		orig_target = make_intrusive<IndexExpr>(dup1, index);
		}

	else if ( orig_target->Tag() == EXPR_FIELD )
		{
		auto dup1 = orig_target->GetOp1()->Duplicate();
		auto field_name = orig_target->AsFieldExpr()->FieldName();
		orig_target = make_intrusive<FieldExpr>(dup1, field_name);
		}

	else
		reporter->InternalError("confused in IncrExpr::Reduce");

	auto assign = make_intrusive<AssignExpr>(orig_target, rhs, false,
						nullptr, nullptr, false);

	orig_target->SetOriginal(ThisPtr());

	// First reduce it regularly, so it can transform into $= or
	// such as needed.  Then reduce that to a singleton to provide
	// the result for this expression.
	StmtPtr assign_stmt2;
	auto res = assign->Reduce(c, assign_stmt2);
	res = res->ReduceToSingleton(c, red_stmt);
	red_stmt = MergeStmts(MergeStmts(init_red_stmt, target_stmt),
			MergeStmts(incr_stmt, assign_stmt, assign_stmt2),
				red_stmt);

	return res;
	}

ExprPtr IncrExpr::ReduceToSingleton(Reducer* c, StmtPtr& red_stmt)
	{
	auto ref_op = op->AsRefExprPtr();
	auto target = ref_op->GetOp1();

	if ( target->Tag() == EXPR_NAME &&
	     IsIntegral(target->GetType()->Tag()) )
		{
		ExprPtr incr_expr = Duplicate();
		red_stmt = make_intrusive<ExprStmt>(incr_expr)->Reduce(c);

		StmtPtr targ_red_stmt;
		auto targ_red = target->Reduce(c, targ_red_stmt);

		red_stmt = MergeStmts(red_stmt, targ_red_stmt);

		return targ_red;
		}

	else
		return UnaryExpr::ReduceToSingleton(c, red_stmt);
	}


ExprPtr ComplementExpr::Duplicate()
	{
	return SetSucc(new ComplementExpr(op->Duplicate()));
	}

bool ComplementExpr::WillTransform(Reducer* c) const
	{
	return op->Tag() == EXPR_COMPLEMENT;
	}

ExprPtr ComplementExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	if ( op->Tag() == EXPR_COMPLEMENT )
		return op->GetOp1()->ReduceToSingleton(c, red_stmt);

	return UnaryExpr::Reduce(c, red_stmt);
	}


ExprPtr NotExpr::Duplicate()
	{
	return SetSucc(new NotExpr(op->Duplicate()));
	}

bool NotExpr::WillTransform(Reducer* c) const
	{
	return op->Tag() == EXPR_NOT && Op()->GetType()->Tag() == TYPE_BOOL;
	}

ExprPtr NotExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	if ( op->Tag() == EXPR_NOT && Op()->GetType()->Tag() == TYPE_BOOL )
		return Op()->Reduce(c, red_stmt);

	return UnaryExpr::Reduce(c, red_stmt);
	}


ExprPtr PosExpr::Duplicate()
	{
	return SetSucc(new PosExpr(op->Duplicate()));
	}

bool PosExpr::WillTransform(Reducer* c) const
	{
	return op->GetType()->Tag() != TYPE_COUNT;
	}

ExprPtr PosExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	if ( op->GetType()->Tag() == TYPE_COUNT )
		// We need to keep the expression because it leads
		// to a coercion from unsigned to signed.
		return UnaryExpr::Reduce(c, red_stmt);

	else
		return op->ReduceToSingleton(c, red_stmt);
	}


ExprPtr NegExpr::Duplicate()
	{
	return SetSucc(new NegExpr(op->Duplicate()));
	}

bool NegExpr::WillTransform(Reducer* c) const
	{
	return op->Tag() == EXPR_NEGATE;
	}

ExprPtr NegExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	if ( op->Tag() == EXPR_NEGATE )
		return op->GetOp1()->ReduceToSingleton(c, red_stmt);

	return UnaryExpr::Reduce(c, red_stmt);
	}


ExprPtr SizeExpr::Duplicate()
	{
	return SetSucc(new SizeExpr(op->Duplicate()));
	}


ExprPtr AddExpr::Duplicate()
	{
	auto op1_d = op1->Duplicate();
	auto op2_d = op2->Duplicate();
	return SetSucc(new AddExpr(op1_d, op2_d));
	}

bool AddExpr::WillTransform(Reducer* c) const
	{
	return op1->IsZero() || op2->IsZero() ||
		op1->Tag() == EXPR_NEGATE || op2->Tag() == EXPR_NEGATE;
	}

ExprPtr AddExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	if ( op1->IsZero() )
		return op2->ReduceToSingleton(c, red_stmt);

	if ( op2->IsZero() )
		return op1->ReduceToSingleton(c, red_stmt);

	if ( op1->Tag() == EXPR_NEGATE )
		return BuildSub(op2, op1)->ReduceToSingleton(c, red_stmt);

	if ( op2->Tag() == EXPR_NEGATE )
		return BuildSub(op1, op2)->ReduceToSingleton(c, red_stmt);

	return BinaryExpr::Reduce(c, red_stmt);
	}

ExprPtr AddExpr::BuildSub(const ExprPtr& op1, const ExprPtr& op2)
	{
	auto rhs = op2->GetOp1();
	auto sub = make_intrusive<SubExpr>(op1, rhs);
	sub->SetOriginal(ThisPtr());
	return sub;
	}


ExprPtr AddToExpr::Duplicate()
	{
	auto op1_d = op1->Duplicate();
	auto op2_d = op2->Duplicate();
	return SetSucc(new AddToExpr(op1_d, op2_d));
	}

ExprPtr AddToExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	if ( IsVector(op1->GetType()->Tag()) )
		{
		StmtPtr red_stmt1;
		StmtPtr red_stmt2;

		if ( op1->Tag() == EXPR_FIELD )
			red_stmt1 = op1->ReduceToSingletons(c);
		else
			op1 = op1->Reduce(c, red_stmt1);

		op2 = op2->Reduce(c, red_stmt2);

		auto append =
			make_intrusive<AppendToExpr>(op1->Duplicate(), op2);
		append->SetOriginal(ThisPtr());

		auto append_stmt = make_intrusive<ExprStmt>(append);

		red_stmt = MergeStmts(red_stmt1, red_stmt2, append_stmt);

		return op1;
		}

	else
		{
		// We could do an ASSERT that op1 is an EXPR_REF, but
		// the following is basically equivalent.
		auto rhs = op1->AsRefExprPtr()->GetOp1();
		auto do_incr = make_intrusive<AddExpr>(rhs->Duplicate(), op2);
		auto assign = make_intrusive<AssignExpr>(op1, do_incr, false, nullptr,
		                                         nullptr, false);

		return assign->ReduceToSingleton(c, red_stmt);
		}
	}


ExprPtr SubExpr::Duplicate()
	{
	auto op1_d = op1->Duplicate();
	auto op2_d = op2->Duplicate();
	return SetSucc(new SubExpr(op1_d, op2_d));
	}

bool SubExpr::WillTransform(Reducer* c) const
	{
	return op2->IsZero() || op2->Tag() == EXPR_NEGATE ||
		(type->Tag() != TYPE_VECTOR && type->Tag() != TYPE_TABLE &&
	         op1->Tag() == EXPR_NAME && op2->Tag() == EXPR_NAME &&
		 op1->AsNameExpr()->Id() == op2->AsNameExpr()->Id());
	}

ExprPtr SubExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	if ( op2->IsZero() )
		return op1->ReduceToSingleton(c, red_stmt);

	if ( op2->Tag() == EXPR_NEGATE )
		{
		auto rhs = op2->GetOp1();
		auto add = make_intrusive<AddExpr>(op1, rhs);
		add->SetOriginal(ThisPtr());
		return add->Reduce(c, red_stmt);
		}

	if ( c->Optimizing() )
		{ // Allow for alias expansion.
		op1 = c->UpdateExpr(op1);
		op2 = c->UpdateExpr(op2);
		}

	if ( type->Tag() != TYPE_VECTOR && type->Tag() != TYPE_TABLE &&
	     op1->Tag() == EXPR_NAME && op2->Tag() == EXPR_NAME )
		{
		auto n1 = op1->AsNameExpr();
		auto n2 = op2->AsNameExpr();
		if ( n1->Id() == n2->Id() )
			{
			auto zero = MakeZeroExpr(type->Tag());
			return TransformMe(zero, c, red_stmt);
			}
		}

	return BinaryExpr::Reduce(c, red_stmt);
	}


ExprPtr RemoveFromExpr::Duplicate()
	{
	auto op1_d = op1->Duplicate();
	auto op2_d = op2->Duplicate();
	return SetSucc(new RemoveFromExpr(op1_d, op2_d));
	}

ExprPtr RemoveFromExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	auto rhs = op1->AsRefExprPtr()->GetOp1();
	auto do_decr = make_intrusive<SubExpr>(rhs->Duplicate(), op2);
	auto assign = make_intrusive<AssignExpr>(op1, do_decr, false, nullptr, nullptr,
	                                         false);

	return assign->Reduce(c, red_stmt);
	}


ExprPtr TimesExpr::Duplicate()
	{
	auto op1_d = op1->Duplicate();
	auto op2_d = op2->Duplicate();
	return SetSucc(new TimesExpr(op1_d, op2_d));
	}

bool TimesExpr::WillTransform(Reducer* c) const
	{
	return op1->IsZero() || op2->IsZero() || op1->IsOne() || op2->IsOne();
	}

ExprPtr TimesExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	if ( op1->IsOne() )
		return op2->ReduceToSingleton(c, red_stmt);

	if ( op2->IsOne() )
		return op1->ReduceToSingleton(c, red_stmt);

	// Optimize integral multiplication by zero ... but not
	// double, due to cases like Inf*0 or NaN*0.
	if ( (op1->IsZero() || op2->IsZero()) &&
	     GetType()->Tag() != TYPE_DOUBLE )
		{
		if ( op1->IsZero() )
			return c->Fold(op1);
		else
			return c->Fold(op2);
		}

	return BinaryExpr::Reduce(c, red_stmt);
	}


ExprPtr DivideExpr::Duplicate()
	{
	auto op1_d = op1->Duplicate();
	auto op2_d = op2->Duplicate();
	return SetSucc(new DivideExpr(op1_d, op2_d));
	}

bool DivideExpr::WillTransform(Reducer* c) const
	{
	return GetType()->Tag() != TYPE_SUBNET && op2->IsOne();
	}

ExprPtr DivideExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	if ( GetType()->Tag() != TYPE_SUBNET )
		{
		if ( op2->IsOne() )
			return op1->ReduceToSingleton(c, red_stmt);
		}

	return BinaryExpr::Reduce(c, red_stmt);
	}


ExprPtr ModExpr::Duplicate()
	{
	auto op1_d = op1->Duplicate();
	auto op2_d = op2->Duplicate();
	return SetSucc(new ModExpr(op1_d, op2_d));
	}


// Helper functions used by BoolExpr.

// Returns true if the given Expr is either of the form "/pat/ in var" or a
// (possibly extended) "||" disjunction of such nodes, for which "var" is
// always the same.  If true, returns the IDPtr corresponding to "var", and
// collects the associated pattern constants in "patterns".
//
// Note that for an initial (non-recursive) call, "id" should be set to
// nullptr, and the caller should have ensured that the starting point is
// a disjunction (since a bare "/pat/ in var" by itself isn't a "cascade"
// and doesn't present a potential optimization opportunity.
static bool is_pattern_cascade(const ExprPtr& e, IDPtr& id,
				std::vector<ConstExprPtr>& patterns)
	{
	auto lhs = e->GetOp1();
	auto rhs = e->GetOp2();

	if ( e->Tag() == EXPR_IN )
		{
		if ( lhs->Tag() != EXPR_CONST ||
		     lhs->GetType()->Tag() != TYPE_PATTERN ||
		     rhs->Tag() != EXPR_NAME )
			return false;

		const auto& rhs_id = rhs->AsNameExpr()->IdPtr();

		if ( id && rhs_id != id )
			return false;

		id = rhs_id;
		patterns.push_back(lhs->AsConstExprPtr());

		return true;
		}

	if ( e->Tag() != EXPR_OR_OR )
		return false;

	return is_pattern_cascade(lhs, id, patterns) &&
		is_pattern_cascade(rhs, id, patterns);
	}

// Given a set of pattern constants, returns a disjunction that
// includes all of them.
static ExprPtr build_disjunction(std::vector<ConstExprPtr>& patterns)
	{
	ASSERT(patterns.size() > 1);

	ExprPtr e = patterns[0];

	for ( auto& p : patterns )
		e = make_intrusive<BitExpr>(EXPR_OR, e, p);

	return e;
	}


ExprPtr BoolExpr::Duplicate()
	{
	auto op1_d = op1->Duplicate();
	auto op2_d = op2->Duplicate();
	return SetSucc(new BoolExpr(tag, op1_d, op2_d));
	}

bool BoolExpr::WillTransform(Reducer* c) const
	{
	return ! IsVector(op1->GetType()->Tag());
	}

bool BoolExpr::WillTransformInConditional(Reducer* c) const
	{
	IDPtr common_id;
	std::vector<ConstExprPtr> patterns;

	ExprPtr e_ptr = {NewRef{}, (Expr*) this};

	return tag == EXPR_OR_OR &&
		is_pattern_cascade(e_ptr, common_id, patterns);
	}

ExprPtr BoolExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	// First, look for a common idiom of "/foo/ in x || /bar/ in x"
	// and translate it to "(/foo/ | /bar) in x", which is more
	// efficient to match.
	IDPtr common_id = nullptr;
	std::vector<ConstExprPtr> patterns;
	if ( tag == EXPR_OR_OR &&
	     is_pattern_cascade(ThisPtr(), common_id, patterns) )
		{
		auto new_pat = build_disjunction(patterns);
		auto new_id = make_intrusive<NameExpr>(common_id);
		auto new_node = make_intrusive<InExpr>(new_pat, new_id);
		return new_node->Reduce(c, red_stmt);
		}

	// It's either an EXPR_AND_AND or an EXPR_OR_OR.
	bool is_and = (tag == EXPR_AND_AND);

	if ( IsTrue(op1) )
		{
		if ( is_and )
			return op2->ReduceToSingleton(c, red_stmt);
		else
			return op1->ReduceToSingleton(c, red_stmt);
		}

	if ( IsFalse(op1) )
		{
		if ( is_and )
			return op1->ReduceToSingleton(c, red_stmt);
		else
			return op2->ReduceToSingleton(c, red_stmt);
		}

	if ( op1->HasNoSideEffects() )
		{
		if ( IsTrue(op2) )
			{
			if ( is_and )
				return op1->ReduceToSingleton(c, red_stmt);
			else
				return op2->ReduceToSingleton(c, red_stmt);
			}

		if ( IsFalse(op2) )
			{
			if ( is_and )
				return op2->ReduceToSingleton(c, red_stmt);
			else
				return op1->ReduceToSingleton(c, red_stmt);
			}
		}

	if ( IsVector(op1->GetType()->Tag()) )
		{
		if ( c->Optimizing() )
			return ThisPtr();
		else
			return AssignToTemporary(c, red_stmt);
		}

	auto else_val = is_and ? val_mgr->False() : val_mgr->True();
	ExprPtr else_e = make_intrusive<ConstExpr>(else_val);

	ExprPtr cond;
	if ( is_and )
		cond = make_intrusive<CondExpr>(op1, op2, else_e);
	else
		cond = make_intrusive<CondExpr>(op1, else_e, op2);

	auto cond_red = cond->ReduceToSingleton(c, red_stmt);

	return TransformMe(cond_red, c, red_stmt);
	}

bool BoolExpr::IsTrue(const ExprPtr& e) const
	{
	if ( ! e->IsConst() )
		return false;

	auto c_e = e->AsConstExpr();
	return c_e->Value()->IsOne();
	}

bool BoolExpr::IsFalse(const ExprPtr& e) const
	{
	if ( ! e->IsConst() )
		return false;

	auto c_e = e->AsConstExpr();
	return c_e->Value()->IsZero();
	}


ExprPtr BitExpr::Duplicate()
	{
	auto op1_d = op1->Duplicate();
	auto op2_d = op2->Duplicate();
	return SetSucc(new BitExpr(tag, op1_d, op2_d));
	}

bool BitExpr::WillTransform(Reducer* c) const
	{
	return GetType()->Tag() == TYPE_COUNT &&
		(op1->IsZero() || op2->IsZero() ||
		 (same_singletons(op1, op2) && op1->Tag() == EXPR_NAME));
	}

ExprPtr BitExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	if ( GetType()->Tag() != TYPE_COUNT )
		return BinaryExpr::Reduce(c, red_stmt);

	auto zero1 = op1->IsZero();
	auto zero2 = op2->IsZero();

	if ( zero1 && zero2 )
		// No matter the operation, the answer is zero.
		return op1->ReduceToSingleton(c, red_stmt);

	if ( zero1 || zero2 )
		{
		ExprPtr& zero_op = zero1 ? op1 : op2;
		ExprPtr& non_zero_op = zero1 ? op2 : op1;

		if ( Tag() == EXPR_AND )
			return zero_op->ReduceToSingleton(c, red_stmt);
		else
			// OR or XOR
			return non_zero_op->ReduceToSingleton(c, red_stmt);
		}

	if ( same_singletons(op1, op2) && op1->Tag() == EXPR_NAME )
		{
		auto n = op1->AsNameExpr();

		if ( Tag() == EXPR_XOR )
			{
			auto zero = make_intrusive<ConstExpr>(val_mgr->Count(0));
			zero->SetOriginal(ThisPtr());
			return zero->Reduce(c, red_stmt);
			}

		else
			return op1->ReduceToSingleton(c, red_stmt);
		}

	return BinaryExpr::Reduce(c, red_stmt);
	}


ExprPtr EqExpr::Duplicate()
	{
	auto op1_d = op1->Duplicate();
	auto op2_d = op2->Duplicate();
	return SetSucc(new EqExpr(tag, op1_d, op2_d));
	}

bool EqExpr::WillTransform(Reducer* c) const
	{
	return GetType()->Tag() == TYPE_BOOL && same_singletons(op1, op2);
	}

ExprPtr EqExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	if ( GetType()->Tag() == TYPE_BOOL && same_singletons(op1, op2) )
		{
		bool t = Tag() == EXPR_EQ;
		auto res = make_intrusive<ConstExpr>(val_mgr->Bool(t));
		res->SetOriginal(ThisPtr());
		return res->Reduce(c, red_stmt);
		}

	return BinaryExpr::Reduce(c, red_stmt);
	}


ExprPtr RelExpr::Duplicate()
	{
	auto op1_d = op1->Duplicate();
	auto op2_d = op2->Duplicate();
	return SetSucc(new RelExpr(tag, op1_d, op2_d));
	}

bool RelExpr::WillTransform(Reducer* c) const
	{
	return GetType()->Tag() == TYPE_BOOL && same_singletons(op1, op2);
	}

ExprPtr RelExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	if ( GetType()->Tag() == TYPE_BOOL )
		{
		if ( same_singletons(op1, op2) )
			{
			bool t = Tag() == EXPR_GE || Tag() == EXPR_LE;
			auto res = make_intrusive<ConstExpr>(val_mgr->Bool(t));
			res->SetOriginal(ThisPtr());
			return res->Reduce(c, red_stmt);
			}

		if ( op1->IsZero() && op2->GetType()->Tag() == TYPE_COUNT &&
		     (Tag() == EXPR_LE || Tag() == EXPR_GT) )
			Warn("degenerate comparison");

		if ( op2->IsZero() && op1->GetType()->Tag() == TYPE_COUNT &&
		     (Tag() == EXPR_LT || Tag() == EXPR_GE) )
			Warn("degenerate comparison");
		}

	return BinaryExpr::Reduce(c, red_stmt);
	}


ExprPtr CondExpr::Duplicate()
	{
	auto op1_d = op1->Duplicate();
	auto op2_d = op2->Duplicate();
	auto op3_d = op3->Duplicate();
	return SetSucc(new CondExpr(op1_d, op2_d, op3_d));
	}

ExprPtr CondExpr::Inline(Inliner* inl)
	{
	op1 = op1->Inline(inl);
	op2 = op2->Inline(inl);
	op3 = op3->Inline(inl);

	return ThisPtr();
	}

bool CondExpr::IsReduced(Reducer* c) const
	{
	if ( ! IsVector(op1->GetType()->Tag()) || ! HasReducedOps(c) ||
             same_singletons(op2, op3) )
		return NonReduced(this);

	return true;
	}

bool CondExpr::HasReducedOps(Reducer* c) const
	{
	return op1->IsSingleton(c) && op2->IsSingleton(c) &&
		op3->IsSingleton(c) && ! op1->IsConst();
	}

bool CondExpr::WillTransform(Reducer* c) const
	{
	return ! HasReducedOps(c);
	}

ExprPtr CondExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	if ( c->Optimizing() )
		{
		op1 = c->UpdateExpr(op1);
		op2 = c->UpdateExpr(op2);
		op3 = c->UpdateExpr(op3);
		}

	StmtPtr op1_red_stmt;
	op1 = op1->ReduceToSingleton(c, op1_red_stmt);

	if ( op1->IsConst() )
		{
		ExprPtr res;
		if ( op1->AsConstExpr()->Value()->IsOne() )
			res = op2->ReduceToSingleton(c, red_stmt);
		else
			res = op3->ReduceToSingleton(c, red_stmt);

		red_stmt = MergeStmts(op1_red_stmt, red_stmt);

		return res;
		}

	if ( same_singletons(op2, op3) )
		{
		if ( op1->HasNoSideEffects() )
			{
			if ( op1->Tag() != EXPR_CONST &&
			     op1->Tag() != EXPR_NAME )
				op1 = op1->AssignToTemporary(c, red_stmt);
			}

		red_stmt = MergeStmts(op1_red_stmt, red_stmt);

		return op2;
		}

	if ( op2->IsConst() && op3->IsConst() && GetType()->Tag() == TYPE_BOOL )
		{
		auto op2_t = op2->IsOne();
		ASSERT(op2_t != op3->IsOne());

		if ( op2_t )
			// This is "var ? T : F", which can be replaced by var.
			return op1;

		// Instead we have "var ? F : T".
		return make_intrusive<NotExpr>(op1);
		}

	if ( c->Optimizing() )
		return ThisPtr();

	red_stmt = ReduceToSingletons(c);

	StmtPtr assign_stmt;
	auto res = AssignToTemporary(c, assign_stmt);

	red_stmt = MergeStmts(op1_red_stmt, red_stmt, assign_stmt);

	return TransformMe(res, c, red_stmt);
	}

StmtPtr CondExpr::ReduceToSingletons(Reducer* c)
	{
	StmtPtr red1_stmt;
	if ( ! op1->IsSingleton(c) )
		op1 = op1->ReduceToSingleton(c, red1_stmt);

	StmtPtr red2_stmt;
	if ( ! op2->IsSingleton(c) )
		op2 = op2->ReduceToSingleton(c, red2_stmt);

	StmtPtr red3_stmt;
	if ( ! op3->IsSingleton(c) )
		op3 = op3->ReduceToSingleton(c, red3_stmt);

	if ( IsVector(op1->GetType()->Tag()) )
		{
		// In this particular case, it's okay to evaluate op2 and
		// op3 fully ahead of time, because the selector has to be
		// able to choose among them.
		return MergeStmts(MergeStmts(red1_stmt, red2_stmt), red3_stmt);
		}

	StmtPtr if_else;

	if ( red2_stmt || red3_stmt )
		{
		if ( ! red2_stmt )
			red2_stmt = make_intrusive<NullStmt>();
		if ( ! red3_stmt )
			red3_stmt = make_intrusive<NullStmt>();

		if_else = make_intrusive<IfStmt>(op1->Duplicate(),
							red2_stmt, red3_stmt);
		}

	return MergeStmts(red1_stmt, if_else);
	}


ExprPtr RefExpr::Duplicate()
	{
	return SetSucc(new RefExpr(op->Duplicate()));
	}

bool RefExpr::IsReduced(Reducer* c) const
	{
	if ( op->Tag() == EXPR_NAME )
		return op->IsReduced(c);

	return NonReduced(this);
	}

bool RefExpr::HasReducedOps(Reducer* c) const
	{
	switch ( op->Tag() ) {
	case EXPR_NAME:
		return op->IsReduced(c);

	case EXPR_FIELD:
		return op->AsFieldExpr()->Op()->IsReduced(c);

	case EXPR_INDEX:
		{
		auto ind = op->AsIndexExpr();
		return ind->Op1()->IsReduced(c) && ind->Op2()->IsReduced(c);
		}

	case EXPR_LIST:
		return op->IsReduced(c);

	default:
		Internal("bad operand in RefExpr::IsReduced");
		return true;
	}
	}

bool RefExpr::WillTransform(Reducer* c) const
	{
	return op->Tag() != EXPR_NAME;
	}

ExprPtr RefExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	if ( op->Tag() == EXPR_NAME )
		op = op->Reduce(c, red_stmt);
	else
		op = AssignToTemporary(c, red_stmt);

	return ThisPtr();
	}

StmtPtr RefExpr::ReduceToLHS(Reducer* c)
	{
	if ( op->Tag() == EXPR_NAME )
		{
		StmtPtr red_stmt;
		op = op->Reduce(c, red_stmt);
		return red_stmt;
		}

	auto red_stmt1 = op->ReduceToSingletons(c);
	auto op_ref = make_intrusive<RefExpr>(op);

	StmtPtr red_stmt2;
	op = AssignToTemporary(op_ref, c, red_stmt2);

	return MergeStmts(red_stmt1, red_stmt2);
	}


ExprPtr AssignExpr::Duplicate()
	{
	auto op1_d = op1->Duplicate();
	auto op2_d = op2->Duplicate();
	return SetSucc(new AssignExpr(op1_d, op2_d, is_init, val));
	}

bool AssignExpr::HasNoSideEffects() const
	{
	return false;
	}

bool AssignExpr::IsReduced(Reducer* c) const
	{
	if ( op2->Tag() == EXPR_ASSIGN )
		// Cascaded assignments are never reduced.
		return false;

	const auto& t1 = op1->GetType();
	const auto& t2 = op2->GetType();

	auto lhs_is_any = t1->Tag() == TYPE_ANY;
	auto rhs_is_any = t2->Tag() == TYPE_ANY;

	if ( lhs_is_any != rhs_is_any && op2->Tag() != EXPR_CONST )
		return NonReduced(this);

	if ( t1->Tag() == TYPE_VECTOR && t1->Yield()->Tag() != TYPE_ANY &&
	     t2->Yield() && t2->Yield()->Tag() == TYPE_ANY )
		return NonReduced(this);

	if ( op1->Tag() == EXPR_REF &&
	     op2->HasConstantOps() && op2->Tag() != EXPR_TO_ANY_COERCE )
		// We are not reduced because we should instead
		// be folded.
		return NonReduced(this);

	if ( IsTemp() )
		return true;

	if ( ! op2->HasReducedOps(c) )
		return NonReduced(this);

	if ( op1->IsSingleton(c) )
		return true;

	if ( op1->Tag() == EXPR_REF )
		return op1->AsRefExprPtr()->IsReduced(c);

	return NonReduced(this);
	}

bool AssignExpr::HasReducedOps(Reducer* c) const
	{
	return op1->IsReduced(c) && op2->IsSingleton(c);
	}

ExprPtr AssignExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	// Yields a fully reduced assignment expression.
	if ( c->Optimizing() )
		{
		// Don't update the LHS, it's already in reduced form
		// and it doesn't make sense to expand aliases or such.
		auto orig_op2 = op2;
		op2 = c->UpdateExpr(op2);

		if ( op2 != orig_op2 && op2->Tag() == EXPR_CONST &&
		     op1->Tag() == EXPR_REF )
			{
			auto lhs = op1->GetOp1();
			auto op2_c = cast_intrusive<ConstExpr>(op2);
			if ( lhs->Tag() == EXPR_NAME )
				c->FoldedTo(orig_op2, op2_c);
			}

		return ThisPtr();
		}

	if ( IsTemp() )
		// These are generated for reduced expressions.
		return ThisPtr();

	auto& t1 = op1->GetType();
	auto& t2 = op2->GetType();

	auto lhs_is_any = t1->Tag() == TYPE_ANY;
	auto rhs_is_any = t2->Tag() == TYPE_ANY;

	StmtPtr rhs_reduce;

	if ( lhs_is_any != rhs_is_any )
		{
		auto op2_loc = op2->GetLocationInfo();

		ExprPtr red_rhs = op2->ReduceToSingleton(c, rhs_reduce);

		if ( lhs_is_any )
			{
			if ( red_rhs->Tag() == EXPR_CONST )
				op2 = red_rhs;
			else
				op2 = make_intrusive<CoerceToAnyExpr>(red_rhs);
			}
		else
			op2 = make_intrusive<CoerceFromAnyExpr>(red_rhs, t1);

		op2->SetLocationInfo(op2_loc);
		}

	if ( t1->Tag() == TYPE_VECTOR && t1->Yield()->Tag() != TYPE_ANY &&
	     t2->Yield() && t2->Yield()->Tag() == TYPE_ANY )
		{
		auto op2_loc = op2->GetLocationInfo();
		ExprPtr red_rhs = op2->ReduceToSingleton(c, rhs_reduce);
		op2 = make_intrusive<CoerceFromAnyVecExpr>(red_rhs, t1);
		op2->SetLocationInfo(op2_loc);
		}

	auto lhs_ref = op1->AsRefExprPtr();
	auto lhs_expr = lhs_ref->GetOp1();

	if ( lhs_expr->Tag() == EXPR_INDEX )
		{
		auto ind_e = lhs_expr->AsIndexExpr();

		StmtPtr ind1_stmt;
		StmtPtr ind2_stmt;
		StmtPtr rhs_stmt;

		auto ind1_e = ind_e->Op1()->Reduce(c, ind1_stmt);
		auto ind2_e = ind_e->Op2()->Reduce(c, ind2_stmt);
		auto rhs_e = op2->Reduce(c, rhs_stmt);

		red_stmt = MergeStmts(MergeStmts(rhs_reduce, ind1_stmt),
					ind2_stmt, rhs_stmt);

		auto index_assign = make_intrusive<IndexAssignExpr>(ind1_e, ind2_e, rhs_e);
		return TransformMe(index_assign, c, red_stmt);
		}

	if ( lhs_expr->Tag() == EXPR_FIELD )
		{
		auto field_e = lhs_expr->AsFieldExpr();

		StmtPtr lhs_stmt;
		StmtPtr rhs_stmt;

		auto lhs_e = field_e->Op()->Reduce(c, lhs_stmt);
		auto rhs_e = op2->ReduceToFieldAssignment(c, rhs_stmt);

		red_stmt = MergeStmts(rhs_reduce, lhs_stmt, rhs_stmt);

		auto field_name = field_e->FieldName();
		auto field = field_e->Field();
		auto field_assign =
			make_intrusive<FieldLHSAssignExpr>(lhs_e, rhs_e, field_name, field);

		return TransformMe(field_assign, c, red_stmt);
		}

	if ( lhs_expr->Tag() == EXPR_LIST )
		{
		auto lhs_list = lhs_expr->AsListExpr()->Exprs();

		StmtPtr rhs_stmt;
		auto rhs_e = op2->Reduce(c, rhs_stmt);

		auto len = lhs_list.length();
		auto check_stmt = make_intrusive<CheckAnyLenStmt>(rhs_e, len);

		red_stmt = MergeStmts(rhs_reduce, rhs_stmt, check_stmt);

		loop_over_list(lhs_list, i)
			{
			auto rhs_dup = rhs_e->Duplicate();
			auto rhs = make_intrusive<AnyIndexExpr>(rhs_dup, i);
			auto lhs = lhs_list[i]->ThisPtr();
			auto assign = make_intrusive<AssignExpr>(lhs, rhs,
						false, nullptr, nullptr, false);
			auto assign_stmt = make_intrusive<ExprStmt>(assign);
			red_stmt = MergeStmts(red_stmt, assign_stmt);
			}

		return TransformMe(make_intrusive<NopExpr>(), c, red_stmt);
		}

	if ( op2->WillTransform(c) )
		{
		StmtPtr xform_stmt;
		op2 = op2->ReduceToSingleton(c, xform_stmt);
		red_stmt = MergeStmts(rhs_reduce, xform_stmt);
		return ThisPtr();
		}

	red_stmt = op2->ReduceToSingletons(c);

	if ( op2->HasConstantOps() && op2->Tag() != EXPR_TO_ANY_COERCE )
		op2 = c->Fold(op2);

	// Check once again for transformation, this time made possible
	// because the operands have been reduced.  We don't simply
	// always first reduce the operands, because for expressions
	// like && and ||, that's incorrect.

	if ( op2->WillTransform(c) )
		{
		StmtPtr xform_stmt;
		op2 = op2->ReduceToSingleton(c, xform_stmt);
		red_stmt = MergeStmts(rhs_reduce, red_stmt, xform_stmt);
		return ThisPtr();
		}

	StmtPtr lhs_stmt = lhs_ref->ReduceToLHS(c);
	StmtPtr rhs_stmt = op2->ReduceToSingletons(c);

	red_stmt = MergeStmts(MergeStmts(rhs_reduce, red_stmt),
				lhs_stmt, rhs_stmt);

	return ThisPtr();
	}

ExprPtr AssignExpr::ReduceToSingleton(Reducer* c, StmtPtr& red_stmt)
	{
	// Yields a statement performing the assignment and for the
	// expression the LHS (but turned into an RHS).
	if ( op1->Tag() != EXPR_REF )
		Internal("Confusion in AssignExpr::ReduceToSingleton");

	ExprPtr assign_expr = Duplicate();
	auto ae_stmt = make_intrusive<ExprStmt>(assign_expr);
	red_stmt = ae_stmt->Reduce(c);

	return op1->AsRefExprPtr()->GetOp1();
	}


ExprPtr IndexSliceAssignExpr::Duplicate()
	{
	auto op1_d = op1->Duplicate();
	auto op2_d = op2->Duplicate();
	return SetSucc(new IndexSliceAssignExpr(op1_d, op2_d, is_init));
	}


ExprPtr IndexExpr::Duplicate()
	{
	auto op1_d = op1->Duplicate();
	auto op2_l = op2->Duplicate()->AsListExprPtr();
	return SetSucc(new IndexExpr(op1_d, op2_l, is_slice));
	}

bool IndexExpr::HasReducedOps(Reducer* c) const
	{
	if ( ! op1->IsSingleton(c) )
		return NonReduced(this);

	if ( op2->Tag() == EXPR_LIST )
		return op2->HasReducedOps(c);
	else
		{
		if ( op2->IsSingleton(c) )
			return true;

		return NonReduced(this);
		}
	}

StmtPtr IndexExpr::ReduceToSingletons(Reducer* c)
	{
	StmtPtr red1_stmt;
	if ( ! op1->IsSingleton(c) )
		SetOp1(op1->ReduceToSingleton(c, red1_stmt));

	StmtPtr red2_stmt = op2->ReduceToSingletons(c);

	return MergeStmts(red1_stmt, red2_stmt);
	}


ExprPtr IndexExprWhen::Duplicate()
	{
	auto op1_d = op1->Duplicate();
	auto op2_l = op2->Duplicate()->AsListExprPtr();
	return SetSucc(new IndexExprWhen(op1_d, op2_l, is_slice));
	}


ExprPtr FieldExpr::Duplicate()
	{
	return SetSucc(new FieldExpr(op->Duplicate(), field_name));
	}


ExprPtr HasFieldExpr::Duplicate()
	{
	return SetSucc(new HasFieldExpr(op->Duplicate(), field_name));
	}


ExprPtr RecordConstructorExpr::Duplicate()
	{
	auto op_l = op->Duplicate()->AsListExprPtr();

	if ( map )
		{
		auto rt = cast_intrusive<RecordType>(type);
		return SetSucc(new RecordConstructorExpr(rt, op_l));
		}
	else
		return SetSucc(new RecordConstructorExpr(op_l));
	}

bool RecordConstructorExpr::HasReducedOps(Reducer* c) const
	{
	auto& exprs = op->AsListExpr()->Exprs();

	loop_over_list(exprs, i)
		{
		auto e_i = exprs[i];
		if ( ! e_i->AsFieldAssignExprPtr()->Op()->IsSingleton(c) )
			return false;
		}

	return true;
	}

ExprPtr RecordConstructorExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	red_stmt = ReduceToSingletons(c);

	if ( c->Optimizing() )
		return ThisPtr();
	else
		return AssignToTemporary(c, red_stmt);
	}

StmtPtr RecordConstructorExpr::ReduceToSingletons(Reducer* c)
	{
	StmtPtr red_stmt;
	auto& exprs = op->AsListExpr()->Exprs();

	// Could consider merging this code with that for ListExpr::Reduce.
	loop_over_list(exprs, i)
		{
		auto e_i = exprs[i];
		auto fa_i = e_i->AsFieldAssignExprPtr();
		auto fa_i_rhs = e_i->GetOp1();

		if ( c->Optimizing() )
			{
			fa_i->SetOp1(c->UpdateExpr(fa_i_rhs));
			continue;
			}

		if ( fa_i_rhs->IsSingleton(c) )
			continue;

		StmtPtr e_stmt;
		auto rhs_red = fa_i_rhs->ReduceToSingleton(c, e_stmt);
		fa_i->SetOp1(rhs_red);

		if ( e_stmt )
			red_stmt = MergeStmts(red_stmt, e_stmt);
		}

	return red_stmt;
	}


ExprPtr TableConstructorExpr::Duplicate()
	{
	auto op_l = op->Duplicate()->AsListExprPtr();

	TypePtr t;
	if ( (type && type->GetName().size() > 0) ||
	     ! op->AsListExpr()->Exprs().empty() )
		t = type;
	else
		// Use a null type rather than the one inferred, to instruct
		// the constructor to again infer the type.
		t = nullptr;

	return SetSucc(new TableConstructorExpr(op_l, nullptr, t, attrs));
	}

bool TableConstructorExpr::HasReducedOps(Reducer* c) const
	{
	const auto& exprs = op->AsListExpr()->Exprs();

	for ( const auto& expr : exprs )
		{
		auto a = expr->AsAssignExpr();
		// LHS is a list, not a singleton.
		if ( ! a->GetOp1()->HasReducedOps(c) ||
		     ! a->GetOp2()->IsSingleton(c) )
			return NonReduced(this);
		}

	return true;
	}

ExprPtr TableConstructorExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	red_stmt = ReduceToSingletons(c);

	if ( c->Optimizing() )
		return ThisPtr();
	else
		return AssignToTemporary(c, red_stmt);
	}

StmtPtr TableConstructorExpr::ReduceToSingletons(Reducer* c)
	{
	// Need to process the list of initializers directly, as
	// they may be expressed as AssignExpr's, and those get
	// treated quite differently during reduction.
	const auto& exprs = op->AsListExpr()->Exprs();

	StmtPtr red_stmt;

	for ( const auto& expr : exprs )
		{
		if ( expr->Tag() == EXPR_ASSIGN )
			{
			auto a = expr->AsAssignExpr();
			auto op1 = a->GetOp1();
			auto op2 = a->GetOp2();

			if ( c->Optimizing() )
				{
				a->SetOp1(c->UpdateExpr(op1));
				a->SetOp2(c->UpdateExpr(op2));
				continue;
				}

			StmtPtr red1_stmt;
			StmtPtr red2_stmt;

			a->SetOp1(op1->ReduceToSingleton(c, red1_stmt));
			a->SetOp2(op2->ReduceToSingleton(c, red2_stmt));

			red_stmt = MergeStmts(red_stmt, red1_stmt, red2_stmt);
			}

		else
			reporter->InternalError("confused in TableConstructorExpr::Reduce");
		}

	return red_stmt;
	}


ExprPtr SetConstructorExpr::Duplicate()
	{
	auto op_l = op->Duplicate()->AsListExprPtr();

	TypePtr t;
	if ( (type && type->GetName().size() > 0) ||
	     ! op->AsListExpr()->Exprs().empty() )
		t = type;
	else
		// Use a null type rather than the one inferred, to instruct
		// the constructor to again infer the type.
		t = nullptr;

	return SetSucc(new SetConstructorExpr(op_l, nullptr, t, attrs));
	}

bool SetConstructorExpr::HasReducedOps(Reducer* c) const
	{
	return op->IsReduced(c);
	}

ExprPtr SetConstructorExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	// We rely on the fact that ListExpr's don't change into
	// temporaries.
	red_stmt = nullptr;

	(void) op->Reduce(c, red_stmt);

	if ( c->Optimizing() )
		return ThisPtr();
	else
		return AssignToTemporary(c, red_stmt);
	}

StmtPtr SetConstructorExpr::ReduceToSingletons(Reducer* c)
	{
	return op->ReduceToSingletons(c);
	}


ExprPtr VectorConstructorExpr::Duplicate()
	{
	auto op_l = op->Duplicate()->AsListExprPtr();

	if ( op->AsListExpr()->Exprs().empty() )
		return SetSucc(new VectorConstructorExpr(op_l, nullptr));
	else
		return SetSucc(new VectorConstructorExpr(op_l, type));
	}

bool VectorConstructorExpr::HasReducedOps(Reducer* c) const
	{
	return Op()->HasReducedOps(c);
	}


ExprPtr FieldAssignExpr::Duplicate()
	{
	auto op_dup = op->Duplicate();
	return SetSucc(new FieldAssignExpr(field_name.c_str(), op_dup));
	}

ExprPtr FieldAssignExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	if ( c->Optimizing() )
		{
		op = c->UpdateExpr(op);
		return ThisPtr();
		}

	red_stmt = nullptr;

	if ( ! op->IsReduced(c) )
		op = op->ReduceToSingleton(c, red_stmt);

	// Doesn't seem worth checking for constant folding.

	return AssignToTemporary(c, red_stmt);
	}


ExprPtr ArithCoerceExpr::Duplicate()
	{
	auto op_dup = op->Duplicate();

	TypeTag tag;

	if ( type->Tag() == TYPE_VECTOR )
		tag = type->AsVectorType()->Yield()->Tag();
	else
		tag = type->Tag();

	return SetSucc(new ArithCoerceExpr(op_dup, tag));
	}

bool ArithCoerceExpr::WillTransform(Reducer* c) const
	{
	if ( op->Tag() != EXPR_CONST )
		return false;

	if ( IsArithmetic(GetType()->Tag()) )
		return true;

	return IsArithmetic(op->AsConstExpr()->Value()->GetType()->Tag());
	}

ExprPtr ArithCoerceExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	if ( c->Optimizing() )
		op = c->UpdateExpr(op);

	red_stmt = nullptr;

	if ( ! op->IsReduced(c) )
		op = op->ReduceToSingleton(c, red_stmt);

	if ( op->Tag() == EXPR_CONST )
		{
		const auto& t = GetType();
		auto cv = op->AsConstExpr()->ValuePtr();
		const auto& ct = cv->GetType();

		if ( IsArithmetic(t->Tag()) || IsArithmetic(ct->Tag()) )
			{
			if ( auto v = FoldSingleVal(cv, t) )
				return make_intrusive<ConstExpr>(v);
			// else there was a coercion error, fall through
			}
		}

	if ( c->Optimizing() )
		return ThisPtr();

	const auto& ot = op->GetType();
	auto bt = ot->InternalType();
	auto tt = type->InternalType();

	if ( ot->Tag() == TYPE_VECTOR )
		{
		bt = ot->Yield()->InternalType();
		tt = type->Yield()->InternalType();
		}

	if ( bt == tt )
		// Can drop the conversion.
		return op;

	return AssignToTemporary(c, red_stmt);
	}


ExprPtr RecordCoerceExpr::Duplicate()
	{
	auto op_dup = op->Duplicate();
	return SetSucc(new RecordCoerceExpr(op_dup, GetType<RecordType>()));
	}


ExprPtr TableCoerceExpr::Duplicate()
	{
	auto op_dup = op->Duplicate();
	return SetSucc(new TableCoerceExpr(op_dup, GetType<TableType>()));
	}


ExprPtr VectorCoerceExpr::Duplicate()
	{
	auto op_dup = op->Duplicate();
	return SetSucc(new VectorCoerceExpr(op_dup, GetType<VectorType>()));
	}


ExprPtr ScheduleExpr::Duplicate()
	{
	auto when_d = when->Duplicate();
	auto event_d = event->Duplicate()->AsEventExprPtr();
	return SetSucc(new ScheduleExpr(when_d, event_d));
	}

ExprPtr ScheduleExpr::Inline(Inliner* inl)
	{
	when = when->Inline(inl);
	event = event->Inline(inl)->AsEventExprPtr();

	return ThisPtr();
	}

ExprPtr ScheduleExpr::GetOp1() const
	{
	return when;
	}

// We can't inline the following without moving the definition of
// EventExpr in Expr.h to come before that of ScheduleExpr.  Just
// doing this out-of-line seems cleaner.
ExprPtr ScheduleExpr::GetOp2() const
	{
	return event;
	}

void ScheduleExpr::SetOp1(ExprPtr op)
	{
	when = op;
	}

void ScheduleExpr::SetOp2(ExprPtr op)
	{
	event = op->AsEventExprPtr();
	}

bool ScheduleExpr::IsReduced(Reducer* c) const
	{
	return when->IsReduced(c) && event->IsReduced(c);
	}

bool ScheduleExpr::HasReducedOps(Reducer* c) const
	{
	if ( when->IsSingleton(c) && event->IsSingleton(c) )
		return true;

	return NonReduced(this);
	}

ExprPtr ScheduleExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	if ( c->Optimizing() )
		{
		when = c->UpdateExpr(when);
		auto e = c->UpdateExpr(event);
		event = e->AsEventExprPtr();
		}

	red_stmt = nullptr;

	if ( ! when->IsReduced(c) )
		when = when->Reduce(c, red_stmt);

	StmtPtr red2_stmt;
	// We assume that EventExpr won't transform itself fundamentally.
	(void) event->Reduce(c, red2_stmt);

	red_stmt = MergeStmts(red_stmt, red2_stmt);

	return ThisPtr();
	}


ExprPtr InExpr::Duplicate()
	{
	auto op1_d = op1->Duplicate();
	auto op2_d = op2->Duplicate();
	return SetSucc(new InExpr(op1_d, op2_d));
	}

bool InExpr::HasReducedOps(Reducer* c) const
	{
	return op1->HasReducedOps(c) && op2->IsSingleton(c);
	}


ExprPtr CallExpr::Duplicate()
	{
	auto func_d = func->Duplicate();
	auto args_d = args->Duplicate()->AsListExprPtr();
	auto func_type = func->GetType();
	auto in_hook = func_type->AsFuncType()->Flavor() == FUNC_FLAVOR_HOOK;

	return SetSucc(new CallExpr(func_d, args_d, in_hook));
	}

ExprPtr CallExpr::Inline(Inliner* inl)
	{
	auto new_me = inl->CheckForInlining({NewRef{}, this});

	if ( new_me.get() != this )
		return new_me;

	// We're not inlining, but perhaps our elements should be.
	func = func->Inline(inl);
	args = cast_intrusive<ListExpr>(args->Inline(inl));

	return ThisPtr();
	}

bool CallExpr::IsReduced(Reducer* c) const
	{
	return func->IsSingleton(c) && args->IsReduced(c);
	}

bool CallExpr::HasReducedOps(Reducer* c) const
	{
	if ( ! func->IsSingleton(c) )
		return NonReduced(this);

	return args->HasReducedOps(c);
	}

ExprPtr CallExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	if ( c->Optimizing() )
		{
		func = c->UpdateExpr(func);
		auto e = c->UpdateExpr(args);
		args = e->AsListExprPtr();
		return ThisPtr();
		}

	red_stmt = nullptr;

	if ( ! func->IsSingleton(c) )
		func = func->ReduceToSingleton(c, red_stmt);

	StmtPtr red2_stmt;
	// We assume that ListExpr won't transform itself fundamentally.
	(void) args->Reduce(c, red2_stmt);

	// ### could check here for (1) pure function, and (2) all
	// arguments constants, and call it to fold right now.

	red_stmt = MergeStmts(red_stmt, red2_stmt);

	if ( GetType()->Tag() == TYPE_VOID )
		return ThisPtr();
	else
		return AssignToTemporary(c, red_stmt);
	}

StmtPtr CallExpr::ReduceToSingletons(Reducer* c)
	{
	StmtPtr func_stmt;

	if ( ! func->IsSingleton(c) )
		func = func->Reduce(c, func_stmt);

	auto args_stmt = args->ReduceToSingletons(c);

	return MergeStmts(func_stmt, args_stmt);
	}


ExprPtr LambdaExpr::Duplicate()
	{
	auto ingr = std::make_unique<function_ingredients>(*ingredients);
	ingr->body = ingr->body->Duplicate();
	return SetSucc(new LambdaExpr(std::move(ingr), outer_ids));
	}

ExprPtr LambdaExpr::Inline(Inliner* inl)
	{
	// Don't inline these, we currently don't get the closure right.
	return ThisPtr();
	}

ExprPtr LambdaExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	if ( c->Optimizing() )
		return ThisPtr();
	else
		return AssignToTemporary(c, red_stmt);
	}


ExprPtr EventExpr::Duplicate()
	{
	auto args_d = args->Duplicate()->AsListExprPtr();
	return SetSucc(new EventExpr(name.c_str(), args_d));
	}

ExprPtr EventExpr::Inline(Inliner* inl)
	{
	args = cast_intrusive<ListExpr>(args->Inline(inl));
	return ThisPtr();
	}

bool EventExpr::IsReduced(Reducer* c) const
	{
	return Args()->IsReduced(c);
	}

ExprPtr EventExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	if ( c->Optimizing() )
		{
		auto e = c->UpdateExpr(args);
		auto args = e->AsListExprPtr();
		return ThisPtr();
		}

	red_stmt = nullptr;

	if ( ! Args()->IsReduced(c) )
		// We assume that ListExpr won't transform itself fundamentally.
		(void) Args()->Reduce(c, red_stmt);

	return ThisPtr();
	}

StmtPtr EventExpr::ReduceToSingletons(Reducer* c)
	{
	return args->ReduceToSingletons(c);
	}


ExprPtr ListExpr::Duplicate()
	{
	auto new_l = new ListExpr();

	loop_over_list(exprs, i)
		new_l->Append(exprs[i]->Duplicate());

	return SetSucc(new_l);
	}

ExprPtr ListExpr::Inline(Inliner* inl)
	{
	loop_over_list(exprs, i)
		{
		auto in_expr = exprs[i]->Inline(inl);
		Unref(exprs[i]);
		exprs[i] = in_expr.release();
		}

	return ThisPtr();
	}

bool ListExpr::IsReduced(Reducer* c) const
	{
	for ( const auto& expr : exprs )
		if ( ! expr->IsSingleton(c) )
			{
			if ( expr->Tag() != EXPR_LIST || ! expr->IsReduced(c) )
				return NonReduced(expr);
			}

	return true;
	}

bool ListExpr::HasReducedOps(Reducer* c) const
	{
	for ( const auto& expr : exprs )
		{
		// Ugly hack for record constructors.
		if ( expr->Tag() == EXPR_FIELD_ASSIGN )
			{
			if ( ! expr->HasReducedOps(c) )
				return false;
			}
		else if ( ! expr->IsSingleton(c) )
			return false;
		}

	return true;
	}

ExprPtr ListExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	red_stmt = nullptr;

	loop_over_list(exprs, i)
		{
		if ( c->Optimizing() )
			{
			auto e_i = c->UpdateExpr(exprs[i]->ThisPtr());
			auto old = exprs.replace(i, e_i.release());
			Unref(old);
			continue;
			}

		if ( exprs[i]->IsSingleton(c) )
			continue;

		StmtPtr e_stmt;
		auto old = exprs.replace(i,
			exprs[i]->ReduceToSingleton(c, e_stmt).release());
		Unref(old);

		if ( e_stmt )
			red_stmt = MergeStmts(red_stmt, e_stmt);
		}

	return ThisPtr();
	}

StmtPtr ListExpr::ReduceToSingletons(Reducer* c)
	{
	StmtPtr red_stmt;

	loop_over_list(exprs, i)
		{
		if ( exprs[i]->IsSingleton(c) )
			continue;

		StmtPtr e_stmt;
		auto old = exprs.replace(i, exprs[i]->Reduce(c, e_stmt).release());
		Unref(old);

		if ( e_stmt )
			red_stmt = MergeStmts(red_stmt, e_stmt);
		}

	return red_stmt;
	}


ExprPtr CastExpr::Duplicate()
	{
	return SetSucc(new CastExpr(op->Duplicate(), type));
	}


ExprPtr IsExpr::Duplicate()
	{
	return SetSucc(new IsExpr(op->Duplicate(), t));
	}


InlineExpr::InlineExpr(ListExprPtr arg_args, std::vector<IDPtr> arg_params,
			StmtPtr arg_body, int _frame_offset, TypePtr ret_type)
: Expr(EXPR_INLINE), args(std::move(arg_args)), body(std::move(arg_body))
	{
	params = std::move(arg_params);
	frame_offset = _frame_offset;
	type = std::move(ret_type);
	}

bool InlineExpr::IsPure() const
	{
	return args->IsPure() && body->IsPure();
	}

ValPtr InlineExpr::Eval(Frame* f) const
	{
	auto v = eval_list(f, args.get());

	if ( ! v )
		return nullptr;

	int nargs = args->Exprs().length();

	f->Reset(frame_offset + nargs);
	f->AdjustOffset(frame_offset);

	// Assign the arguments.
	for ( auto i = 0; i < nargs; ++i )
		f->SetElement(i, (*v)[i]);

	auto flow = FLOW_NEXT;
	ValPtr result;
	try
		{
		result = body->Exec(f, flow);
		}

	catch ( InterpreterException& e )
		{
		f->AdjustOffset(-frame_offset);
		throw;
		}

	f->AdjustOffset(-frame_offset);

	return result;
	}

ExprPtr InlineExpr::Duplicate()
	{
	auto args_d = args->Duplicate()->AsListExprPtr();
	auto body_d = body->Duplicate();
	return SetSucc(new InlineExpr(args_d, params, body_d, frame_offset, type));
	}

bool InlineExpr::IsReduced(Reducer* c) const
	{
	return NonReduced(this);
	}

ExprPtr InlineExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	// First, reduce each argument and assign it to a parameter.
	// We do this one at a time because that will often allow the
	// optimizer to collapse the final assignment.

	red_stmt = nullptr;

	auto args_list = args->Exprs();

	loop_over_list(args_list, i)
		{
		StmtPtr arg_red_stmt;
		auto red_i = args_list[i]->Reduce(c, arg_red_stmt);

		auto param_i = c->GenInlineBlockName(params[i]);
		auto assign = make_intrusive<AssignExpr>(param_i, red_i,
						false, nullptr, nullptr, false);
		auto assign_stmt = make_intrusive<ExprStmt>(assign);

		red_stmt = MergeStmts(red_stmt, arg_red_stmt, assign_stmt);
		}

	auto ret_val = c->PushInlineBlock(type);
	body = body->Reduce(c);
	c->PopInlineBlock();

	auto catch_ret = make_intrusive<CatchReturnStmt>(body, ret_val);

	red_stmt = MergeStmts(red_stmt, catch_ret);

	return ret_val ? ret_val->Duplicate() : nullptr;
	}

TraversalCode InlineExpr::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreExpr(this);
	HANDLE_TC_EXPR_PRE(tc);

	tc = args->Traverse(cb);
	HANDLE_TC_EXPR_PRE(tc);

	tc = body->Traverse(cb);
	HANDLE_TC_EXPR_PRE(tc);

	tc = cb->PostExpr(this);
	HANDLE_TC_EXPR_POST(tc);
	}

void InlineExpr::ExprDescribe(ODesc* d) const
	{
	if ( d->IsReadable() || d->IsPortable() )
		{
		d->Add("inline(");
		args->Describe(d);
		d->Add("){");
		body->Describe(d);
		d->Add("}");
		}
	else
		{
		args->Describe(d);
		body->Describe(d);
		}
	}


AppendToExpr::AppendToExpr(ExprPtr arg_op1, ExprPtr arg_op2)
	: BinaryExpr(EXPR_APPEND_TO, std::move(arg_op1), std::move(arg_op2))
	{
	// This is an internal type, so we don't bother with type-checking
	// or coercions, those have already been done before we're created.
	SetType(op1->GetType());
	}

ValPtr AppendToExpr::Eval(Frame* f) const
	{
	auto v1 = op1->Eval(f);

	if ( ! v1 )
		return nullptr;

	auto v2 = op2->Eval(f);

	if ( ! v2 )
		return nullptr;

	VectorVal* vv = v1->AsVectorVal();

	if ( ! vv->Assign(vv->Size(), v2) )
		RuntimeError("type-checking failed in vector append");

	return v1;
	}

ExprPtr AppendToExpr::Duplicate()
	{
	auto op1_d = op1->Duplicate();
	auto op2_d = op2->Duplicate();
	return SetSucc(new AppendToExpr(op1_d, op2_d));
	}

bool AppendToExpr::IsReduced(Reducer* c) const
	{
	// These are created reduced.
	return true;
	}

ExprPtr AppendToExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	if ( c->Optimizing() )
		{
		op1 = c->UpdateExpr(op1);
		op2 = c->UpdateExpr(op2);
		}

	return ThisPtr();
	}


IndexAssignExpr::IndexAssignExpr(ExprPtr arg_op1, ExprPtr arg_op2,
					ExprPtr arg_op3)
: BinaryExpr(EXPR_INDEX_ASSIGN, std::move(arg_op1), std::move(arg_op2))
	{
	op3 = arg_op3;
	SetType(op3->GetType());
	}

ValPtr IndexAssignExpr::Eval(Frame* f) const
	{
	auto v1 = op1->Eval(f);
	auto v2 = op2->Eval(f);
	auto v3 = op3->Eval(f);

	AssignToIndex(v1, v2, v3);

	return nullptr;
	}

bool IndexAssignExpr::IsReduced(Reducer* c) const
	{
	// op2 is a ListExpr, not a singleton expression.
	ASSERT(op1->IsSingleton(c) && op2->IsReduced(c) && op3->IsSingleton(c));
	return true;
	}

bool IndexAssignExpr::HasReducedOps(Reducer* c) const
	{
	return true;
	}

ExprPtr IndexAssignExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	if ( c->Optimizing() )
		{
		op1 = c->UpdateExpr(op1);
		op2 = c->UpdateExpr(op2);
		op3 = c->UpdateExpr(op3);
		}

	return ThisPtr();
	}

ExprPtr IndexAssignExpr::ReduceToSingleton(Reducer* c, StmtPtr& red_stmt)
	{
	// Yields a statement performing the assignment and for the
	// expression the LHS (but turned into an RHS).
	if ( op1->Tag() != EXPR_NAME )
		Internal("Confusion in IndexAssignExpr::ReduceToSingleton");

	StmtPtr op1_red_stmt;
	op1 = op1->Reduce(c, op1_red_stmt);

	auto assign_stmt = make_intrusive<ExprStmt>(Duplicate());

	auto index = op2->AsListExprPtr();
	auto res = make_intrusive<IndexExpr>(GetOp1(), index, false);
	auto final_res = res->ReduceToSingleton(c, red_stmt);

	red_stmt = MergeStmts(op1_red_stmt, assign_stmt, red_stmt);

	return final_res;
	}

ExprPtr IndexAssignExpr::Duplicate()
	{
	auto op1_d = op1->Duplicate();
	auto op2_d = op2->Duplicate();
	auto op3_d = op3->Duplicate();

	return SetSucc(new IndexAssignExpr(op1_d, op2_d, op3_d));
	}

TraversalCode IndexAssignExpr::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreExpr(this);
	HANDLE_TC_EXPR_PRE(tc);

	tc = op1->Traverse(cb);
	HANDLE_TC_EXPR_PRE(tc);

	tc = op2->Traverse(cb);
	HANDLE_TC_EXPR_PRE(tc);

	tc = op3->Traverse(cb);
	HANDLE_TC_EXPR_PRE(tc);

	tc = cb->PostExpr(this);
	HANDLE_TC_EXPR_POST(tc);
	}

void IndexAssignExpr::ExprDescribe(ODesc* d) const
	{
	op1->Describe(d);
	if ( d->IsReadable() )
		d->Add("[");

	op2->Describe(d);
	if ( d->IsReadable() )
		{
		d->Add("]");
		d->Add(" []= ");
		}

	op3->Describe(d);
	}


FieldLHSAssignExpr::FieldLHSAssignExpr(ExprPtr arg_op1, ExprPtr arg_op2,
					const char* _field_name, int _field)
: BinaryExpr(EXPR_FIELD_LHS_ASSIGN, std::move(arg_op1), std::move(arg_op2))
	{
	field_name = _field_name;
	field = _field;
	SetType(op2->GetType());
	}

ValPtr FieldLHSAssignExpr::Eval(Frame* f) const
	{
	auto v1 = op1->Eval(f);
	auto v2 = op2->Eval(f);

	if ( v1 && v2 )
		{
		RecordVal* r = v1->AsRecordVal();
		r->Assign(field, std::move(v2));
		}

	return nullptr;
	}

ExprPtr FieldLHSAssignExpr::Duplicate()
	{
	auto op1_d = op1->Duplicate();
	auto op2_d = op2->Duplicate();

	return SetSucc(new FieldLHSAssignExpr(op1_d, op2_d, field_name, field));
	}

bool FieldLHSAssignExpr::IsReduced(Reducer* c) const
	{
	ASSERT(op1->IsSingleton(c) && op2->IsReducedFieldAssignment(c));
	return true;
	}

bool FieldLHSAssignExpr::HasReducedOps(Reducer* c) const
	{
	return true;
	}

ExprPtr FieldLHSAssignExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	if ( c->Optimizing() )
		{
		op1 = c->UpdateExpr(op1);
		op2 = c->UpdateExpr(op2);
		}

	return ThisPtr();
	}

ExprPtr FieldLHSAssignExpr::ReduceToSingleton(Reducer* c, StmtPtr& red_stmt)
	{
	// Yields a statement performing the assignment and for the
	// expression the LHS (but turned into an RHS).
	if ( op1->Tag() != EXPR_NAME )
		Internal("Confusion in FieldLHSAssignExpr::ReduceToSingleton");

	StmtPtr op1_red_stmt;
	op1 = op1->Reduce(c, op1_red_stmt);

	auto assign_stmt = make_intrusive<ExprStmt>(Duplicate());

	auto field_res = make_intrusive<FieldExpr>(op1, field_name);
	StmtPtr field_res_stmt;
	auto res = field_res->ReduceToSingleton(c, field_res_stmt);

	red_stmt = MergeStmts(MergeStmts(op1_red_stmt, assign_stmt),
				red_stmt, field_res_stmt);

	return res;
	}

void FieldLHSAssignExpr::ExprDescribe(ODesc* d) const
	{
	op1->Describe(d);
	if ( d->IsReadable() )
		d->Add("$");

	d->Add(field_name);

	if ( d->IsReadable() )
		d->Add(" $= ");

	op2->Describe(d);
	}


CoerceToAnyExpr::CoerceToAnyExpr(ExprPtr arg_op)
	: UnaryExpr(EXPR_TO_ANY_COERCE, std::move(arg_op))
	{
	type = base_type(TYPE_ANY);
	}

ValPtr CoerceToAnyExpr::Fold(Val* v) const
	{
	return {NewRef{}, v};
	}

ExprPtr CoerceToAnyExpr::Duplicate()
	{
	return SetSucc(new CoerceToAnyExpr(op->Duplicate()));
	}


CoerceFromAnyExpr::CoerceFromAnyExpr(ExprPtr arg_op, TypePtr to_type)
	: UnaryExpr(EXPR_FROM_ANY_COERCE, std::move(arg_op))
	{
	type = std::move(to_type);
	}

ValPtr CoerceFromAnyExpr::Fold(Val* v) const
	{
	auto t = GetType()->Tag();
	auto vt = v->GetType()->Tag();

	if ( vt != t && vt != TYPE_ERROR )
		RuntimeError("incompatible \"any\" type");

	return {NewRef{}, v};
	}

ExprPtr CoerceFromAnyExpr::Duplicate()
	{
	return SetSucc(new CoerceFromAnyExpr(op->Duplicate(), type));
	}


CoerceFromAnyVecExpr::CoerceFromAnyVecExpr(ExprPtr arg_op, TypePtr to_type)
	: UnaryExpr(EXPR_FROM_ANY_VEC_COERCE, std::move(arg_op))
	{
	type = std::move(to_type);
	}

ValPtr CoerceFromAnyVecExpr::Eval(Frame* f) const
	{
	if ( IsError() )
		return nullptr;

	auto v = op->Eval(f);

	if ( ! v )
		return nullptr;

	auto vv = v->AsVectorVal();
	if ( ! vv->Concretize(type->Yield()) )
		RuntimeError("incompatible \"vector of any\" type");

	return v;
	}

ExprPtr CoerceFromAnyVecExpr::Duplicate()
	{
	return SetSucc(new CoerceFromAnyVecExpr(op->Duplicate(), type));
	}


AnyIndexExpr::AnyIndexExpr(ExprPtr arg_op, int _index)
	: UnaryExpr(EXPR_ANY_INDEX, std::move(arg_op))
	{
	index = _index;
	type = op->GetType();
	}

ValPtr AnyIndexExpr::Fold(Val* v) const
	{
	return v->AsListVal()->Idx(index);
	}

ExprPtr AnyIndexExpr::Duplicate()
	{
	return SetSucc(new AnyIndexExpr(op->Duplicate(), index));
	}

ExprPtr AnyIndexExpr::Reduce(Reducer* c, StmtPtr& red_stmt)
	{
	return ThisPtr();
	}

void AnyIndexExpr::ExprDescribe(ODesc* d) const
	{
	if ( d->IsReadable() )
		d->Add("(");

	op->Describe(d);

	if ( d->IsReadable() )
		d->Add(")any [");

	d->Add(index);

	if ( d->IsReadable() )
		d->Add("]");
	}


void NopExpr::ExprDescribe(ODesc* d) const
	{
	if ( d->IsReadable() )
		d->Add("NOP");
	}

ValPtr NopExpr::Eval(Frame* /* f */) const
	{
	return nullptr;
	}

ExprPtr NopExpr::Duplicate()
	{
	return SetSucc(new NopExpr());
	}

TraversalCode NopExpr::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreExpr(this);
	HANDLE_TC_EXPR_PRE(tc);

	tc = cb->PostExpr(this);
	HANDLE_TC_EXPR_POST(tc);
	}


static bool same_singletons(ExprPtr e1, ExprPtr e2)
	{
	auto e1t = e1->Tag();
	auto e2t = e2->Tag();

	if ( (e1t != EXPR_NAME && e1t != EXPR_CONST) ||
	     (e2t != EXPR_NAME && e2t != EXPR_CONST) )
		return false;

	if ( e1t != e2t )
		return false;

	if ( e1t == EXPR_CONST )
		{
		auto c1 = e1->AsConstExpr()->Value();
		auto c2 = e2->AsConstExpr()->Value();

		if ( ! is_atomic_val(c1) || ! is_atomic_val(c2) )
			return false;

		return same_atomic_val(c1, c2);
		}

	auto i1 = e1->AsNameExpr()->Id();
	auto i2 = e2->AsNameExpr()->Id();

	return i1 == i2;
	}


} // namespace zeek::detail
