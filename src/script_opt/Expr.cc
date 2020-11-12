// See the file "COPYING" in the main distribution directory for copyright.

// Optimization-related methods for Expr classes.

#include "Expr.h"
#include "Stmt.h"
#include "Func.h"
#include "Scope.h"
#include "Desc.h"


namespace zeek::detail {


ExprPtr NameExpr::Duplicate()
	{
	return SetSucc(new NameExpr(id, in_const_init));
	}


ExprPtr ConstExpr::Duplicate()
	{
	return SetSucc(new ConstExpr(val));
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


ExprPtr ComplementExpr::Duplicate()
	{
	return SetSucc(new ComplementExpr(op->Duplicate()));
	}


ExprPtr NotExpr::Duplicate()
	{
	return SetSucc(new NotExpr(op->Duplicate()));
	}


ExprPtr PosExpr::Duplicate()
	{
	return SetSucc(new PosExpr(op->Duplicate()));
	}


ExprPtr NegExpr::Duplicate()
	{
	return SetSucc(new NegExpr(op->Duplicate()));
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


ExprPtr AddToExpr::Duplicate()
	{
	auto op1_d = op1->Duplicate();
	auto op2_d = op2->Duplicate();
	return SetSucc(new AddToExpr(op1_d, op2_d));
	}


ExprPtr SubExpr::Duplicate()
	{
	auto op1_d = op1->Duplicate();
	auto op2_d = op2->Duplicate();
	return SetSucc(new SubExpr(op1_d, op2_d));
	}


ExprPtr RemoveFromExpr::Duplicate()
	{
	auto op1_d = op1->Duplicate();
	auto op2_d = op2->Duplicate();
	return SetSucc(new RemoveFromExpr(op1_d, op2_d));
	}


ExprPtr TimesExpr::Duplicate()
	{
	auto op1_d = op1->Duplicate();
	auto op2_d = op2->Duplicate();
	return SetSucc(new TimesExpr(op1_d, op2_d));
	}


ExprPtr DivideExpr::Duplicate()
	{
	auto op1_d = op1->Duplicate();
	auto op2_d = op2->Duplicate();
	return SetSucc(new DivideExpr(op1_d, op2_d));
	}


ExprPtr ModExpr::Duplicate()
	{
	auto op1_d = op1->Duplicate();
	auto op2_d = op2->Duplicate();
	return SetSucc(new ModExpr(op1_d, op2_d));
	}


ExprPtr BoolExpr::Duplicate()
	{
	auto op1_d = op1->Duplicate();
	auto op2_d = op2->Duplicate();
	return SetSucc(new BoolExpr(tag, op1_d, op2_d));
	}


ExprPtr BitExpr::Duplicate()
	{
	auto op1_d = op1->Duplicate();
	auto op2_d = op2->Duplicate();
	return SetSucc(new BitExpr(tag, op1_d, op2_d));
	}


ExprPtr EqExpr::Duplicate()
	{
	auto op1_d = op1->Duplicate();
	auto op2_d = op2->Duplicate();
	return SetSucc(new EqExpr(tag, op1_d, op2_d));
	}


ExprPtr RelExpr::Duplicate()
	{
	auto op1_d = op1->Duplicate();
	auto op2_d = op2->Duplicate();
	return SetSucc(new RelExpr(tag, op1_d, op2_d));
	}


ExprPtr CondExpr::Duplicate()
	{
	auto op1_d = op1->Duplicate();
	auto op2_d = op2->Duplicate();
	auto op3_d = op3->Duplicate();
	return SetSucc(new CondExpr(op1_d, op2_d, op3_d));
	}


ExprPtr RefExpr::Duplicate()
	{
	return SetSucc(new RefExpr(op->Duplicate()));
	}


ExprPtr AssignExpr::Duplicate()
	{
	auto op1_d = op1->Duplicate();
	auto op2_d = op2->Duplicate();
	return SetSucc(new AssignExpr(op1_d, op2_d, is_init, val));
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

	// Leaving the code here for later when we add record construction
	// maps, so hopefully it won't be overlooked.
#if NOT_YET
	if ( map )
		return SetSucc(new RecordConstructorExpr(rt, op_l));
	else
#endif
		return SetSucc(new RecordConstructorExpr(op_l));
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


ExprPtr VectorConstructorExpr::Duplicate()
	{
	auto op_l = op->Duplicate()->AsListExprPtr();

	if ( op->AsListExpr()->Exprs().empty() )
		return SetSucc(new VectorConstructorExpr(op_l, nullptr));
	else
		return SetSucc(new VectorConstructorExpr(op_l, type));
	}


ExprPtr FieldAssignExpr::Duplicate()
	{
	auto op_dup = op->Duplicate();
	return SetSucc(new FieldAssignExpr(field_name.c_str(), op_dup));
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


ExprPtr RecordCoerceExpr::Duplicate()
	{
	auto op_dup = op->Duplicate();
	auto rt = GetType()->AsRecordType();
	RecordTypePtr rt_p = {NewRef{}, rt};
	return SetSucc(new RecordCoerceExpr(op_dup, rt_p));
	}


ExprPtr TableCoerceExpr::Duplicate()
	{
	auto op_dup = op->Duplicate();
	auto tt = GetType()->AsTableType();
	TableTypePtr tt_p = {NewRef{}, tt};
	return SetSucc(new TableCoerceExpr(op_dup, tt_p));
	}


ExprPtr VectorCoerceExpr::Duplicate()
	{
	auto op_dup = op->Duplicate();
	auto vt = GetType()->AsVectorType();
	VectorTypePtr vt_p = {NewRef{}, vt};
	return SetSucc(new VectorCoerceExpr(op_dup, vt_p));
	}


ExprPtr ScheduleExpr::Duplicate()
	{
	auto when_d = when->Duplicate();
	auto event_d = event->Duplicate()->AsEventExprPtr();
	return SetSucc(new ScheduleExpr(when_d, event_d));
	}


ExprPtr InExpr::Duplicate()
	{
	auto op1_d = op1->Duplicate();
	auto op2_d = op2->Duplicate();
	return SetSucc(new InExpr(op1_d, op2_d));
	}


ExprPtr CallExpr::Duplicate()
	{
	auto func_d = func->Duplicate();
	auto args_d = args->Duplicate()->AsListExprPtr();
	auto func_type = func->GetType();
	auto in_hook = func_type->AsFuncType()->Flavor() == FUNC_FLAVOR_HOOK;

	return SetSucc(new CallExpr(func_d, args_d, in_hook));
	}


ExprPtr LambdaExpr::Duplicate()
	{
	auto ingr = std::make_unique<function_ingredients>(*ingredients);
	ingr->body = ingr->body->Duplicate();
	return SetSucc(new LambdaExpr(std::move(ingr), outer_ids));
	}


ExprPtr EventExpr::Duplicate()
	{
	auto args_d = args->Duplicate()->AsListExprPtr();
	return SetSucc(new EventExpr(name.c_str(), args_d));
	}


ExprPtr ListExpr::Duplicate()
	{
	auto new_l = new ListExpr();

	loop_over_list(exprs, i)
		new_l->Append(exprs[i]->Duplicate());

	return SetSucc(new_l);
	}


ExprPtr CastExpr::Duplicate()
	{
	return SetSucc(new CastExpr(op->Duplicate(), type));
	}


ExprPtr IsExpr::Duplicate()
	{
	return SetSucc(new IsExpr(op->Duplicate(), t));
	}

} // namespace zeek::detail
