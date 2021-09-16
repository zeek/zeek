// See the file "COPYING" in the main distribution directory for copyright.

// C++ compiler methods relating to generating code for Stmt's.

#include "zeek/script_opt/CPP/Compile.h"

namespace zeek::detail
	{

using namespace std;

void CPPCompile::GenStmt(const Stmt* s)
	{
	switch ( s->Tag() )
		{
		case STMT_INIT:
			GenInitStmt(s->AsInitStmt());
			break;

		case STMT_LIST:
				{
				// These always occur in contexts surrounded by {}'s,
				// so no need to add them explicitly.
				auto sl = s->AsStmtList();
				const auto& stmts = sl->Stmts();

				for ( const auto& stmt : stmts )
					GenStmt(stmt);
				}
			break;

		case STMT_EXPR:
			if ( auto e = s->AsExprStmt()->StmtExpr() )
				Emit("%s;", GenExpr(e, GEN_DONT_CARE, true));
			break;

		case STMT_IF:
			GenIfStmt(s->AsIfStmt());
			break;

		case STMT_WHILE:
			GenWhileStmt(s->AsWhileStmt());
			break;

		case STMT_NULL:
			Emit(";");
			break;

		case STMT_RETURN:
			GenReturnStmt(s->AsReturnStmt());
			break;

		case STMT_ADD:
			GenAddStmt(static_cast<const ExprStmt*>(s));
			break;

		case STMT_DELETE:
			GenDeleteStmt(static_cast<const ExprStmt*>(s));
			break;

		case STMT_EVENT:
			GenEventStmt(static_cast<const EventStmt*>(s));
			break;

		case STMT_SWITCH:
			GenSwitchStmt(static_cast<const SwitchStmt*>(s));
			break;

		case STMT_FOR:
			GenForStmt(s->AsForStmt());
			break;

		case STMT_NEXT:
			Emit("continue;");
			break;

		case STMT_BREAK:
			if ( break_level > 0 )
				Emit("break;");
			else
				Emit("return false;");
			break;

		case STMT_PRINT:
				{
				auto el = static_cast<const ExprListStmt*>(s)->ExprList();
				Emit("do_print_stmt({%s});", GenExpr(el, GEN_VAL_PTR));
				}
			break;

		case STMT_FALLTHROUGH:
			break;

		case STMT_WHEN:
			ASSERT(0);
			break;

		default:
			reporter->InternalError("bad statement type in CPPCompile::GenStmt");
		}
	}

void CPPCompile::GenInitStmt(const InitStmt* init)
	{
	auto inits = init->Inits();

	for ( const auto& aggr : inits )
		{
		const auto& t = aggr->GetType();

		if ( ! IsAggr(t->Tag()) )
			continue;

		auto type_name = IntrusiveVal(t);
		auto type_type = TypeType(t);
		auto type_ind = GenTypeName(t);

		if ( locals.count(aggr.get()) == 0 )
			{
			// fprintf(stderr, "aggregate %s unused\n", obj_desc(aggr.get()).c_str());
			continue;
			}

		Emit("%s = make_intrusive<%s>(cast_intrusive<%s>(%s));", IDName(aggr), type_name, type_type,
		     type_ind);
		}
	}

void CPPCompile::GenIfStmt(const IfStmt* i)
	{
	auto cond = i->StmtExpr();

	Emit("if ( %s )", GenExpr(cond, GEN_NATIVE));
	StartBlock();
	GenStmt(i->TrueBranch());
	EndBlock();

	const auto& fb = i->FalseBranch();

	if ( fb->Tag() != STMT_NULL )
		{
		Emit("else");
		StartBlock();
		GenStmt(i->FalseBranch());
		EndBlock();
		}
	}

void CPPCompile::GenWhileStmt(const WhileStmt* w)
	{
	Emit("while ( %s )", GenExpr(w->Condition(), GEN_NATIVE));

	StartBlock();

	++break_level;
	GenStmt(w->Body());
	--break_level;

	EndBlock();
	}

void CPPCompile::GenReturnStmt(const ReturnStmt* r)
	{
	auto e = r->StmtExpr();

	if ( ! ret_type || ! e || e->GetType()->Tag() == TYPE_VOID || in_hook )
		{
		if ( in_hook )
			Emit("return true;");
		else
			Emit("return;");

		return;
		}

	auto gt = ret_type->Tag() == TYPE_ANY ? GEN_VAL_PTR : GEN_NATIVE;
	auto ret = GenExpr(e, gt);

	if ( e->GetType()->Tag() == TYPE_ANY )
		ret = GenericValPtrToGT(ret, ret_type, gt);

	Emit("return %s;", ret);
	}

void CPPCompile::GenAddStmt(const ExprStmt* es)
	{
	auto op = es->StmtExpr();
	auto aggr = GenExpr(op->GetOp1(), GEN_DONT_CARE);
	auto indices = op->GetOp2();

	Emit("add_element__CPP(%s, index_val__CPP({%s}));", aggr, GenExpr(indices, GEN_VAL_PTR));
	}

void CPPCompile::GenDeleteStmt(const ExprStmt* es)
	{
	auto op = es->StmtExpr();
	auto aggr = op->GetOp1();
	auto aggr_gen = GenExpr(aggr, GEN_VAL_PTR);

	if ( op->Tag() == EXPR_INDEX )
		{
		auto indices = op->GetOp2();

		Emit("remove_element__CPP(%s, index_val__CPP({%s}));", aggr_gen,
		     GenExpr(indices, GEN_VAL_PTR));
		}

	else
		{
		ASSERT(op->Tag() == EXPR_FIELD);
		auto field = GenField(aggr, op->AsFieldExpr()->Field());
		Emit("%s->Remove(%s);", aggr_gen, field);
		}
	}

void CPPCompile::GenEventStmt(const EventStmt* ev)
	{
	auto ev_s = ev->StmtExprPtr();
	auto ev_e = cast_intrusive<EventExpr>(ev_s);
	auto ev_n = ev_e->Name();

	RegisterEvent(ev_n);

	if ( ev_e->Args()->Exprs().length() > 0 )
		Emit("event_mgr.Enqueue(%s_ev, %s);", globals[string(ev_n)],
		     GenExpr(ev_e->Args(), GEN_VAL_PTR));
	else
		Emit("event_mgr.Enqueue(%s_ev, Args{});", globals[string(ev_n)]);
	}

void CPPCompile::GenSwitchStmt(const SwitchStmt* sw)
	{
	auto e = sw->StmtExpr();
	auto cases = sw->Cases();

	auto e_it = e->GetType()->InternalType();
	bool is_int = e_it == TYPE_INTERNAL_INT;
	bool is_uint = e_it == TYPE_INTERNAL_UNSIGNED;
	bool organic = is_int || is_uint;

	string sw_val;

	if ( organic )
		sw_val = GenExpr(e, GEN_NATIVE);
	else
		sw_val = string("p_hash(") + GenExpr(e, GEN_VAL_PTR) + ")";

	Emit("switch ( %s ) {", sw_val.c_str());

	++break_level;

	for ( const auto& c : *cases )
		{
		if ( c->ExprCases() )
			{
			const auto& c_e_s = c->ExprCases()->AsListExpr()->Exprs();

			for ( const auto& c_e : c_e_s )
				{
				auto c_v = c_e->Eval(nullptr);
				ASSERT(c_v);

				string c_v_rep;

				if ( is_int )
					c_v_rep = Fmt(int(c_v->AsInt()));
				else if ( is_uint )
					c_v_rep = Fmt(p_hash_type(c_v->AsCount()));
				else
					c_v_rep = Fmt(p_hash(c_v));

				Emit("case %s:", c_v_rep);
				}
			}

		else
			Emit("default:");

		StartBlock();
		GenStmt(c->Body());
		EndBlock();
		}

	--break_level;

	Emit("}");
	}

void CPPCompile::GenForStmt(const ForStmt* f)
	{
	Emit("{ // begin a new scope for the internal loop vars");

	++break_level;

	auto v = f->StmtExprPtr();
	auto t = v->GetType()->Tag();
	auto loop_vars = f->LoopVars();

	if ( t == TYPE_TABLE )
		GenForOverTable(v, f->ValueVar(), loop_vars);

	else if ( t == TYPE_VECTOR )
		GenForOverVector(v, loop_vars);

	else if ( t == TYPE_STRING )
		GenForOverString(v, loop_vars);

	else
		reporter->InternalError("bad for statement in CPPCompile::GenStmt");

	GenStmt(f->LoopBody());
	EndBlock();

	if ( t == TYPE_TABLE )
		EndBlock();

	--break_level;

	Emit("} // end of for scope");
	}

void CPPCompile::GenForOverTable(const ExprPtr& tbl, const IDPtr& value_var,
                                 const IDPList* loop_vars)
	{
	Emit("auto tv__CPP = %s;", GenExpr(tbl, GEN_DONT_CARE));
	Emit("const PDict<TableEntryVal>* loop_vals__CPP = tv__CPP->AsTable();");

	Emit("if ( loop_vals__CPP->Length() > 0 )");
	StartBlock();

	Emit("for ( const auto& lve__CPP : *loop_vals__CPP )");
	StartBlock();

	Emit("auto k__CPP = lve__CPP.GetHashKey();");
	Emit("auto* current_tev__CPP = lve__CPP.GetValue<TableEntryVal*>();");
	Emit("auto ind_lv__CPP = tv__CPP->RecreateIndex(*k__CPP);");

	if ( value_var )
		Emit("%s = %s;", IDName(value_var),
		     GenericValPtrToGT("current_tev__CPP->GetVal()", value_var->GetType(), GEN_NATIVE));

	for ( int i = 0; i < loop_vars->length(); ++i )
		{
		auto var = (*loop_vars)[i];
		const auto& v_t = var->GetType();
		auto acc = NativeAccessor(v_t);

		if ( IsNativeType(v_t) )
			Emit("%s = ind_lv__CPP->Idx(%s)%s;", IDName(var), Fmt(i), acc);
		else
			Emit("%s = {NewRef{}, ind_lv__CPP->Idx(%s)%s};", IDName(var), Fmt(i), acc);
		}
	}

void CPPCompile::GenForOverVector(const ExprPtr& vec, const IDPList* loop_vars)
	{
	Emit("auto vv__CPP = %s;", GenExpr(vec, GEN_DONT_CARE));

	Emit("for ( auto i__CPP = 0u; i__CPP < vv__CPP->Size(); ++i__CPP )");
	StartBlock();

	Emit("if ( ! vv__CPP->Has(i__CPP) ) continue;");
	Emit("%s = i__CPP;", IDName((*loop_vars)[0]));
	}

void CPPCompile::GenForOverString(const ExprPtr& str, const IDPList* loop_vars)
	{
	Emit("auto sval__CPP = %s;", GenExpr(str, GEN_DONT_CARE));

	Emit("for ( auto i__CPP = 0u; i__CPP < sval__CPP->Len(); ++i__CPP )");
	StartBlock();

	Emit("auto sv__CPP = make_intrusive<StringVal>(1, (const char*) sval__CPP->Bytes() + i__CPP);");
	Emit("%s = std::move(sv__CPP);", IDName((*loop_vars)[0]));
	}

	} // zeek::detail
