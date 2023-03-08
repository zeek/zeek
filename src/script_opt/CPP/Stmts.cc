// See the file "COPYING" in the main distribution directory for copyright.

// C++ compiler methods relating to generating code for Stmt's.

#include "zeek/script_opt/CPP/Compile.h"

namespace zeek::detail
	{

using namespace std;

void CPPCompile::GenStmt(const Stmt* s)
	{
	auto loc = s->GetLocationInfo();
	if ( loc != &detail::no_location && s->Tag() != STMT_LIST )
		Emit("// %s:%s", loc->filename, to_string(loc->first_line));

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

		case STMT_WHEN:
			GenWhenStmt(static_cast<const WhenStmt*>(s));
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

	if ( in_hook )
		Emit("return true;");

	else if ( ! e && ret_type && ret_type->Tag() != TYPE_VOID )
		// This occurs for ExpressionlessReturnOkay() functions.
		Emit("return nullptr;");

	else if ( ! ret_type || ! e || e->GetType()->Tag() == TYPE_VOID )
		Emit("return;");

	else
		{
		auto gt = ret_type->Tag() == TYPE_ANY ? GEN_VAL_PTR : GEN_NATIVE;
		auto ret = GenExpr(e, gt);

		if ( e->GetType()->Tag() == TYPE_ANY )
			ret = GenericValPtrToGT(ret, ret_type, gt);

		Emit("return %s;", ret);
		}
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

	if ( sw->TypeMap()->empty() )
		GenValueSwitchStmt(e, cases);
	else
		GenTypeSwitchStmt(e, cases);
	}

void CPPCompile::GenTypeSwitchStmt(const Expr* e, const case_list* cases)
	{
	// Start a scoping block so we avoid naming conflicts if a function
	// has multiple type switches.
	Emit("{");
	Emit("static std::vector<int> CPP__switch_types =");
	StartBlock();

	for ( const auto& c : *cases )
		{
		auto tc = c->TypeCases();
		if ( tc )
			for ( auto id : *tc )
				Emit(Fmt(TypeOffset(id->GetType())) + ",");
		}
	EndBlock(true);

	NL();

	Emit("ValPtr CPP__sw_val = %s;", GenExpr(e, GEN_VAL_PTR));
	Emit("auto& CPP__sw_val_t = CPP__sw_val->GetType();");
	Emit("int CPP__sw_type_ind = 0;");

	Emit("for ( auto CPP__st : CPP__switch_types )");
	StartBlock();
	Emit("if ( can_cast_value_to_type(CPP__sw_val.get(), CPP__Type__[CPP__st].get()) )");
	Emit("\tbreak;");
	Emit("++CPP__sw_type_ind;");
	EndBlock();

	Emit("switch ( CPP__sw_type_ind ) {");

	++break_level;

	int case_offset = 0;

	for ( const auto& c : *cases )
		{
		auto tc = c->TypeCases();
		if ( tc )
			{
			bool is_multi = tc->size() > 1;
			for ( auto id : *tc )
				GenTypeSwitchCase(id, case_offset++, is_multi);
			}
		else
			Emit("default:");

		StartBlock();
		GenStmt(c->Body());
		EndBlock();
		}

	--break_level;

	Emit("}"); // end the switch
	Emit("}"); // end the scoping block
	}

void CPPCompile::GenTypeSwitchCase(const ID* id, int case_offset, bool is_multi)
	{
	Emit("case %s:", Fmt(case_offset));

	if ( ! id->Name() )
		// No assignment, we're done.
		return;

	// It's an assignment case.  If it's a collection of multiple cases,
	// assign to the variable only for this particular case.
	IndentUp();

	if ( is_multi )
		{
		Emit("if ( CPP__sw_type_ind == %s )", Fmt(case_offset));
		IndentUp();
		}

	auto targ_val = "CPP__sw_val.get()";
	auto targ_type = string("CPP__Type__[CPP__switch_types[") + Fmt(case_offset) + "]].get()";

	auto cast = string("cast_value_to_type(") + targ_val + ", " + targ_type + ")";

	Emit("%s = %s;", LocalName(id), GenericValPtrToGT(cast, id->GetType(), GEN_NATIVE));

	IndentDown();

	if ( is_multi )
		IndentDown();
	}

void CPPCompile::GenValueSwitchStmt(const Expr* e, const case_list* cases)
	{
	auto e_it = e->GetType()->InternalType();
	bool is_int = e_it == TYPE_INTERNAL_INT;
	bool is_uint = e_it == TYPE_INTERNAL_UNSIGNED;
	bool organic = is_int || is_uint;

	string sw_val;

	if ( organic )
		sw_val = GenExpr(e, GEN_NATIVE);
	else
		sw_val = string("p_hash(") + GenExpr(e, GEN_VAL_PTR) + ")";

	Emit("switch ( %s ) {", sw_val);

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

void CPPCompile::GenWhenStmt(const WhenStmt* w)
	{
	auto wi = w->Info();
	auto wl = wi->Lambda();

	if ( ! wl )
		reporter->FatalError("cannot compile deprecated \"when\" statement");

	auto is_return = wi->IsReturn() ? "true" : "false";
	auto timeout = wi->TimeoutExpr();
	auto timeout_val = timeout ? GenExpr(timeout, GEN_NATIVE) : "-1.0";
	auto loc = w->GetLocationInfo();

	Emit("{ // begin a new scope for internal variables");

	Emit("static WhenInfo* CPP__wi = nullptr;");
	Emit("static IDSet CPP__w_globals;");

	NL();

	Emit("if ( ! CPP__wi )");
	StartBlock();
	Emit("CPP__wi = new WhenInfo(%s);", is_return);
	for ( auto& wg : wi->WhenExprGlobals() )
		Emit("CPP__w_globals.insert(find_global__CPP(\"%s\").get());", wg->Name());
	EndBlock();
	NL();

	Emit("std::vector<ValPtr> CPP__local_aggrs;");
	for ( auto l : wi->WhenExprLocals() )
		if ( IsAggr(l->GetType()) )
			Emit("CPP__local_aggrs.emplace_back(%s);", IDNameStr(l));

	Emit("CPP__wi->Instantiate(%s);", GenExpr(wi->Lambda(), GEN_NATIVE));

	// We need a new frame for the trigger to unambiguously associate
	// with, in case we're called multiple times with our existing frame.
	Emit("auto new_frame = make_intrusive<Frame>(0, nullptr, nullptr);");
	Emit("auto curr_t = f__CPP->GetTrigger();");
	Emit("auto curr_assoc = f__CPP->GetTriggerAssoc();");
	Emit("new_frame->SetTrigger({NewRef{}, curr_t});");
	Emit("new_frame->SetTriggerAssoc(curr_assoc);");

	Emit("auto t = new trigger::Trigger(CPP__wi, %s, CPP__w_globals, CPP__local_aggrs, "
	     "new_frame.get(), "
	     "nullptr);",
	     timeout_val);

	auto loc_str = util::fmt("%s:%d-%d", loc->filename, loc->first_line, loc->last_line);
	Emit("t->SetName(\"%s\");", loc_str);

	if ( ret_type && ret_type->Tag() != TYPE_VOID )
		{
		Emit("ValPtr retval = {NewRef{}, curr_t->Lookup(curr_assoc)};");
		Emit("if ( ! retval )");
		Emit("\tthrow DelayedCallException();");
		Emit("return %s;", GenericValPtrToGT("retval", ret_type, GEN_NATIVE));
		}

	Emit("}");
	}

void CPPCompile::GenForStmt(const ForStmt* f)
	{
	Emit("{ // begin a new scope for the internal loop vars");

	++break_level;

	auto v = f->StmtExprPtr();
	auto t = v->GetType()->Tag();
	auto loop_vars = f->LoopVars();
	auto value_var = f->ValueVar();

	if ( t == TYPE_TABLE )
		GenForOverTable(v, value_var, loop_vars);

	else if ( t == TYPE_VECTOR )
		GenForOverVector(v, value_var, loop_vars);

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
	Emit("auto* current_tev__CPP = lve__CPP.value;");
	Emit("auto ind_lv__CPP = tv__CPP->RecreateIndex(*k__CPP);");

	if ( value_var && ! value_var->IsBlank() )
		Emit("%s = %s;", IDName(value_var),
		     GenericValPtrToGT("current_tev__CPP->GetVal()", value_var->GetType(), GEN_NATIVE));

	for ( int i = 0; i < loop_vars->length(); ++i )
		{
		auto var = (*loop_vars)[i];
		if ( var->IsBlank() )
			continue;

		const auto& v_t = var->GetType();
		auto acc = NativeAccessor(v_t);

		if ( IsNativeType(v_t) )
			Emit("%s = ind_lv__CPP->Idx(%s)%s;", IDName(var), Fmt(i), acc);
		else
			Emit("%s = {NewRef{}, ind_lv__CPP->Idx(%s)%s};", IDName(var), Fmt(i), acc);
		}
	}

void CPPCompile::GenForOverVector(const ExprPtr& vec, const IDPtr& value_var,
                                  const IDPList* loop_vars)
	{
	Emit("auto vv__CPP = %s;", GenExpr(vec, GEN_DONT_CARE));

	Emit("for ( auto i__CPP = 0u; i__CPP < vv__CPP->Size(); ++i__CPP )");
	StartBlock();

	Emit("if ( ! vv__CPP->Has(i__CPP) ) continue;");

	auto lv0 = (*loop_vars)[0];

	if ( ! lv0->IsBlank() )
		Emit("%s = i__CPP;", IDName(lv0));

	if ( value_var && ! value_var->IsBlank() )
		{
		auto vv = IDName(value_var);
		auto access = "vv__CPP->ValAt(i__CPP)";
		auto native = GenericValPtrToGT(access, value_var->GetType(), GEN_NATIVE);
		Emit("%s = %s;", IDName(value_var), native);
		}
	}

void CPPCompile::GenForOverString(const ExprPtr& str, const IDPList* loop_vars)
	{
	Emit("auto sval__CPP = %s;", GenExpr(str, GEN_DONT_CARE));

	Emit("for ( auto i__CPP = 0; i__CPP < sval__CPP->Len(); ++i__CPP )");
	StartBlock();

	Emit("auto sv__CPP = make_intrusive<StringVal>(1, (const char*) sval__CPP->Bytes() + i__CPP);");

	auto lv0 = (*loop_vars)[0];
	if ( ! lv0->IsBlank() )
		Emit("%s = std::move(sv__CPP);", IDName(lv0));
	}

	} // zeek::detail
