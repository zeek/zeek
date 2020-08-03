// See the file "COPYING" in the main distribution directory for copyright.

// This file includes the ZAM methods associated with generating an
// initial, complete intermediary ZAM body for a given function.
// Optimization of that ZAM body is factored out into ZOpt.cc.

#include "ZAM.h"
#include "CompHash.h"
#include "RE.h"
#include "Frame.h"
#include "Reduce.h"
#include "Scope.h"
#include "ProfileFunc.h"
#include "ScriptAnaly.h"
#include "BroString.h"
#include "Reporter.h"


class OpaqueVals {
public:
	OpaqueVals(ZInstAux* _aux)	{ aux = _aux; }

	ZInstAux* aux;
};


// Helper functions, to translate NameExpr*'s to slots.  Some aren't
// needed, but we provide a complete set mirroring those for ZInstI
// for consistency.
ZInstI GenInst(ZAM* m, ZOp op)
	{
	return ZInstI(op);
	}

ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v1)
	{
	return ZInstI(op, m->Frame1Slot(v1, op));
	}

ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v1, int i)
	{
	auto z = ZInstI(op, m->Frame1Slot(v1, op), i);
	z.op_type = OP_VV_I2;
	return z;
	}

ZInstI GenInst(ZAM* m, ZOp op, const ConstExpr* c, const NameExpr* v1, int i)
	{
	auto z = ZInstI(op, m->Frame1Slot(v1, op), i, c);
	z.op_type = OP_VVC_I2;
	return z;
	}

ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2)
	{
	int nv2 = m->FrameSlot(v2);
	return ZInstI(op, m->Frame1Slot(v1, op), nv2);
	}

ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2,
		const NameExpr* v3)
	{
	int nv2 = m->FrameSlot(v2);
	int nv3 = m->FrameSlot(v3);
	return ZInstI(op, m->Frame1Slot(v1, op), nv2, nv3);
	}

ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2,
		const NameExpr* v3, const NameExpr* v4)
	{
	int nv2 = m->FrameSlot(v2);
	int nv3 = m->FrameSlot(v3);
	int nv4 = m->FrameSlot(v4);
	return ZInstI(op, m->Frame1Slot(v1, op), nv2, nv3, nv4);
	}

ZInstI GenInst(ZAM* m, ZOp op, const ConstExpr* ce)
	{
	return ZInstI(op, ce);
	}

ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v1, const ConstExpr* ce)
	{
	return ZInstI(op, m->Frame1Slot(v1, op), ce);
	}

ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v1, const ConstExpr* ce,
		const NameExpr* v2)
	{
	int nv2 = m->FrameSlot(v2);
	return ZInstI(op, m->Frame1Slot(v1, op), nv2, ce);
	}
ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2,
		const ConstExpr* ce)
	{
	int nv2 = m->FrameSlot(v2);
	return ZInstI(op, m->Frame1Slot(v1, op), nv2, ce);
	}

ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2,
		const NameExpr* v3, const ConstExpr* ce)
	{
	int nv2 = m->FrameSlot(v2);
	int nv3 = m->FrameSlot(v3);
	return ZInstI(op, m->Frame1Slot(v1, op), nv2, nv3, ce);
	}
ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2,
		const ConstExpr* ce, const NameExpr* v3)
	{
	// Note that here we reverse the order of the arguments; saves
	// us from needing to implement a redundant constructor.
	int nv2 = m->FrameSlot(v2);
	int nv3 = m->FrameSlot(v3);
	return ZInstI(op, m->Frame1Slot(v1, op), nv2, nv3, ce);
	}

ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v1, const ConstExpr* c, int i)
	{
	auto z = ZInstI(op, m->Frame1Slot(v1, op), i, c);
	z.op_type = OP_VVC_I2;
	return z;
	}
ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2, int i)
	{
	int nv2 = m->FrameSlot(v2);
	auto z = ZInstI(op, m->Frame1Slot(v1, op), nv2, i);
	z.op_type = OP_VVV_I3;
	return z;
	}
ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2,
		int i1, int i2)
	{
	int nv2 = m->FrameSlot(v2);
	auto z = ZInstI(op, m->Frame1Slot(v1, op), nv2, i1, i2);
	z.op_type = OP_VVVV_I3_I4;
	return z;
	}
ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v, const ConstExpr* c,
		int i1, int i2)
	{
	auto z = ZInstI(op, m->Frame1Slot(v, op), i1, i2, c);
	z.op_type = OP_VVVC_I2_I3;
	return z;
	}

ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2,
		const NameExpr* v3, int i)
	{
	int nv2 = m->FrameSlot(v2);
	int nv3 = m->FrameSlot(v3);
	auto z = ZInstI(op, m->Frame1Slot(v1, op), nv2, nv3, i);
	z.op_type = OP_VVVV_I4;
	return z;
	}
ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2,
		const ConstExpr* c, int i)
	{
	int nv2 = m->FrameSlot(v2);
	auto z = ZInstI(op, m->Frame1Slot(v1, op), nv2, i, c);
	z.op_type = OP_VVVC_I3;
	return z;
	}
ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v1, const ConstExpr* c,
		const NameExpr* v2, int i)
	{
	int nv2 = m->FrameSlot(v2);
	auto z = ZInstI(op, m->Frame1Slot(v1, op), nv2, i, c);
	z.op_type = OP_VVVC_I3;
	return z;
	}


ZAM::ZAM(BroFunc* f, Scope* _scope, Stmt* _body,
		UseDefs* _ud, Reducer* _rd, ProfileFunc* _pf)
	{
	func = f;
	scope = _scope;
	body = _body;
	body->Ref();
	ud = _ud;
	reducer = _rd;
	pf = _pf;
	frame_sizeI = 0;

	Init();
	}

ZAM::~ZAM()
	{
	Unref(body);
	delete ud;
	delete reducer;
	delete pf;
	}

Stmt* ZAM::CompileBody()
	{
	curr_stmt = nullptr;

	if ( func->Flavor() == FUNC_FLAVOR_HOOK )
		PushBreaks();

	(void) body->Compile(this);

	if ( LastStmt(body)->Tag() != STMT_RETURN )
		SyncGlobals(nullptr);

	if ( breaks.size() > 0 )
		{
		ASSERT(breaks.size() == 1);

		if ( func->Flavor() == FUNC_FLAVOR_HOOK )
			{
			// Rewrite the breaks.
			for ( auto b : breaks[0] )
				{
				auto& i = insts1[b.stmt_num];
				delete i;
				i = new ZInstI(OP_HOOK_BREAK_X);
				}
			}

		else
			reporter->Error("\"break\" used without an enclosing \"for\" or \"switch\"");
		}

	if ( nexts.size() > 0 )
		reporter->Error("\"next\" used without an enclosing \"for\"");

	if ( fallthroughs.size() > 0 )
		reporter->Error("\"fallthrough\" used without an enclosing \"switch\"");

	if ( catches.size() > 0 )
		reporter->InternalError("untargeted inline return");

	// Make sure we have a (pseudo-)instruction at the end so we
	// can use it as a branch label.
	if ( ! pending_inst )
		pending_inst = new ZInstI();

	// Concretize instruction numbers in inst1 so we can
	// easily move through the code.
	for ( auto i = 0; i < insts1.size(); ++i )
		insts1[i]->inst_num = i;

	// Compute which instructions are inside loops.
	for ( auto i = 0; i < insts1.size(); ++i )
		{
		auto inst = insts1[i];

		auto t = inst->target;
		if ( ! t || t == pending_inst )
			continue;

		if ( t->inst_num < i )
			{
			auto j = t->inst_num;

			if ( ! t->loop_start )
				{
				// Loop is newly discovered.
				t->loop_start = true;
				}
			else
				{
				// We're extending an existing loop.  Find
				// its current end.
				auto depth = t->loop_depth;
				while ( j < i &&
					insts1[j]->loop_depth == depth )
					++j;

				ASSERT(insts1[j]->loop_depth == depth - 1);
				}

			// Run from j's current position to i, bumping
			// the loop depth.
			while ( j <= i )
				{
				++insts1[j]->loop_depth;
				++j;
				}
			}

		ASSERT(! inst->target2 || inst->target2->inst_num > i);
		}

	if ( ! analysis_options.no_ZAM_opt )
		OptimizeInsts();

	// Move branches to dead code forward to their successor live code.
	for ( auto i = 0; i < insts1.size(); ++i )
		{
		auto inst = insts1[i];
		if ( ! inst->live )
			continue;

		auto t = inst->target;

		if ( ! t )
			continue;

		inst->target = FindLiveTarget(t);

		if ( inst->target2 )
			inst->target2 = FindLiveTarget(inst->target2);
		}

	// Construct the final program with the dead code eliminated
	// and branches resolved.

	// Make sure we don't include the empty pending-instruction,
	// if any.
	if ( pending_inst )
		pending_inst->live = false;

	// Maps inst1 instructions to where they are in inst2.
	// Dead instructions map to -1.
	std::vector<int> inst1_to_inst2;

	for ( auto i = 0; i < insts1.size(); ++i )
		{
		if ( insts1[i]->live )
			{
			inst1_to_inst2.push_back(insts2.size());
			insts2.push_back(insts1[i]);
			}
		else
			inst1_to_inst2.push_back(-1);
		}

	// Re-concretize instruction numbers, and concretize GoTo's.
	for ( auto i = 0; i < insts2.size(); ++i )
		insts2[i]->inst_num = i;

	for ( auto i = 0; i < insts2.size(); ++i )
		{
		auto inst = insts2[i];

		if ( inst->target )
			{
			RetargetBranch(inst, inst->target, inst->target_slot);

			if ( inst->target2 )
				RetargetBranch(inst, inst->target2,
						inst->target2_slot);
			}
		}

	// If we have remapped frame denizens, update them.  If not,
	// create them.
	if ( shared_frame_denizens.size() > 0 )
		{ // update
		for ( auto i = 0; i < shared_frame_denizens.size(); ++i )
			{
			auto& info = shared_frame_denizens[i];

			for ( auto& start : info.id_start )
				start = inst1_to_inst2[start];

			shared_frame_denizens_final.push_back(info);
			}
		}

	else
		{ // create
		for ( auto i = 0; i < frame_denizens.size(); ++i )
			{
			FrameSharingInfo info;
			info.ids.push_back(frame_denizens[i]);
			info.id_start.push_back(0);
			info.scope_end = insts2.size();

			// The following doesn't matter since the value
			// is only used during compiling, not during
			// execution.
			info.is_managed = false;

			shared_frame_denizens_final.push_back(info);
			}
		}

	delete pending_inst;

	// Create concretized versions of any case tables.
	ZBody::CaseMaps<bro_int_t> int_cases;
	ZBody::CaseMaps<bro_uint_t> uint_cases;
	ZBody::CaseMaps<double> double_cases;
	ZBody::CaseMaps<std::string> str_cases;

#define CONCRETIZE_SWITCH_TABLES(T, switchesI, switches) \
	for ( auto& targs : switchesI ) \
		{ \
		ZBody::CaseMap<T> cm; \
		for ( auto& targ : targs ) \
			cm[targ.first] = targ.second->inst_num; \
		switches.push_back(cm); \
		}

	CONCRETIZE_SWITCH_TABLES(bro_int_t, int_casesI, int_cases);
	CONCRETIZE_SWITCH_TABLES(bro_uint_t, uint_casesI, uint_cases);
	CONCRETIZE_SWITCH_TABLES(double, double_casesI, double_cases);
	CONCRETIZE_SWITCH_TABLES(std::string, str_casesI, str_cases);

	// Could erase insts1 here to recover memory, but it's handy
	// for debugging.

	if ( non_recursive )
		func->UseStaticFrame();

	return new ZBody(func->Name(), insts2, shared_frame_denizens_final,
				managed_slotsI, globalsI, non_recursive,
				int_cases, uint_cases, double_cases, str_cases);
	}

void ZAM::Init()
	{
	auto uds = ud->HasUsage(body) ? ud->GetUsage(body) : nullptr;
	auto args = scope->OrderedVars();
	auto nparam = func->FType()->Args()->NumFields();

	for ( auto g : pf->globals )
		{
		GlobalInfo info;
		info.id = g;
		info.slot = AddToFrame(g);
		global_id_to_info[g] = globalsI.size();
		globalsI.push_back(info);
		}

	::Ref(scope);
	push_existing_scope(scope);

	for ( auto a : args )
		{
		if ( --nparam < 0 )
			break;

		auto arg_id = a.get();
		if ( uds && uds->HasID(arg_id) )
			LoadParam(arg_id);
		else
			{
			// printf("param %s unused\n", obj_desc(arg_id.get()));
			}
		}

	pop_scope();

	// Assign slots for locals (which includes temporaries).
	for ( auto l : pf->locals )
		{
		// ### should check for unused variables.
		// Don't add locals that were already added because they're
		// parameters.
		if ( ! HasFrameSlot(l) )
			(void) AddToFrame(l);
		}

	// Complain about unused aggregates ... but not if we're inlining,
	// as that can lead to optimizations where they wind up being unused
	// but the original logic for using them was sound.
	if ( ! analysis_options.inliner )
		for ( auto a : pf->inits )
			{
			if ( pf->locals.find(a) == pf->locals.end() )
				reporter->Warning("%s unused", a->Name());
			}

	for ( auto& slot : frame_layout1 )
		{
		// Look for locals with values of types for which
		// we do explicit memory management on (re)assignment.
		auto t = slot.first->Type();
		if ( IsManagedType(t) )
			managed_slotsI.push_back(slot.second);
		}

	non_recursive = non_recursive_funcs.count(func) > 0;
	}


#include "ZAM-OpsMethodsDefs.h"

bool ZAM::IsZAM_BuiltIn(const Expr* e)
	{
	// The expression is either directly a call (in which case there's
	// no return value), or an assignment to a call.
	const CallExpr* c;

	if ( e->Tag() == EXPR_CALL )
		c = e->AsCallExpr();
	else
		c = e->GetOp2()->AsCallExpr();

	auto func_expr = c->Func();
	if ( func_expr->Tag() != EXPR_NAME )
		return false;

	auto func_val = func_expr->AsNameExpr()->Id()->ID_Val();
	if ( ! func_val )
		return false;

	auto func = func_val->AsFunc();
	if ( func->GetKind() != BuiltinFunc::BUILTIN_FUNC )
		return false;

	auto& args = c->Args()->Exprs();

	const NameExpr* n;	// name to assign to, if any

	if ( e->Tag() == EXPR_CALL )
		n = nullptr;
	else
		n = e->GetOp1()->AsRefExpr()->GetOp1()->AsNameExpr();

	if ( streq(func->Name(), "sub_bytes") )
		return BuiltIn_sub_bytes(n, args);

	else if ( streq(func->Name(), "to_lower") )
		return BuiltIn_to_lower(n, args);

	else if ( streq(func->Name(), "Log::__write") )
		return BuiltIn_Log__write(n, args);

	else if ( streq(func->Name(), "Broker::__flush_logs") )
		return BuiltIn_Broker__flush_logs(n, args);

	else if ( streq(func->Name(), "get_port_transport_proto") )
		return BuiltIn_get_port_etc(n, args);

	else if ( streq(func->Name(), "reading_live_traffic") )
		return BuiltIn_reading_live_traffic(n, args);

	else if ( streq(func->Name(), "reading_traces") )
		return BuiltIn_reading_traces(n, args);

	else if ( streq(func->Name(), "strstr") )
		return BuiltIn_strstr(n, args);

	return false;
	}

bro_uint_t ZAM::ConstArgsMask(const expr_list& args, int nargs) const
	{
	ASSERT(args.length() == nargs);

	bro_uint_t mask = 0;

	for ( int i = 0; i < nargs; ++i )
		{
		mask <<= 1;
		if ( args[i]->Tag() == EXPR_CONST )
			mask |= 1;
		}

	return mask;
	}

bool ZAM::BuiltIn_to_lower(const NameExpr* n, const expr_list& args)
	{
	if ( ! n )
		{
		reporter->Warning("return value from built-in function ignored");
		return true;
		}

	int nslot = Frame1Slot(n, OP1_WRITE);

	if ( args[0]->Tag() == EXPR_CONST )
		{
		auto arg_c = args[0]->AsConstExpr()->Value()->AsStringVal();
		IntrusivePtr<Val> arg_lc = {AdoptRef{}, ZAM_to_lower(arg_c)};
		auto arg_lce = make_intrusive<ConstExpr>(arg_lc);
		auto z = ZInstI(OP_ASSIGN_CONST_VC, nslot, arg_lce.get());
		z.is_managed = true;
		AddInst(z);
		}

	else
		{
		auto arg_s = args[0]->AsNameExpr();

		AddInst(ZInstI(OP_TO_LOWER_VV, nslot, FrameSlot(arg_s)));
		}

	return true;
	}

bool ZAM::BuiltIn_sub_bytes(const NameExpr* n, const expr_list& args)
	{
	if ( ! n )
		{
		reporter->Warning("return value from built-in function ignored");
		return true;
		}

	auto arg_s = args[0];
	auto arg_start = args[1];
	auto arg_n = args[2];

	int nslot = Frame1Slot(n, OP1_WRITE);

	int v2 = FrameSlotIfName(arg_s);
	int v3 = ConvertToCount(arg_start);
	int v4 = ConvertToInt(arg_n);

	auto c = arg_s->Tag() == EXPR_CONST ? arg_s->AsConstExpr() : nullptr;

	ZInstI z;

	switch ( ConstArgsMask(args, 3) ) {
	case 0x0:	// all variable
		z = ZInstI(OP_SUB_BYTES_VVVV, nslot, v2, v3, v4);
		z.op_type = OP_VVVV;
		break;

	case 0x1:	// last argument a constant
		z = ZInstI(OP_SUB_BYTES_VVVi, nslot, v2, v3, v4);
		z.op_type = OP_VVVV_I4;
		break;

	case 0x2:	// 2nd argument a constant; flip!
		z = ZInstI(OP_SUB_BYTES_VViV, nslot, v2, v4, v3);
		z.op_type = OP_VVVV_I4;
		break;

	case 0x3:	// both 2nd and third are constants
		z = ZInstI(OP_SUB_BYTES_VVii, nslot, v2, v3, v4);
		z.op_type = OP_VVVV_I3_I4;
		break;

	case 0x4:	// first argument a constant
		z = ZInstI(OP_SUB_BYTES_VVVC, nslot, v3, v4, c);
		z.op_type = OP_VVVC;
		break;

	case 0x5:	// first and third constant
		z = ZInstI(OP_SUB_BYTES_VViC, nslot, v3, v4, c);
		z.op_type = OP_VVVC_I3;
		break;

	case 0x6:	// first and second constant - flip!
		z = ZInstI(OP_SUB_BYTES_ViVC, nslot, v4, v3, c);
		z.op_type = OP_VVVC_I3;
		break;

	case 0x7:	// whole shebang
		z = ZInstI(OP_SUB_BYTES_ViiC, nslot, v3, v4, c);
		z.op_type = OP_VVVC_I2_I3;
		break;

	default:
		reporter->InternalError("bad constant mask");
	}

	AddInst(z);

	return true;
	}

bool ZAM::BuiltIn_Log__write(const NameExpr* n, const expr_list& args)
	{
	if ( ! log_ID_enum_type )
		{
		auto log_ID_type = lookup_ID("ID", "Log");
		ASSERT(log_ID_type);
		log_ID_enum_type = log_ID_type->Type()->AsEnumType();
		}

	auto id = args[0];
	auto columns = args[1];

	if ( columns->Tag() != EXPR_NAME )
		return false;

	auto columns_n = columns->AsNameExpr();
	auto col_slot = FrameSlot(columns_n);

	ZInstI z;

	if ( n )
		{
		int nslot = Frame1Slot(n, OP1_WRITE);
		if ( id->Tag() == EXPR_CONST )
			{
			z = ZInstI(OP_LOG_WRITE_VVC, nslot, col_slot,
					id->AsConstExpr());
			z.op_type = OP_VVc;
			}
		else
			z = ZInstI(OP_LOG_WRITE_VVV, nslot,
					FrameSlot(id->AsNameExpr()), col_slot);
		}
	else
		{
		if ( id->Tag() == EXPR_CONST )
			{
			z = ZInstI(OP_LOG_WRITE_VC, col_slot, id->AsConstExpr());
			z.op_type = OP_Vc;
			}
		else
			z = ZInstI(OP_LOG_WRITE_VV, FrameSlot(id->AsNameExpr()),
					col_slot);
		}

	z.SetType(columns_n->Type());

	AddInst(z);

	return true;
	}

bool ZAM::BuiltIn_Broker__flush_logs(const NameExpr* n, const expr_list& args)
	{
	if ( n )
		AddInst(ZInstI(OP_BROKER_FLUSH_LOGS_V,
				Frame1Slot(n, OP1_WRITE)));
	else
		AddInst(ZInstI(OP_BROKER_FLUSH_LOGS_X));

	return true;
	}

bool ZAM::BuiltIn_get_port_etc(const NameExpr* n, const expr_list& args)
	{
	if ( ! n )
		{
		reporter->Warning("return value from built-in function ignored");
		return true;
		}

	auto p = args[0];

	if ( p->Tag() != EXPR_NAME )
		return false;

	auto pn = p->AsNameExpr();
	int nslot = Frame1Slot(n, OP1_WRITE);

	AddInst(ZInstI(OP_GET_PORT_TRANSPORT_PROTO_VV, nslot, FrameSlot(pn)));

	return true;
	}

bool ZAM::BuiltIn_reading_live_traffic(const NameExpr* n, const expr_list& args)
	{
	if ( ! n )
		{
		reporter->Warning("return value from built-in function ignored");
		return true;
		}

	int nslot = Frame1Slot(n, OP1_WRITE);

	AddInst(ZInstI(OP_READING_LIVE_TRAFFIC_V, nslot));

	return true;
	}

bool ZAM::BuiltIn_reading_traces(const NameExpr* n, const expr_list& args)
	{
	if ( ! n )
		{
		reporter->Warning("return value from built-in function ignored");
		return true;
		}

	int nslot = Frame1Slot(n, OP1_WRITE);

	AddInst(ZInstI(OP_READING_TRACES_V, nslot));

	return true;
	}

bool ZAM::BuiltIn_strstr(const NameExpr* n, const expr_list& args)
	{
	if ( ! n )
		{
		reporter->Warning("return value from built-in function ignored");
		return true;
		}

	int nslot = Frame1Slot(n, OP1_WRITE);

	auto big = args[0];
	auto little = args[1];

	auto big_n = big->Tag() == EXPR_NAME ? big->AsNameExpr() : nullptr;
	auto little_n =
		little->Tag() == EXPR_NAME ? little->AsNameExpr() : nullptr;

	ZInstI z;

	if ( big_n && little_n )
		z = GenInst(this, OP_STRSTR_VVV, n, big_n, little_n);
	else if ( big_n )
		z = GenInst(this, OP_STRSTR_VVC, n, big_n, little->AsConstExpr());
	else if ( little_n )
		z = GenInst(this, OP_STRSTR_VCV, n, little_n, big->AsConstExpr());
	else
		return false;

	AddInst(z);

	return true;
	}

const CompiledStmt ZAM::DoCall(const CallExpr* c, const NameExpr* n)
	{
	SyncGlobals(c);

	auto func = c->Func()->AsNameExpr();
	auto func_id = func->Id();
	auto& args = c->Args()->Exprs();

	int nargs = args.length();
	int call_case = nargs;

	bool indirect = ! func_id->IsGlobal();

	if ( indirect )
		call_case = -1;	// force default of CallN

	bool aux_call = true;	// whether instruction uses .aux field

	auto nt = n ? n->Type()->Tag() : TYPE_VOID;
	auto n_slot = n ? Frame1Slot(n, OP1_WRITE) : -1;

	ZInstI z;

	if ( call_case == 0 )
		{
		aux_call = false;
		if ( n )
			z = ZInstI(AssignmentFlavor(OP_CALL0_V, nt), n_slot);
		else
			z = ZInstI(OP_CALL0_X);
		}

	else if ( call_case == 1 )
		{
		aux_call = false;
		auto arg0 = args[0];
		auto n0 = arg0->Tag() == EXPR_NAME ?
						arg0->AsNameExpr() : nullptr;
		auto c0 = arg0->Tag() == EXPR_CONST ?
						arg0->AsConstExpr() : nullptr;

		if ( n )
			{
			if ( n0 )
				z = ZInstI(AssignmentFlavor(OP_CALL1_VV, nt),
						n_slot, FrameSlot(n0));
			else
				z = ZInstI(AssignmentFlavor(OP_CALL1_VC, nt),
						n_slot, c0);
			}
		else
			{
			if ( n0 )
				z = ZInstI(OP_CALL1_V, FrameSlot(n0));
			else
				z = ZInstI(OP_CALL1_C, c0);
			}

		z.t = arg0->Type().get();
		}

	else
		{
		auto aux = new ZInstAux(nargs);

		for ( int i = 0; i < nargs; ++i )
			{
			auto ai = args[i];
			auto ai_t = ai->Type();
			if ( ai->Tag() == EXPR_NAME )
				aux->Add(i, FrameSlot(ai->AsNameExpr()), ai_t);
			else
				aux->Add(i, ai->AsConstExpr()->ValuePtr());
			}

		ZOp op;

		switch ( call_case ) {
		case 2: op = n ? OP_CALL2_V : OP_CALL2_X; break;
		case 3: op = n ? OP_CALL3_V : OP_CALL3_X; break;
		case 4: op = n ? OP_CALL4_V : OP_CALL4_X; break;
		case 5: op = n ? OP_CALL5_V : OP_CALL5_X; break;

		default:
			if ( indirect )
				op = n ? OP_INDCALLN_VV : OP_INDCALLN_V;
			else
				op = n ? OP_CALLN_V : OP_CALLN_X;
			break;
		}

		if ( n )
			{
			op = AssignmentFlavor(op, nt);
			auto n_slot = Frame1Slot(n, OP1_WRITE);

			if ( indirect)
				{
				z = ZInstI(op, n_slot, FrameSlot(func));
				z.op_type = OP_VV;
				}

			else
				{
				z = ZInstI(op, n_slot);
				z.op_type = OP_V;
				}
			}
		else
			{
			if ( indirect )
				{
				z = ZInstI(op, FrameSlot(func));
				z.op_type = OP_V;
				}
			else
				{
				z = ZInstI(op);
				z.op_type = OP_X;
				}
			}

		z.aux = aux;
		}

	if ( ! indirect )
		z.func = func_id->ID_Val()->AsFunc();

	if ( n )
		{
		auto id = n->Id();
		if ( id->IsGlobal() )
			{
			AddInst(z);
			z = ZInstI(OP_DIRTY_GLOBAL_V, global_id_to_info[id]);
			z.op_type = OP_V_I1;
			}
		}

	return AddInst(z);
	}

void ZAM::FlushVars(const Expr* e)
	{
	ProfileFunc expr_pf;
	e->Traverse(&expr_pf);

	SyncGlobals(expr_pf.globals, e);

	for ( auto l : expr_pf.locals )
		StoreLocal(l);
	}

const CompiledStmt ZAM::ConstructTable(const NameExpr* n, const Expr* e)
	{
	auto con = e->GetOp1()->AsListExpr();
	auto tt = n->Type()->AsTableType();
	auto width = tt->Indices()->Types()->length();

	auto z = GenInst(this, OP_CONSTRUCT_TABLE_VV, n, width);
	z.aux = InternalBuildVals(con, width + 1);
	z.t = tt;
	z.attrs = e->AsTableConstructorExpr()->Attrs();

	return AddInst(z);
	}

const CompiledStmt ZAM::ConstructSet(const NameExpr* n, const Expr* e)
	{
	auto con = e->GetOp1()->AsListExpr();
	auto tt = n->Type()->AsTableType();
	auto width = tt->Indices()->Types()->length();

	auto z = GenInst(this, OP_CONSTRUCT_SET_VV, n, width);
	z.aux = InternalBuildVals(con, width);
	z.t = e->Type().get();
	z.attrs = e->AsSetConstructorExpr()->Attrs();

	return AddInst(z);
	}

const CompiledStmt ZAM::ConstructRecord(const NameExpr* n, const Expr* e)
	{
	auto con = e->GetOp1()->AsListExpr();

	auto z = GenInst(this, OP_CONSTRUCT_RECORD_V, n);
	z.aux = InternalBuildVals(con);
	z.t = e->Type().get();

	return AddInst(z);
	}

const CompiledStmt ZAM::ConstructVector(const NameExpr* n, const Expr* e)
	{
	auto con = e->GetOp1()->AsListExpr();

	auto z = GenInst(this, OP_CONSTRUCT_VECTOR_V, n);
	z.aux = InternalBuildVals(con);
	z.t = e->Type().get();

	return AddInst(z);
	}

const CompiledStmt ZAM::ArithCoerce(const NameExpr* n, const Expr* e)
	{
	auto nt = n->Type();
	auto nt_is_vec = nt->Tag() == TYPE_VECTOR;

	auto op = e->GetOp1();
	auto op_t = op->Type().get();
	auto op_is_vec = op_t->Tag() == TYPE_VECTOR;

	auto e_t = e->Type().get();
	auto et_is_vec = e_t->Tag() == TYPE_VECTOR;

	if ( nt_is_vec || op_is_vec || et_is_vec )
		{
		if ( ! (nt_is_vec && op_is_vec && et_is_vec) )
			reporter->InternalError("vector confusion compiling coercion");

		op_t = op_t->AsVectorType()->YieldType();
		e_t = e_t->AsVectorType()->YieldType();
		}

	auto targ_it = e_t->InternalType();
	auto op_it = op_t->InternalType();

	if ( op_it == targ_it )
		reporter->InternalError("coercion wasn't folded");

	if ( op->Tag() != EXPR_NAME )
		reporter->InternalError("coercion wasn't folded");

	ZOp a;

	switch ( targ_it ) {
	case TYPE_INTERNAL_DOUBLE:
		{
		a = op_it == TYPE_INTERNAL_INT ?
			(nt_is_vec ? OP_COERCE_DI_VEC_VV : OP_COERCE_DI_VV) :
			(nt_is_vec ? OP_COERCE_DU_VEC_VV : OP_COERCE_DU_VV);
		break;
		}

	case TYPE_INTERNAL_INT:
		{
		a = op_it == TYPE_INTERNAL_UNSIGNED ?
			(nt_is_vec ? OP_COERCE_IU_VEC_VV : OP_COERCE_IU_VV) :
			(nt_is_vec ? OP_COERCE_ID_VEC_VV : OP_COERCE_ID_VV);
		break;
		}

	case TYPE_INTERNAL_UNSIGNED:
		{
		a = op_it == TYPE_INTERNAL_INT ?
			(nt_is_vec ? OP_COERCE_UI_VEC_VV : OP_COERCE_UI_VV) :
			(nt_is_vec ? OP_COERCE_UD_VEC_VV : OP_COERCE_UD_VV);
		break;
		}

	default:
		reporter->InternalError("bad target internal type in coercion");
	}

	return AddInst(GenInst(this, a, n, op->AsNameExpr()));
	}

const CompiledStmt ZAM::RecordCoerce(const NameExpr* n, const Expr* e)
	{
	auto r = e->AsRecordCoerceExpr();
	auto op = r->GetOp1()->AsNameExpr();
	auto map = r->Map();
	auto map_size = r->MapSize();

	int op_slot = FrameSlot(op);
	auto zop = OP_RECORD_COERCE_VVV;
	ZInstI z(zop, Frame1Slot(n, zop), op_slot, map_size);

	z.SetType(e->Type());
	z.op_type = OP_VVV_I3;
	z.int_ptr = map;

	return AddInst(z);
	}

const CompiledStmt ZAM::TableCoerce(const NameExpr* n, const Expr* e)
	{
	auto op = e->GetOp1()->AsNameExpr();

	int op_slot = FrameSlot(op);
	auto zop = OP_TABLE_COERCE_VV;
	ZInstI z(zop, Frame1Slot(n, zop), op_slot);
	z.SetType(e->Type());

	return AddInst(z);
	}

const CompiledStmt ZAM::VectorCoerce(const NameExpr* n, const Expr* e)
	{
	auto op = e->GetOp1()->AsNameExpr();
	int op_slot = FrameSlot(op);

	auto zop = OP_VECTOR_COERCE_VV;
	ZInstI z(zop, Frame1Slot(n, zop), op_slot);
	z.SetType(e->Type());

	return AddInst(z);
	}

const CompiledStmt ZAM::Is(const NameExpr* n, const Expr* e)
	{
	auto is = e->AsIsExpr();
	auto op = e->GetOp1()->AsNameExpr();
	int op_slot = FrameSlot(op);

	ZInstI z(OP_IS_VV, Frame1Slot(n, OP_IS_VV), op_slot);
	z.t2 = op->Type().get();
	z.SetType(is->TestType());

	return AddInst(z);
	}

const CompiledStmt ZAM::IfElse(const Expr* e, const Stmt* s1, const Stmt* s2)
	{
	CompiledStmt cond_stmt = EmptyStmt();
	int branch_v;

	if ( e->Tag() == EXPR_NAME )
		{
		auto n = e->AsNameExpr();

		ZOp op = (s1 && s2) ?
			OP_IF_ELSE_VV : (s1 ? OP_IF_VV : OP_IF_NOT_VV);

		ZInstI cond(op, FrameSlot(n), 0);
		cond_stmt = AddInst(cond);
		branch_v = 2;
		}
	else
		cond_stmt = GenCond(e, branch_v);

	if ( s1 )
		{
		auto s1_end = s1->Compile(this);
		if ( s2 )
			{
			auto branch_after_s1 = GoToStub();
			auto s2_end = s2->Compile(this);
			SetV(cond_stmt, GoToTargetBeyond(branch_after_s1),
				branch_v);
			SetGoTo(branch_after_s1, GoToTargetBeyond(s2_end));

			return s2_end;
			}

		else
			{
			SetV(cond_stmt, GoToTargetBeyond(s1_end), branch_v);
			return s1_end;
			}
		}

	else
		{
		auto s2_end = s2->Compile(this);

		// For complex conditionals, we need to invert their
		// sense since we're switching to "if ( ! cond ) s2".
		auto z = insts1[cond_stmt.stmt_num];

		switch ( z->op ) {
		case OP_IF_ELSE_VV:
		case OP_IF_VV:
		case OP_IF_NOT_VV:
			// These are generated correctly above, no need
			// to fix up.
			break;

		case OP_HAS_FIELD_COND_VVV:
			z->op = OP_NOT_HAS_FIELD_COND_VVV;
			break;
		case OP_NOT_HAS_FIELD_COND_VVV:
			z->op = OP_HAS_FIELD_COND_VVV;
			break;

		case OP_VAL_IS_IN_TABLE_COND_VVV:
			z->op = OP_VAL_IS_NOT_IN_TABLE_COND_VVV;
			break;
		case OP_VAL_IS_NOT_IN_TABLE_COND_VVV:
			z->op = OP_VAL_IS_IN_TABLE_COND_VVV;
			break;

		case OP_CONST_IS_IN_TABLE_COND_VVC:
			z->op = OP_CONST_IS_NOT_IN_TABLE_COND_VVC;
			break;
		case OP_CONST_IS_NOT_IN_TABLE_COND_VVC:
			z->op = OP_CONST_IS_IN_TABLE_COND_VVC;
			break;

		case OP_VAL2_IS_IN_TABLE_COND_VVVV:
			z->op = OP_VAL2_IS_NOT_IN_TABLE_COND_VVVV;
			break;
		case OP_VAL2_IS_NOT_IN_TABLE_COND_VVVV:
			z->op = OP_VAL2_IS_IN_TABLE_COND_VVVV;
			break;

		case OP_VAL2_IS_IN_TABLE_COND_VVVC:
			z->op = OP_VAL2_IS_NOT_IN_TABLE_COND_VVVC;
			break;
		case OP_VAL2_IS_NOT_IN_TABLE_COND_VVVC:
			z->op = OP_VAL2_IS_IN_TABLE_COND_VVVC;
			break;

		case OP_VAL2_IS_IN_TABLE_COND_VVCV:
			z->op = OP_VAL2_IS_NOT_IN_TABLE_COND_VVCV;
			break;
		case OP_VAL2_IS_NOT_IN_TABLE_COND_VVCV:
			z->op = OP_VAL2_IS_IN_TABLE_COND_VVCV;
			break;

		default:
			reporter->InternalError("inconsistency in ZAM::IfElse");
		}

		SetV(cond_stmt, GoToTargetBeyond(s2_end), branch_v);
		return s2_end;
		}
	}

const CompiledStmt ZAM::GenCond(const Expr* e, int& branch_v)
	{
	auto op1 = e->GetOp1();
	auto op2 = e->GetOp2();

	NameExpr* n1 = nullptr;
	NameExpr* n2 = nullptr;
	ConstExpr* c = nullptr;

	if ( e->Tag() == EXPR_HAS_FIELD )
		{
		auto hf = e->AsHasFieldExpr();
		auto z = GenInst(this, OP_HAS_FIELD_COND_VVV, op1->AsNameExpr(),
					hf->Field());
		z.op_type = OP_VVV_I2_I3;
		branch_v = 3;
		return AddInst(z);
		}

	if ( e->Tag() == EXPR_IN )
		{
		auto op1 = e->GetOp1();
		auto op2 = e->GetOp2()->AsNameExpr();

		// First, deal with the easy cases: it's a single index.
		if ( op1->Tag() == EXPR_LIST )
			{
			auto& ind = op1->AsListExpr()->Exprs();
			if ( ind.length() == 1 )
				op1 = {NewRef{}, ind[0]};
			}

		if ( op1->Tag() == EXPR_NAME )
			{
			auto z = GenInst(this, OP_VAL_IS_IN_TABLE_COND_VVV,
						op1->AsNameExpr(), op2, 0);
			z.t = op1->Type().release();
			branch_v = 3;
			return AddInst(z);
			}

		if ( op1->Tag() == EXPR_CONST )
			{
			auto z = GenInst(this, OP_CONST_IS_IN_TABLE_COND_VVC,
						op2, op1->AsConstExpr(), 0);
			z.t = op1->Type().release();
			branch_v = 2;
			return AddInst(z);
			}

		// Now the harder case: 2 indexes.  (Any number here other
		// than two should have been disallowed due to how we reduce
		// conditional expressions.)

		auto& ind = op1->AsListExpr()->Exprs();
		ASSERT(ind.length() == 2);

		auto ind0 = ind[0];
		auto ind1 = ind[1];

		auto name0 = ind0->Tag() == EXPR_NAME;
		auto name1 = ind1->Tag() == EXPR_NAME;

		auto n0 = name0 ? ind0->AsNameExpr() : nullptr;
		auto n1 = name1 ? ind1->AsNameExpr() : nullptr;

		auto c0 = name0 ? nullptr : ind0->AsConstExpr();
		auto c1 = name1 ? nullptr : ind1->AsConstExpr();

		ZInstI z;

		if ( name0 && name1 )
			{
			z = GenInst(this, OP_VAL2_IS_IN_TABLE_COND_VVVV,
					n0, n1, op2, 0);
			branch_v = 4;
			z.t = n0->Type().release();
			}

		else if ( name0 )
			{
			z = GenInst(this, OP_VAL2_IS_IN_TABLE_COND_VVVC,
					n0, op2, c1, 0);
			branch_v = 3;
			z.t = n0->Type().release();
			}

		else if ( name1 )
			{
			z = GenInst(this, OP_VAL2_IS_IN_TABLE_COND_VVCV,
					n1, op2, c0, 0);
			branch_v = 3;
			z.t = n1->Type().release();
			}

		else
			{ // Both are constants, assign first to temporary.
			auto slot = NewSlot(c0->Type());
			z = ZInstI(OP_ASSIGN_CONST_VC, slot, c0);
			z.CheckIfManaged(c0);
			(void) AddInst(z);

			z = ZInstI(OP_VAL2_IS_IN_TABLE_COND_VVVC,
					slot, FrameSlot(op2), 0, c1);
			z.op_type = OP_VVVC_I3;
			branch_v = 3;
			z.t = c0->Type().release();
			}

		return AddInst(z);
		}

	if ( op1->Tag() == EXPR_NAME )
		{
		n1 = op1->AsNameExpr();

		if ( op2->Tag() == EXPR_NAME )
			n2 = op2->AsNameExpr();
		else
			c = op2->AsConstExpr();
		}

	else
		{
		c = op1->AsConstExpr();
		n2 = op2->AsNameExpr();
		}

	if ( n1 && n2 )
		branch_v = 3;
	else
		branch_v = 2;

	switch ( e->Tag() ) {
#include "ZAM-Conds.h"

	default:
		reporter->InternalError("bad expression type in ZAM::GenCond");
	}

	// Not reached.
	}

const CompiledStmt ZAM::While(const Stmt* cond_stmt, const Expr* cond,
				const Stmt* body)
	{
	auto head = StartingBlock();

	if ( cond_stmt )
		(void) cond_stmt->Compile(this);

	CompiledStmt cond_IF = EmptyStmt();
	int branch_v;

	if ( cond->Tag() == EXPR_NAME )
		{
		auto n = cond->AsNameExpr();
		cond_IF = AddInst(ZInstI(OP_IF_VV, FrameSlot(n), 0));
		branch_v = 2;
		}
	else
		cond_IF = GenCond(cond, branch_v);

	PushNexts();
	PushBreaks();

	if ( body && body->Tag() != STMT_NULL )
		(void) body->Compile(this);

	auto tail = GoTo(GoToTarget(head));

	auto beyond_tail = GoToTargetBeyond(tail);
	SetV(cond_IF, beyond_tail, branch_v);

	ResolveNexts(GoToTarget(head));
	ResolveBreaks(beyond_tail);

	return tail;
	}

const CompiledStmt ZAM::Loop(const Stmt* body)
	{
	PushNexts();
	PushBreaks();

	auto head = StartingBlock();
	(void) body->Compile(this);
	auto tail = GoTo(GoToTarget(head));

	ResolveNexts(GoToTarget(head));
	ResolveBreaks(GoToTargetBeyond(tail));

	return tail;
	}

const CompiledStmt ZAM::When(Expr* cond, const Stmt* body,
				const Expr* timeout, const Stmt* timeout_body,
				bool is_return)
	{
	// ### Flush locals on eval, and also on exit
	ZInstI z;

	if ( timeout )
		{
		// Note, we fill in is_return by hand since it's already
		// an int_val, doesn't need translation.
		if ( timeout->Tag() == EXPR_CONST )
			{
			z = GenInst(this, OP_WHEN_VVVC, timeout->AsConstExpr());
			z.op_type = OP_VVVC_I1_I2_I3;
			z.v3 = is_return;
			}
		else
			{
			z = GenInst(this, OP_WHEN_VVVV, timeout->AsNameExpr());
			z.op_type = OP_VVVV_I2_I3_I4;
			z.v4 = is_return;
			}
		}

	else
		{
		z = GenInst(this, OP_WHEN_VV);
		z.op_type = OP_VV_I1_I2;
		z.v1 = is_return;
		}

	z.e = cond;

	auto when_eval = AddInst(z);

	auto branch_past_blocks = GoToStub();

	auto when_body = body->Compile(this);
	auto when_done = ReturnX();

	if ( timeout )
		{
		auto t_body = timeout_body->Compile(this);
		auto t_done = ReturnX();

		if ( timeout->Tag() == EXPR_CONST )
			{
			SetV1(when_eval, GoToTargetBeyond(branch_past_blocks));
			SetV2(when_eval, GoToTargetBeyond(when_done));
			}
		else
			{
			SetV2(when_eval, GoToTargetBeyond(branch_past_blocks));
			SetV3(when_eval, GoToTargetBeyond(when_done));
			}

		SetGoTo(branch_past_blocks, GoToTargetBeyond(t_done));

		return t_done;
		}

	else
		{
		SetV2(when_eval, GoToTargetBeyond(branch_past_blocks));
		SetGoTo(branch_past_blocks, GoToTargetBeyond(when_done));

		return when_done;
		}
	}

const CompiledStmt ZAM::Switch(const SwitchStmt* sw)
	{
	auto e = sw->StmtExpr();

	const NameExpr* n = e->Tag() == EXPR_NAME ? e->AsNameExpr() : nullptr;
	const ConstExpr* c = e->Tag() == EXPR_CONST ? e->AsConstExpr() : nullptr;

	auto t = e->Type()->Tag();

	PushBreaks();

	auto& cases = *sw->Cases();

	if ( cases.length() > 0 && cases[0]->TypeCases() )
		return TypeSwitch(sw, n, c);
	else
		return ValueSwitch(sw, n, c);
	}

const CompiledStmt ZAM::ValueSwitch(const SwitchStmt* sw, const NameExpr* v,
					const ConstExpr* c)
	{
	int slot = v ? FrameSlot(v) : 0;

	if ( c )
		{
		// Weird to have a constant switch expression, enough
		// so that it doesn't seem worth optimizing.
		slot = NewSlot(c->Type());
		auto z = ZInstI(OP_ASSIGN_CONST_VC, slot, c);
		z.CheckIfManaged(c);
		(void) AddInst(z);
		}

	// Figure out which jump table we're using.
	auto t = v ? v->Type() : c->Type();
	int tbl = 0;
	ZOp op;

	switch ( t->InternalType() ) {
	case TYPE_INTERNAL_INT:
		op = OP_SWITCHI_VVV;
		tbl = int_casesI.size();
		break;

	case TYPE_INTERNAL_UNSIGNED:
		op = OP_SWITCHU_VVV;
		tbl = uint_casesI.size();
		break;

	case TYPE_INTERNAL_DOUBLE:
		op = OP_SWITCHD_VVV;
		tbl = double_casesI.size();
		break;

	case TYPE_INTERNAL_STRING:
		op = OP_SWITCHS_VVV;
		tbl = str_casesI.size();
		break;

	case TYPE_INTERNAL_ADDR:
		op = OP_SWITCHA_VVV;
		tbl = str_casesI.size();
		break;

	case TYPE_INTERNAL_SUBNET:
		op = OP_SWITCHN_VVV;
		tbl = str_casesI.size();
		break;

	default:
		reporter->InternalError("bad switch type");
	}

	// Add the "head", i.e., the execution of the jump table.
	auto sw_head_op = ZInstI(op, slot, tbl, 0);
	sw_head_op.op_type = OP_VVV_I2_I3;

	auto sw_head = AddInst(sw_head_op);
	auto body_end = sw_head;

	// Generate each of the cases.
	auto cases = sw->Cases();
	std::vector<InstLabel> case_start;

	PushFallThroughs();
	for ( auto c : *cases )
		{
		auto start = GoToTargetBeyond(body_end);
		ResolveFallThroughs(start);
		case_start.push_back(start);
		PushFallThroughs();
		body_end = c->Body()->Compile(this);
		}

	auto sw_end = GoToTargetBeyond(body_end);
	ResolveFallThroughs(sw_end);
	ResolveBreaks(sw_end);

	int def_ind = sw->DefaultCaseIndex();
	if ( def_ind >= 0 )
		SetV3(sw_head, case_start[def_ind]);
	else
		SetV3(sw_head, sw_end);

	// Now fill out the corresponding jump table.
	//
	// We will only use one of these.
	CaseMapI<bro_int_t> new_int_cases;
	CaseMapI<bro_uint_t> new_uint_cases;
	CaseMapI<double> new_double_cases;
	CaseMapI<std::string> new_str_cases;

	auto val_map = sw->ValueMap();

	// Ugh: the switch statement data structures don't store
	// the values directly, so we have to back-scrape them from
	// the interpreted jump table.
	auto ch = sw->CompHash();

	HashKey* k;
	int* index;
	IterCookie* cookie = val_map->InitForIteration();
	while ( (index = val_map->NextEntry(k, cookie)) )
		{
		auto case_val_list = ch->RecoverVals(k);
		delete k;

		auto case_vals = case_val_list->Vals();

		if ( case_vals->length() != 1 )
			reporter->InternalError("bad recovered value when compiling switch");

		auto cv = (*case_vals)[0];
		auto case_body_start = case_start[*index];

		switch ( cv->Type()->InternalType() ) {
		case TYPE_INTERNAL_INT:
			new_int_cases[cv->InternalInt()] = case_body_start;
			break;

		case TYPE_INTERNAL_UNSIGNED:
			new_uint_cases[cv->InternalUnsigned()] = case_body_start;
			break;

		case TYPE_INTERNAL_DOUBLE:
			new_double_cases[cv->InternalDouble()] = case_body_start;
			break;

		case TYPE_INTERNAL_STRING:
			{
			// This leaks, but only statically so not worth
			// tracking the value for ultimate deletion.
			auto sv = cv->AsString()->Render();
			std::string s(sv);
			new_str_cases[s] = case_body_start;
			break;
			}

		case TYPE_INTERNAL_ADDR:
			{
			auto a = cv->AsAddr().AsString();
			new_str_cases[a] = case_body_start;
			break;
			}

		case TYPE_INTERNAL_SUBNET:
			{
			auto n = cv->AsSubNet().AsString();
			new_str_cases[n] = case_body_start;
			break;
			}

		default:
			reporter->InternalError("bad recovered type when compiling switch");
		}
		}

	// Now add the jump table to the set we're keeping for the
	// corresponding type.

	switch ( t->InternalType() ) {
	case TYPE_INTERNAL_INT:
		int_casesI.push_back(new_int_cases);
		break;

	case TYPE_INTERNAL_UNSIGNED:
		uint_casesI.push_back(new_uint_cases);
		break;

	case TYPE_INTERNAL_DOUBLE:
		double_casesI.push_back(new_double_cases);
		break;

	case TYPE_INTERNAL_STRING:
	case TYPE_INTERNAL_ADDR:
	case TYPE_INTERNAL_SUBNET:
		str_casesI.push_back(new_str_cases);
		break;

	default:
		reporter->InternalError("bad switch type");
	}

	return body_end;
	}

const CompiledStmt ZAM::TypeSwitch(const SwitchStmt* sw, const NameExpr* v,
					const ConstExpr* c)
	{
	auto cases = sw->Cases();
	auto type_map = sw->TypeMap();

	auto body_end = EmptyStmt();

	auto tmp = NewSlot(true);	// true since we know "any" is managed

	int slot = v ? FrameSlot(v) : 0;

	if ( v && v->Type()->Tag() != TYPE_ANY )
		{
		auto z = ZInstI(OP_ASSIGN_ANY_VV, tmp, slot);
		body_end = AddInst(z);
		slot = tmp;
		}

	if ( c )
		{
		auto z = ZInstI(OP_ASSIGN_ANY_VC, tmp, c);
		body_end = AddInst(z);
		slot = tmp;
		}

	int def_ind = sw->DefaultCaseIndex();
	CompiledStmt def_succ(0);	// successor to default, if any
	bool saw_def_succ = false;	// whether def_succ is meaningful

	PushFallThroughs();
	for ( auto& i : *type_map )
		{
		auto id = i.first;
		auto type = id->Type();

		ZInstI z;

		z = ZInstI(OP_BRANCH_IF_NOT_TYPE_VV, slot, 0);
		z.SetType(type);
		auto case_test = AddInst(z);

		// Type cases that don't use "as" create a placeholder
		// ID with a null name.
		if ( id->Name() )
			{
			int id_slot = Frame1Slot(id, OP_CAST_ANY_VV);
			z = ZInstI(OP_CAST_ANY_VV, id_slot, slot);
			z.SetType(type);
			body_end = AddInst(z);
			}
		else
			body_end = case_test;

		ResolveFallThroughs(GoToTargetBeyond(body_end));
		body_end = (*cases)[i.second]->Body()->Compile(this);
		SetV2(case_test, GoToTargetBeyond(body_end));

		if ( def_ind >= 0 && i.second == def_ind + 1 )
			{
			def_succ = case_test;
			saw_def_succ = true;
			}

		PushFallThroughs();
		}

	ResolveFallThroughs(GoToTargetBeyond(body_end));

	if ( def_ind >= 0 )
		{
		PushFallThroughs();

		body_end = (*sw->Cases())[def_ind]->Body()->Compile(this);

		// Now resolve any fallthrough's in the default.
		if ( saw_def_succ )
			ResolveFallThroughs(GoToTargetBeyond(def_succ));
		else
			ResolveFallThroughs(GoToTargetBeyond(body_end));
		}

	ResolveBreaks(GoToTargetBeyond(body_end));

	return body_end;
	}

const CompiledStmt ZAM::For(const ForStmt* f)
	{
	auto e = f->LoopExpr();
	auto val = e->AsNameExpr();
	auto et = e->Type()->Tag();

	PushNexts();
	PushBreaks();

	if ( et == TYPE_TABLE )
		return LoopOverTable(f, val);

	else if ( et == TYPE_VECTOR )
		return LoopOverVector(f, val);

	else if ( et == TYPE_STRING )
		return LoopOverString(f, val);

	else
		reporter->InternalError("bad \"for\" loop-over value when compiling");
	}

const CompiledStmt ZAM::Call(const ExprStmt* e)
	{
	if ( IsZAM_BuiltIn(e->StmtExpr()) )
		return LastInst();

	auto call = e->StmtExpr()->AsCallExpr();
	return DoCall(call, nullptr);
	}

const CompiledStmt ZAM::AssignToCall(const ExprStmt* e)
	{
	if ( IsZAM_BuiltIn(e->StmtExpr()) )
		return LastInst();

	auto assign = e->StmtExpr()->AsAssignExpr();
	auto n = assign->GetOp1()->AsRefExpr()->GetOp1()->AsNameExpr();
	auto call = assign->GetOp2()->AsCallExpr();

	return DoCall(call, n);
	}

const CompiledStmt ZAM::AssignVecElems(const Expr* e)
	{
	auto index_assign = e->AsIndexAssignExpr();

	auto op1 = index_assign->GetOp1();
	auto op3 = index_assign->GetOp3();
	auto any_val = IsAny(op3->Type());

	auto lhs = op1->AsNameExpr();
	auto lt = lhs->Type();

	if ( IsAnyVec(lt) )
		{
		ZInstI z;

		if ( any_val )
			// No need to set the type, as it's retrieved
			// dynamically.
			z = GenInst(this, OP_TRANSFORM_ANY_VEC2_VV, lhs,
					op3->AsNameExpr());
		else
			{
			z = GenInst(this, OP_TRANSFORM_ANY_VEC_V, lhs);
			z.SetType(op3->Type());
			}

		AddInst(z);
		}

	auto indexes_expr = index_assign->GetOp2()->AsListExpr();
	auto indexes = indexes_expr->Exprs();

	if ( indexes.length() > 1 )
		{ // Vector slice assignment.
		ASSERT(op1->Tag() == EXPR_NAME);
		ASSERT(op3->Tag() == EXPR_NAME);
		ASSERT(op1->Type()->Tag() == TYPE_VECTOR);
		ASSERT(op3->Type()->Tag() == TYPE_VECTOR);

		auto z = GenInst(this, OP_VECTOR_SLICE_ASSIGN_VV,
					op1->AsNameExpr(), op3->AsNameExpr());

		z.aux = InternalBuildVals(indexes_expr);

		return AddInst(z);
		}

	auto op2 = indexes[0];

	if ( op2->Tag() == EXPR_CONST && op3->Tag() == EXPR_CONST )
		{
		// Turn into a VVC assignment by assigning the index to
		// a temporary.
		auto c = op2->AsConstExpr();
		auto tmp = NewSlot(c->Type());
		auto z = ZInstI(OP_ASSIGN_CONST_VC, tmp, c);
		z.CheckIfManaged(c);

		AddInst(z);

		auto zop = OP_VECTOR_ELEM_ASSIGN_VVC;

		return AddInst(ZInstI(zop, Frame1Slot(lhs, zop), tmp,
					op3->AsConstExpr()));
		}

	if ( op2->Tag() == EXPR_NAME )
		{
		CompiledStmt inst(0);

		if ( op3->Tag() == EXPR_NAME )
			inst = any_val ? Vector_Elem_Assign_AnyVVV(lhs,
							op2->AsNameExpr(),
							op3->AsNameExpr()) :
					Vector_Elem_AssignVVV(lhs,
							op2->AsNameExpr(),
							op3->AsNameExpr());
		else
			inst = Vector_Elem_AssignVVC(lhs, op2->AsNameExpr(),
							op3->AsConstExpr());

		TopMainInst()->t = op3->Type().get();
		return inst;
		}

	else
		{
		auto c = op2->AsConstExpr();
		auto index = c->Value()->AsCount();

		auto inst = any_val ? Vector_Elem_Assign_AnyVVi(lhs,
						op3->AsNameExpr(), index) :
					Vector_Elem_AssignVVi(lhs,
						op3->AsNameExpr(), index);

		TopMainInst()->t = op3->Type().get();
		return inst;
		}
	}

const CompiledStmt ZAM::AssignTableElem(const Expr* e)
	{
	auto index_assign = e->AsIndexAssignExpr();

	auto op1 = index_assign->GetOp1()->AsNameExpr();
	auto op2 = index_assign->GetOp2()->AsListExpr();
	auto op3 = index_assign->GetOp3();

	ZInstI z;

	if ( op3->Tag() == EXPR_NAME )
		z = GenInst(this, OP_TABLE_ELEM_ASSIGN_VV,
				op1, op3->AsNameExpr());
	else
		z = GenInst(this, OP_TABLE_ELEM_ASSIGN_VC,
				op1, op3->AsConstExpr());

	z.aux = InternalBuildVals(op2);
	z.t = op3->Type().get();

	return AddInst(z);
	}

const CompiledStmt ZAM::LoopOverTable(const ForStmt* f, const NameExpr* val)
	{
	auto loop_vars = f->LoopVars();
	auto value_var = f->ValueVar();

	auto ii = new IterInfo();

	for ( int i = 0; i < loop_vars->length(); ++i )
		{
		auto id = (*loop_vars)[i];
		ii->loop_vars.push_back(FrameSlot(id));
		ii->loop_var_types.push_back(id->Type());
		}

	auto info = NewSlot(false);	// false <- IterInfo isn't managed
	auto z = ZInstI(OP_INIT_TABLE_LOOP_VV, info, FrameSlot(val));
	z.op_type = OP_VV;
	z.SetType(value_var ? value_var->Type() : nullptr);
	z.aux = new ZInstAux(0);
	z.aux->iter_info = ii;

	auto init_end = AddInst(z);

	auto iter_head = StartingBlock();
	if ( value_var )
		{
		z = ZInstI(OP_NEXT_TABLE_ITER_VAL_VAR_VVV, FrameSlot(value_var),
				info, 0);
		z.CheckIfManaged(value_var->Type());
		z.op_type = OP_VVV_I3;
		}
	else
		{
		z = ZInstI(OP_NEXT_TABLE_ITER_VV, info, 0);
		z.op_type = OP_VV_I2;
		}

	return FinishLoop(iter_head, z, f->LoopBody(), info);
	}

const CompiledStmt ZAM::LoopOverVector(const ForStmt* f, const NameExpr* val)
	{
	auto loop_vars = f->LoopVars();
	auto loop_var = (*loop_vars)[0];

	auto ii = new IterInfo();
	ii->vec_type = val->Type()->AsVectorType();
	ii->yield_type = ii->vec_type->YieldType();

	auto info = NewSlot(false);
	auto z = ZInstI(OP_INIT_VECTOR_LOOP_VV, info, FrameSlot(val));
	z.op_type = OP_VV;
	z.aux = new ZInstAux(0);
	z.aux->iter_info = ii;

	auto init_end = AddInst(z);

	auto iter_head = StartingBlock();

	z = ZInstI(OP_NEXT_VECTOR_ITER_VVV, FrameSlot(loop_var), info, 0);
	z.op_type = OP_VVV_I3;

	return FinishLoop(iter_head, z, f->LoopBody(), info);
	}

const CompiledStmt ZAM::LoopOverString(const ForStmt* f, const NameExpr* val)
	{
	auto loop_vars = f->LoopVars();
	auto loop_var = (*loop_vars)[0];

	auto info = NewSlot(false);
	auto z = ZInstI(OP_INIT_STRING_LOOP_VV, info, FrameSlot(val));
	z.op_type = OP_VV;
	z.aux = new ZInstAux(0);
	z.aux->iter_info = new IterInfo();

	auto init_end = AddInst(z);

	auto iter_head = StartingBlock();

	z = ZInstI(OP_NEXT_STRING_ITER_VVV, FrameSlot(loop_var), info, 0);
	z.CheckIfManaged(loop_var->Type());
	z.op_type = OP_VVV_I3;

	return FinishLoop(iter_head, z, f->LoopBody(), info);
	}

const CompiledStmt ZAM::FinishLoop(const CompiledStmt iter_head,
					ZInstI iter_stmt, const Stmt* body,
					int info_slot)
	{
	auto loop_iter = AddInst(iter_stmt);
	auto body_end = body->Compile(this);

	auto loop_end = GoTo(GoToTarget(iter_head));
	auto final_stmt = AddInst(ZInstI(OP_END_LOOP_V, info_slot));

	if ( iter_stmt.op_type == OP_VVV_I3 )
		SetV3(loop_iter, GoToTarget(final_stmt));
	else
		SetV2(loop_iter, GoToTarget(final_stmt));

	ResolveNexts(GoToTarget(iter_head));
	ResolveBreaks(GoToTarget(final_stmt));

	return final_stmt;
	}

const CompiledStmt ZAM::InitRecord(ID* id, RecordType* rt)
	{
	auto z = ZInstI(OP_INIT_RECORD_V, FrameSlot(id));
	z.SetType(rt);
	return AddInst(z);
	}

const CompiledStmt ZAM::InitVector(ID* id, VectorType* vt)
	{
	auto z = ZInstI(OP_INIT_VECTOR_V, FrameSlot(id));
	z.SetType(vt);
	return AddInst(z);
	}

const CompiledStmt ZAM::InitTable(ID* id, TableType* tt, Attributes* attrs)
	{
	auto z = ZInstI(OP_INIT_TABLE_V, FrameSlot(id));
	z.SetType(tt);
	z.attrs = attrs;
	return AddInst(z);
	}

const CompiledStmt ZAM::Return(const ReturnStmt* r)
	{
	auto e = r->StmtExpr();

	// We could consider only doing this sync for "true" returns
	// and not for catch-return's.  To make that work, however,
	// would require propagating the "dirty" status of globals
	// modified inside an inlined function.  These changes aren't
	// visible because RDs don't propagate across return's, even
	// inlined ones.  See the coment in for STMT_RETURN's in
	// RD_Decorate::PostStmt for why we can't simply propagate
	// RDs in this case.
	//
	// In addition, by sync'ing here rather than deferring we
	// provide opportunities to double-up the frame slot used
	// by the global.
	SyncGlobals(r);

	if ( retvars.size() == 0 )
		{ // a "true" return
		if ( e )
			{
			if ( e->Tag() == EXPR_NAME )
				return ReturnV(e->AsNameExpr());
			else
				return ReturnC(e->AsConstExpr());
			}

		else
			return ReturnX();
		}

	auto rv = retvars.back();
	if ( e && ! rv )
		reporter->InternalError("unexpected returned value inside inlined block");
	if ( ! e && rv )
		reporter->InternalError("expected returned value inside inlined block but none provider");

	if ( e )
		{
		if ( e->Tag() == EXPR_NAME )
			(void) AssignXV(rv, e->AsNameExpr());
		else
			(void) AssignXC(rv, e->AsConstExpr());
		}

	return CatchReturn();
	}

const CompiledStmt ZAM::CatchReturn(const CatchReturnStmt* cr)
	{
	retvars.push_back(cr->RetVar());

	PushCatchReturns();

	auto block = cr->Block();
	auto block_end = block->Compile(this);
	retvars.pop_back();

	ResolveCatchReturns(GoToTargetBeyond(block_end));

	// If control flow runs off the end of the block, then we need
	// to consider sync'ing globals at that point.
	auto block_last = LastStmt(block.get());

	if ( block_last->Tag() == STMT_RETURN )
		return block_end;

	SyncGlobals(block_last);
	return top_main_inst;
	}

const CompiledStmt ZAM::StartingBlock()
	{
	return CompiledStmt(insts1.size());
	}

const CompiledStmt ZAM::FinishBlock(const CompiledStmt /* start */)
	{
	return CompiledStmt(insts1.size() - 1);
	}

bool ZAM::NullStmtOK() const
	{
	// They're okay iff they're the entire statement body.
	return insts1.size() == 0;
	}

const CompiledStmt ZAM::EmptyStmt()
	{
	return CompiledStmt(insts1.size() - 1);
	}

const CompiledStmt ZAM::LastInst()
	{
	return CompiledStmt(insts1.size() - 1);
	}

const CompiledStmt ZAM::ErrorStmt()
	{
	return CompiledStmt(0);
	}

bool ZAM::IsUnused(const ID* id, const Stmt* where) const
	{
	if ( ! ud->HasUsage(where) )
		return true;

	auto usage = ud->GetUsage(where);
	// usage can be nil if due to constant propagation we've prune
	// all of the uses of the given identifier.

	return ! usage || ! usage->HasID(id);
	}

OpaqueVals* ZAM::BuildVals(const IntrusivePtr<ListExpr>& l)
	{
	return new OpaqueVals(InternalBuildVals(l.get()));
	}

ZInstAux* ZAM::InternalBuildVals(const ListExpr* l, int stride)
	{
	auto exprs = l->Exprs();
	int n = exprs.length();

	auto aux = new ZInstAux(n * stride);

	int offset = 0;	// offset into aux info
	for ( int i = 0; i < n; ++i )
		{
		auto& e = exprs[i];
		int num_vals = InternalAddVal(aux, offset, e);
		ASSERT(num_vals == stride);
		offset += num_vals;
		}

	return aux;
	}

int ZAM::InternalAddVal(ZInstAux* zi, int i, Expr* e)
	{
	if ( e->Tag() == EXPR_ASSIGN )
		{ // We're building up a table constructor
		auto& indices = e->GetOp1()->AsListExpr()->Exprs();
		auto val = e->GetOp2();
		int width = indices.length();

		for ( int j = 0; j < width; ++j )
			ASSERT(InternalAddVal(zi, i + j, indices[j]) == 1);

		ASSERT(InternalAddVal(zi, i + width, val.get()) == 1);

		return width + 1;
		}

	if ( e->Tag() == EXPR_LIST )
		{ // We're building up a set constructor
		auto& indices = e->AsListExpr()->Exprs();
		int width = indices.length();

		for ( int j = 0; j < width; ++j )
			ASSERT(InternalAddVal(zi, i + j, indices[j]) == 1);

		return width;
		}

	if ( e->Tag() == EXPR_FIELD_ASSIGN )
		{
		// These can appear when we're processing the
		// expression list for a record constructor.
		auto fa = e->AsFieldAssignExpr();
		e = fa->GetOp1().get();

		if ( e->Type()->Tag() == TYPE_TYPE )
			{
			// Ugh - we actually need a "type" constant.
			auto v = e->Eval(nullptr);
			ASSERT(v);
			zi->Add(i, v);
			return 1;
			}

		// Now that we've adjusted, fall through.
		}

	if ( e->Tag() == EXPR_NAME )
		zi->Add(i, FrameSlot(e->AsNameExpr()), e->Type());

	else
		zi->Add(i, e->AsConstExpr()->ValuePtr());

	return 1;
	}

const CompiledStmt ZAM::AddInst(const ZInstI& inst)
	{
	ZInstI* i;

	if ( pending_inst )
		{
		i = pending_inst;
		pending_inst = nullptr;
		}
	else
		i = new ZInstI();

	*i = inst;

	insts1.push_back(i);

	top_main_inst = insts1.size() - 1;

	if ( mark_dirty < 0 )
		return CompiledStmt(top_main_inst);

	auto dirty_global_slot = mark_dirty;
	mark_dirty = -1;

	auto dirty_inst = ZInstI(OP_DIRTY_GLOBAL_V, dirty_global_slot);
	dirty_inst.op_type = OP_V_I1;

	return AddInst(dirty_inst);
	}

const Stmt* ZAM::LastStmt(const Stmt* s) const
	{
	if ( s->Tag() == STMT_LIST )
		{
		auto sl = s->AsStmtList()->Stmts();
		return sl[sl.length() - 1];
		}

	else
		return s;
	}

const CompiledStmt ZAM::LoadOrStoreLocal(ID* id, bool is_load, bool add)
	{
	if ( id->AsType() )
		reporter->InternalError("don't know how to compile local variable that's a type not a value");

	if ( ! is_load )
		interpreter_locals.insert(id);

	bool is_any = IsAny(id->Type());

	ZOp op;

	if ( is_load )
		op = AssignmentFlavor(OP_LOAD_VAL_VV, id->Type()->Tag());
	else
		op = is_any ? OP_STORE_ANY_VAL_VV : OP_STORE_VAL_VV;

	int slot = (is_load && add) ? AddToFrame(id) : FrameSlot(id);

	ZInstI z(op, slot, id->Offset());
	z.SetType(id->Type());
	z.op_type = OP_VV_FRAME;

	return AddInst(z);
	}

const CompiledStmt ZAM::LoadGlobal(ID* id)
	{
	ZOp op;

	if ( id->AsType() )
		// Need a special load for these, as they don't fit
		// with the usual template.
		op = OP_LOAD_GLOBAL_TYPE_VVC;
	else
		op = AssignmentFlavor(OP_LOAD_GLOBAL_VVC, id->Type()->Tag());

	auto slot = RawSlot(id);

	ZInstI z(op, slot, global_id_to_info[id]);
	z.c.id_val = id;
	z.SetType(id->Type());
	z.op_type = OP_ViC_ID;

	return AddInst(z);
	}

int ZAM::AddToFrame(ID* id)
	{
	frame_layout1[id] = frame_sizeI;
	frame_denizens.push_back(id);
	return frame_sizeI++;
	}

void ZAM::Dump()
	{
	bool remapped_frame = ! analysis_options.no_ZAM_opt;

	if ( remapped_frame )
		printf("Original frame:\n");

	for ( auto frame_elem : frame_layout1 )
		printf("frame[%d] = %s\n", frame_elem.second, frame_elem.first->Name());

	if ( remapped_frame )
		{
		printf("Final frame:\n");

		for ( auto i = 0; i < shared_frame_denizens.size(); ++i )
			{
			printf("frame2[%d] =", i);
			for ( auto& id : shared_frame_denizens[i].ids )
				printf(" %s", id->Name());
			printf("\n");
			}
		}

	if ( insts2.size() > 0 )
		printf("Pre-removal of dead code:\n");

	auto remappings = remapped_frame ? &shared_frame_denizens : nullptr;

	for ( int i = 0; i < insts1.size(); ++i )
		{
		auto& inst = insts1[i];
		auto depth = inst->loop_depth;
		printf("%d%s%s: ", i, inst->live ? "" : " (dead)",
			depth ? fmt(" (loop %d)", depth) : "");
		inst->Dump(&frame_denizens, remappings);
		}

	if ( insts2.size() > 0 )
		printf("Final intermediary code:\n");

	remappings = remapped_frame ? &shared_frame_denizens_final : nullptr;

	for ( int i = 0; i < insts2.size(); ++i )
		{
		auto& inst = insts2[i];
		auto depth = inst->loop_depth;
		printf("%d%s%s: ", i, inst->live ? "" : " (dead)",
			depth ? fmt(" (loop %d)", depth) : "");
		inst->Dump(&frame_denizens, remappings);
		}

	if ( insts2.size() > 0 )
		printf("Final code:\n");

	for ( int i = 0; i < insts2.size(); ++i )
		{
		auto& inst = insts2[i];
		printf("%d: ", i);
		inst->Dump(&frame_denizens, remappings);
		}

	for ( int i = 0; i < int_casesI.size(); ++i )
		DumpIntCases(i);
	for ( int i = 0; i < uint_casesI.size(); ++i )
		DumpUIntCases(i);
	for ( int i = 0; i < double_casesI.size(); ++i )
		DumpDoubleCases(i);
	for ( int i = 0; i < str_casesI.size(); ++i )
		DumpStrCases(i);
	}

void ZAM::DumpIntCases(int i) const
	{
	printf("int switch table #%d:", i);
	for ( auto& m : int_casesI[i] )
		printf(" %lld->%d", m.first, m.second->inst_num);
	printf("\n");
	}

void ZAM::DumpUIntCases(int i) const
	{
	printf("uint switch table #%d:", i);
	for ( auto& m : uint_casesI[i] )
		printf(" %llu->%d", m.first, m.second->inst_num);
	printf("\n");
	}

void ZAM::DumpDoubleCases(int i) const
	{
	printf("double switch table #%d:", i);
	for ( auto& m : double_casesI[i] )
		printf(" %lf->%d", m.first, m.second->inst_num);
	printf("\n");
	}

void ZAM::DumpStrCases(int i) const
	{
	printf("str switch table #%d:", i);
	for ( auto& m : str_casesI[i] )
		printf(" %s->%d", m.first.c_str(), m.second->inst_num);
	printf("\n");
	}

const CompiledStmt ZAM::CompileInExpr(const NameExpr* n1,
				const NameExpr* n2, const ConstExpr* c2,
				const NameExpr* n3, const ConstExpr* c3)
	{
	auto op2 = n2 ? (Expr*) n2 : (Expr*) c2;
	auto op3 = n3 ? (Expr*) n3 : (Expr*) c3;

	ZOp a;

	if ( op2->Type()->Tag() == TYPE_PATTERN )
		a = n2 ? (n3 ? OP_P_IN_S_VVV : OP_P_IN_S_VVC) : OP_P_IN_S_VCV;

	else if ( op2->Type()->Tag() == TYPE_STRING )
		a = n2 ? (n3 ? OP_S_IN_S_VVV : OP_S_IN_S_VVC) : OP_S_IN_S_VCV;

	else if ( op2->Type()->Tag() == TYPE_ADDR &&
		  op3->Type()->Tag() == TYPE_SUBNET )
		a = n2 ? (n3 ? OP_A_IN_S_VVV : OP_A_IN_S_VVC) : OP_A_IN_S_VCV;

	else if ( op3->Type()->Tag() == TYPE_TABLE )
		a = n2 ? OP_VAL_IS_IN_TABLE_VVV : OP_CONST_IS_IN_TABLE_VCV;

	else
		reporter->InternalError("bad types when compiling \"in\"");

	auto s2 = n2 ? FrameSlot(n2) : 0;
	auto s3 = n3 ? FrameSlot(n3) : 0;
	auto s1 = Frame1Slot(n1, a);

	ZInstI z;

	if ( n2 )
		{
		if ( n3 )
			z = ZInstI(a, s1, s2, s3);
		else
			z = ZInstI(a, s1, s2, c3);
		}
	else
		z = ZInstI(a, s1, s3, c2);

	BroType* stmt_type =
		c2 ? c2->Type().get() : (c3 ? c3->Type().get() : nullptr);

	BroType* zt;

	if ( c2 )
		zt = c2->Type().get();
	else if ( c3 )
		zt = c3->Type().get();
	else
		zt = n2->Type().get();

	z.SetType(zt);

	return AddInst(z);
	}

const CompiledStmt ZAM::CompileInExpr(const NameExpr* n1, const ListExpr* l,
					const NameExpr* n2, const ConstExpr* c)
	{
	auto& l_e = l->Exprs();
	int n = l_e.length();

	// Look for a very common special case: l is a single-element list,
	// and n2 is present rather than c.
	if ( n == 1 && n2 )
		{
		ZInstI z;
		bool is_vec = n2->Type()->Tag() == TYPE_VECTOR;

		if ( l_e[0]->Tag() == EXPR_NAME )
			{
			auto l_e0_n = l_e[0]->AsNameExpr();
			ZOp op = is_vec ? OP_VAL_IS_IN_VECTOR_VVV :
						OP_VAL_IS_IN_TABLE_VVV;
			z = GenInst(this, op, n1, l_e0_n, n2);
			}

		else
			{
			auto l_e0_c = l_e[0]->AsConstExpr();
			ZOp op = is_vec ? OP_CONST_IS_IN_VECTOR_VCV :
						OP_CONST_IS_IN_TABLE_VCV;
			z = GenInst(this, op, n1, l_e0_c, n2);
			}

		z.t = l_e[0]->Type().release();
		return AddInst(z);
		}

	// Also somewhat common is a 2-element index.  Here, one or both of
	// the elements might be a constant, which makes things messier.

	if ( n == 2 && n2 &&
	     (l_e[0]->Tag() == EXPR_NAME || l_e[1]->Tag() == EXPR_NAME) )
		{
		auto is_name0 = l_e[0]->Tag() == EXPR_NAME;
		auto is_name1 = l_e[1]->Tag() == EXPR_NAME;

		auto l_e0_n = is_name0 ? l_e[0]->AsNameExpr() : nullptr;
		auto l_e1_n = is_name1 ? l_e[1]->AsNameExpr() : nullptr;

		auto l_e0_c = is_name0 ? nullptr : l_e[0]->AsConstExpr();
		auto l_e1_c = is_name1 ? nullptr : l_e[1]->AsConstExpr();

		ZInstI z;

		if ( l_e0_n && l_e1_n )
			{
			z = GenInst(this, OP_VAL2_IS_IN_TABLE_VVVV,
					n1, l_e0_n, l_e1_n, n2);
			z.t = l_e0_n->Type().release();
			}

		else if ( l_e0_n )
			{
			z = GenInst(this, OP_VAL2_IS_IN_TABLE_VVVC,
					n1, l_e0_n, n2, l_e1_c);
			z.t = l_e0_n->Type().release();
			}

		else if ( l_e1_n )
			{
			z = GenInst(this, OP_VAL2_IS_IN_TABLE_VVCV,
					n1, l_e1_n, n2, l_e0_c);
			z.t = l_e1_n->Type().release();
			}

		else
			{
			// Ugh, both are constants.  Assign first to
			// a temporary.
			auto slot = NewSlot(l_e0_c->Type());
			auto z = ZInstI(OP_ASSIGN_CONST_VC, slot, l_e0_c);
			z.CheckIfManaged(l_e0_c);
			(void) AddInst(z);

			z = ZInstI(OP_VAL2_IS_IN_TABLE_VVVC, FrameSlot(n1),
					slot, FrameSlot(n2), l_e1_c);
			z.op_type = OP_VVVC;
			z.t = l_e0_c->Type().release();
			}

		return AddInst(z);
		}

	auto aggr = n2 ? (Expr*) n2 : (Expr*) c;

	ZOp op;

	if ( aggr->Type()->Tag() == TYPE_VECTOR )
		op = n2 ? OP_INDEX_IS_IN_VECTOR_VV : OP_INDEX_IS_IN_VECTOR_VC;
	else
		op = n2 ? OP_LIST_IS_IN_TABLE_VV : OP_LIST_IS_IN_TABLE_VC;

	ZInstI z;

	if ( n2 )
		z = ZInstI(op, Frame1Slot(n1, op), FrameSlot(n2));
	else
		z = ZInstI(op, Frame1Slot(n1, op), c);

	z.aux = InternalBuildVals(l);

	return AddInst(z);
	}

const CompiledStmt ZAM::CompileIndex(const NameExpr* n1, const NameExpr* n2,
					const ListExpr* l)
	{
	ZInstI z;

	int n = l->Exprs().length();
	auto n2t = n2->Type();
	auto n2tag = n2t->Tag();

	if ( n == 1 )
		{
		auto ind = l->Exprs()[0];
		auto var_ind = ind->Tag() == EXPR_NAME;
		auto n3 = var_ind ? ind->AsNameExpr() : nullptr;
		auto c3 = var_ind ? nullptr : ind->AsConstExpr();
		bro_uint_t c = 0;

		int n2_slot = FrameSlot(n2);

		if ( ! var_ind )
			{
			if ( ind->Type()->Tag() == TYPE_COUNT )
				c = c3->Value()->AsCount();
			else if ( ind->Type()->Tag() == TYPE_INT )
				c = c3->Value()->AsInt();
			}

		if ( n2tag == TYPE_STRING )
			{
			if ( n3 )
				{
				int n3_slot = FrameSlot(n3);
				auto zop = OP_INDEX_STRING_VVV;
				z = ZInstI(zop, Frame1Slot(n1, zop),
						n2_slot, n3_slot);
				}
			else
				{
				auto zop = OP_INDEX_STRINGC_VVV;
				z = ZInstI(zop, Frame1Slot(n1, zop), n2_slot, c);
				z.op_type = OP_VVV_I3;
				}

			return AddInst(z);
			}

		if ( n2tag == TYPE_VECTOR )
			{
			auto n2_yt = n2t->AsVectorType()->YieldType();
			bool is_any = n2_yt->Tag() == TYPE_ANY;

			if ( n3 )
				{
				int n3_slot = FrameSlot(n3);
				auto zop = is_any ? OP_INDEX_ANY_VEC_VVV :
							OP_INDEX_VEC_VVV;
				z = ZInstI(zop, Frame1Slot(n1, zop),
						n2_slot, n3_slot);
				}
			else
				{
				auto zop = is_any ? OP_INDEX_ANY_VECC_VVV :
							OP_INDEX_VECC_VVV;
				z = ZInstI(zop, Frame1Slot(n1, zop), n2_slot, c);
				z.op_type = OP_VVV_I3;
				}

			z.SetType(n1->Type());
			return AddInst(z);
			}

		if ( n2tag == TYPE_TABLE )
			{
			if ( n3 )
				{
				int n3_slot = FrameSlot(n3);
				auto zop = AssignmentFlavor(OP_TABLE_INDEX1_VVV,
							n1->Type()->Tag());
				z = ZInstI(zop, Frame1Slot(n1, zop), n2_slot,
						n3_slot);
				z.SetType(n3->Type());
				}

			else
				{
				auto zop = AssignmentFlavor(OP_TABLE_INDEX1_VVC,
							n1->Type()->Tag());
				z = ZInstI(zop, Frame1Slot(n1, zop),
							n2_slot, c3);
				}

			return AddInst(z);
			}
		}

	auto indexes = l->Exprs();
	int n2_slot = FrameSlot(n2);

	ZOp op;

	switch ( n2tag ) {
	case TYPE_VECTOR:
		op = OP_INDEX_VEC_SLICE_VV;
		z = ZInstI(op, Frame1Slot(n1, op), n2_slot);
		z.SetType(n2->Type());
		break;

	case TYPE_TABLE:
		op = OP_TABLE_INDEX_VV;
		z = ZInstI(op, Frame1Slot(n1, op), n2_slot);
		z.SetType(n1->Type());
		break;

	case TYPE_STRING:
		op = OP_INDEX_STRING_SLICE_VV;
		z = ZInstI(op, Frame1Slot(n1, op), n2_slot);
		z.SetType(n1->Type());
		break;

	default:
		reporter->InternalError("bad aggregate type when compiling index");
	}

	z.aux = InternalBuildVals(l);
	z.CheckIfManaged(n1);

	return AddInst(z);
	}

const CompiledStmt ZAM::CompileSchedule(const NameExpr* n, const ConstExpr* c,
					int is_interval, EventHandler* h,
					const ListExpr* l)
	{
	int len = l->Exprs().length();
	ZInstI z;

	if ( len == 0 )
		{
		z = n ? ZInstI(OP_SCHEDULE0_ViH, FrameSlot(n), is_interval) :
			ZInstI(OP_SCHEDULE0_CiH, is_interval, c);
		z.op_type = n ? OP_VV_I2 : OP_VC_I1;
		}

	else
		{
		if ( n )
			{
			z = ZInstI(OP_SCHEDULE_ViHL, FrameSlot(n), is_interval);
			z.op_type = OP_VV_I2;
			}
		else
			{
			z = ZInstI(OP_SCHEDULE_CiHL, is_interval, c);
			z.op_type = OP_VC_I1;
			}

		z.aux = InternalBuildVals(l);
		}

	z.event_handler = h;

	return AddInst(z);
	}

const CompiledStmt ZAM::CompileEvent(EventHandler* h, const ListExpr* l)
	{
	ZInstI z(OP_EVENT_HL);
	z.aux = InternalBuildVals(l);
	z.event_handler = h;

	return AddInst(z);
	}

void ZAM::SyncGlobals(const BroObj* o)
	{
	SyncGlobals(pf->globals, o);
	}

void ZAM::SyncGlobals(std::unordered_set<ID*>& globals, const BroObj* o)
	{
	auto mgr = reducer->GetDefSetsMgr();
	auto entry_rds = mgr->GetPreMaxRDs(body);

	auto curr_rds = o ?
		mgr->GetPreMaxRDs(o) : mgr->GetPostMaxRDs(LastStmt(body));

	if ( ! curr_rds )
		// This can happen for functions that only access (but
		// don't modify) globals, with no modified locals, at
		// the point of interest.
		return;

	bool could_be_dirty = false;

	for ( auto g : globals )
		{
		auto g_di = mgr->GetConstID_DI(g);
		auto entry_dps = entry_rds->GetDefPoints(g_di);
		auto curr_dps = curr_rds->GetDefPoints(g_di);

		if ( ! entry_rds->SameDefPoints(entry_dps, curr_dps) )
			{
			modified_globals.insert(g);
			could_be_dirty = true;
			}
		}

	if ( could_be_dirty )
		(void) AddInst(ZInstI(OP_SYNC_GLOBALS_X));
	}

const CompiledStmt  ZAM::AssignedToGlobal(const ID* global_id)
	{
	// We used to need this before adding ZAMOp1Flavor.  We keep
	// it as a structure since it potentially could be needed
	// in the future.
	return EmptyStmt();
	}

void ZAM::PushGoTos(GoToSets& gotos)
	{
	vector<CompiledStmt> vi;
	gotos.push_back(vi);
	}

void ZAM::ResolveGoTos(GoToSets& gotos, const InstLabel l)
	{
	auto& g = gotos.back();

	for ( int i = 0; i < g.size(); ++i )
		SetGoTo(g[i], l);

	gotos.pop_back();
	}

CompiledStmt ZAM::GenGoTo(GoToSet& v)
	{
	auto g = GoToStub();
	v.push_back(g.stmt_num);

	return g;
	}

CompiledStmt ZAM::GoToStub()
	{
	ZInstI z(OP_GOTO_V, 0);
	z.op_type = OP_V_I1;
	return AddInst(z);
	}

CompiledStmt ZAM::GoTo(const InstLabel l)
	{
	ZInstI inst(OP_GOTO_V, 0);
	inst.target = l;
	inst.target_slot = 1;
	inst.op_type = OP_V_I1;
	return AddInst(inst);
	}

InstLabel ZAM::GoToTarget(const CompiledStmt s)
	{
	return insts1[s.stmt_num];
	}

InstLabel ZAM::GoToTargetBeyond(const CompiledStmt s)
	{
	int n = s.stmt_num;

	if ( n == insts1.size() - 1 )
		{
		if ( ! pending_inst )
			pending_inst = new ZInstI();

		return pending_inst;
		}

	return insts1[n+1];
	}

CompiledStmt ZAM::PrevStmt(const CompiledStmt s)
	{
	return CompiledStmt(s.stmt_num - 1);
	}

void ZAM::SetTarget(ZInstI* inst, const InstLabel l, int slot)
	{
	if ( inst->target )
		{
		ASSERT(! inst->target2);
		inst->target2 = l;
		inst->target2_slot = slot;
		}
	else
		{
		inst->target = l;
		inst->target_slot = slot;
		}
	}

void ZAM::SetV1(CompiledStmt s, const InstLabel l)
	{
	auto inst = insts1[s.stmt_num];
	SetTarget(inst, l, 1);
	ASSERT(inst->op_type == OP_V || inst->op_type == OP_V_I1);
	inst->op_type = OP_V_I1;
	}

void ZAM::SetV2(CompiledStmt s, const InstLabel l)
	{
	auto inst = insts1[s.stmt_num];
	SetTarget(inst, l, 2);

	if ( inst->op_type == OP_VV )
		inst->op_type = OP_VV_I2;

	else if ( inst->op_type == OP_VVC )
		inst->op_type = OP_VVC_I2;

	else
		ASSERT(inst->op_type == OP_VV_I2 || inst->op_type == OP_VVC_I2);
	}

void ZAM::SetV3(CompiledStmt s, const InstLabel l)
	{
	auto inst = insts1[s.stmt_num];
	SetTarget(inst, l, 3);

	auto ot = inst->op_type;

	if ( ot == OP_VVV_I2_I3 || ot == OP_VVVC_I3 )
		return;

	ASSERT(ot == OP_VVV || ot == OP_VVV_I3);
	inst->op_type = OP_VVV_I3;
	}

void ZAM::SetV4(CompiledStmt s, const InstLabel l)
	{
	auto inst = insts1[s.stmt_num];
	SetTarget(inst, l, 4);

	auto ot = inst->op_type;

	ASSERT(ot == OP_VVVV || ot == OP_VVVV_I4);
	if ( ot != OP_VVVV_I4 )
		inst->op_type = OP_VVVV_I4;
	}


int ZAM::FrameSlot(const ID* id)
	{
	auto slot = RawSlot(id);

	if ( id->IsGlobal() )
		(void) LoadGlobal(frame_denizens[slot]);

	return slot;
	}

int ZAM::Frame1Slot(const ID* id, ZAMOp1Flavor fl)
	{
	auto slot = RawSlot(id);

	switch ( fl ) {
	case OP1_READ:
		if ( id->IsGlobal() )
			(void) LoadGlobal(frame_denizens[slot]);
		break;

	case OP1_WRITE:
		if ( id->IsGlobal() )
			mark_dirty = global_id_to_info[id];
		break;

        case OP1_READ_WRITE:
		if ( id->IsGlobal() )
			{
			(void) LoadGlobal(frame_denizens[slot]);
			mark_dirty = global_id_to_info[id];
			}
		break;

	case OP1_INTERNAL:
		break;
	}

	return slot;
	}

int ZAM::RawSlot(const ID* id)
	{
	auto id_slot = frame_layout1.find(id);

	if ( id_slot == frame_layout1.end() )
		reporter->InternalError("ID %s missing from frame layout", id->Name());

	return id_slot->second;
	}

bool ZAM::HasFrameSlot(const ID* id) const
	{
	return frame_layout1.find(id) != frame_layout1.end();
	}

int ZAM::NewSlot(bool is_managed)
	{
	char buf[8192];
	snprintf(buf, sizeof buf, "#internal-%d#", frame_sizeI);

	// In the following, all that matters is that for managed
	// types we pick a tag that will be viewed as managed, and
	// vice versa.
	auto tag = is_managed ? TYPE_TABLE : TYPE_VOID;

	auto internal_reg = new ID(buf, SCOPE_FUNCTION, false);
	internal_reg->SetType(base_type(tag));

	return AddToFrame(internal_reg);
	}
