// See the file "COPYING" in the main distribution directory for copyright.

// Methods for dealing with ZAM branches.

#include "zeek/Reporter.h"
#include "zeek/Desc.h"
#include "zeek/script_opt/ZAM/Compile.h"

namespace zeek::detail {


void ZAMCompiler::PushGoTos(GoToSets& gotos)
	{
	gotos.push_back({});
	}

void ZAMCompiler::ResolveGoTos(GoToSets& gotos, const InstLabel l)
	{
	for ( auto& gi : gotos.back() )
		SetGoTo(gi, l);

	gotos.pop_back();
	}

ZAMStmt ZAMCompiler::GenGoTo(GoToSet& v)
	{
	auto g = GoToStub();
	v.push_back(g.stmt_num);

	return g;
	}

ZAMStmt ZAMCompiler::GoToStub()
	{
	ZInstI z(OP_GOTO_V, 0);
	z.op_type = OP_V_I1;
	return AddInst(z);
	}

ZAMStmt ZAMCompiler::GoTo(const InstLabel l)
	{
	ZInstI inst(OP_GOTO_V, 0);
	inst.target = l;
	inst.target_slot = 1;
	inst.op_type = OP_V_I1;
	return AddInst(inst);
	}

InstLabel ZAMCompiler::GoToTarget(const ZAMStmt s)
	{
	return insts1[s.stmt_num];
	}

InstLabel ZAMCompiler::GoToTargetBeyond(const ZAMStmt s)
	{
	int n = s.stmt_num;

	if ( n == int(insts1.size()) - 1 )
		{
		if ( ! pending_inst )
			pending_inst = new ZInstI();

		return pending_inst;
		}

	return insts1[n+1];
	}

void ZAMCompiler::SetTarget(ZInstI* inst, const InstLabel l, int slot)
	{
	inst->target = l;
	inst->target_slot = slot;
	}

ZInstI* ZAMCompiler::FindLiveTarget(ZInstI* goto_target)
	{
	if ( goto_target == pending_inst )
		return goto_target;

	int idx = goto_target->inst_num;
	ASSERT(idx >= 0 && idx <= insts1.size());

	while ( idx < int(insts1.size()) && ! insts1[idx]->live )
		++idx;

	if ( idx == int(insts1.size()) )
		return pending_inst;
	else
		return insts1[idx];
	}

void ZAMCompiler::ConcretizeBranch(ZInstI* inst, ZInstI* target,
                                   int target_slot)
	{
	int t;	// instruction number of target

	if ( target == pending_inst )
		{
		if ( insts2.empty() )
			// We're doing this in the context of concretizing
			// intermediary instructions for dumping them out.
			t = insts1.size();
		else
			t = insts2.size();
		}
	else
		t = target->inst_num;

	switch ( target_slot ) {
	case 1:	inst->v1 = t; break;
	case 2:	inst->v2 = t; break;
	case 3:	inst->v3 = t; break;
	case 4:	inst->v4 = t; break;

	default:
		reporter->InternalError("bad GoTo target");
	}
	}

void ZAMCompiler::SetV1(ZAMStmt s, const InstLabel l)
	{
	auto inst = insts1[s.stmt_num];
	SetTarget(inst, l, 1);
	ASSERT(inst->op_type == OP_V || inst->op_type == OP_V_I1);
	inst->op_type = OP_V_I1;
	}

void ZAMCompiler::SetV2(ZAMStmt s, const InstLabel l)
	{
	auto inst = insts1[s.stmt_num];
	SetTarget(inst, l, 2);

	auto& ot = inst->op_type;

	if ( ot == OP_VV )
		ot = OP_VV_I2;

	else if ( ot == OP_VC || ot == OP_VVC )
		ot = OP_VVC_I2;

	else
		ASSERT(ot == OP_VV_I2 || ot == OP_VV_I1_I2 || ot == OP_VVC_I2);
	}

void ZAMCompiler::SetV3(ZAMStmt s, const InstLabel l)
	{
	auto inst = insts1[s.stmt_num];
	SetTarget(inst, l, 3);

	auto ot = inst->op_type;

	if ( ot == OP_VVV_I2_I3 || ot == OP_VVVC_I3 )
		return;

	ASSERT(ot == OP_VV || ot == OP_VVV || ot == OP_VVV_I3);
	inst->op_type = OP_VVV_I3;
	}

void ZAMCompiler::SetV4(ZAMStmt s, const InstLabel l)
	{
	auto inst = insts1[s.stmt_num];
	SetTarget(inst, l, 4);

	auto ot = inst->op_type;

	ASSERT(ot == OP_VVVV || ot == OP_VVVV_I4);
	if ( ot != OP_VVVV_I4 )
		inst->op_type = OP_VVVV_I4;
	}

} // zeek::detail
