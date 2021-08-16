// See the file "COPYING" in the main distribution directory for copyright.

// Methods for dealing with variables (both ZAM and script-level).

#include "zeek/Reporter.h"
#include "zeek/Desc.h"
#include "zeek/script_opt/ProfileFunc.h"
#include "zeek/script_opt/Reduce.h"
#include "zeek/script_opt/ZAM/Compile.h"

namespace zeek::detail {


bool ZAMCompiler::IsUnused(const IDPtr& id, const Stmt* where) const
	{
	if ( ! ud->HasUsage(where) )
		return true;

	auto usage = ud->GetUsage(where);

	// "usage" can be nil if due to constant propagation we've prune
	// all of the uses of the given identifier.

	return ! usage || ! usage->HasID(id.get());
	}

void ZAMCompiler::LoadParam(ID* id)
	{
	if ( id->IsType() )
		reporter->InternalError("don't know how to compile local variable that's a type not a value");

	bool is_any = IsAny(id->GetType());

	ZOp op;

	op = AssignmentFlavor(OP_LOAD_VAL_VV, id->GetType()->Tag());

	int slot = AddToFrame(id);

	ZInstI z(op, slot, id->Offset());
	z.SetType(id->GetType());
	z.op_type = OP_VV_FRAME;

	(void) AddInst(z);
	}

const ZAMStmt ZAMCompiler::LoadGlobal(ID* id)
	{
	ZOp op;

	if ( id->IsType() )
		// Need a special load for these, as they don't fit
		// with the usual template.
		op = OP_LOAD_GLOBAL_TYPE_VV;
	else
		op = AssignmentFlavor(OP_LOAD_GLOBAL_VV, id->GetType()->Tag());

	auto slot = RawSlot(id);

	ZInstI z(op, slot, global_id_to_info[id]);
	z.SetType(id->GetType());
	z.op_type = OP_VV_I2;

	// We use the id_val for reporting used-but-not-set errors.
	z.aux = new ZInstAux(0);
	z.aux->id_val = id;

	return AddInst(z);
	}

int ZAMCompiler::AddToFrame(ID* id)
	{
	frame_layout1[id] = frame_sizeI;
	frame_denizens.push_back(id);
	return frame_sizeI++;
	}

int ZAMCompiler::FrameSlot(const ID* id)
	{
	auto slot = RawSlot(id);

	if ( id->IsGlobal() )
		(void) LoadGlobal(frame_denizens[slot]);

	return slot;
	}

int ZAMCompiler::Frame1Slot(const ID* id, ZAMOp1Flavor fl)
	{
	auto slot = RawSlot(id);

	switch ( fl ) {
	case OP1_READ:
		if ( id->IsGlobal() )
			(void) LoadGlobal(frame_denizens[slot]);
		break;

	case OP1_WRITE:
		if ( id->IsGlobal() )
			pending_global_store = global_id_to_info[id];
		break;

        case OP1_READ_WRITE:
		if ( id->IsGlobal() )
			{
			(void) LoadGlobal(frame_denizens[slot]);
			pending_global_store = global_id_to_info[id];
			}
		break;

	case OP1_INTERNAL:
		break;
	}

	return slot;
	}

int ZAMCompiler::RawSlot(const ID* id)
	{
	auto id_slot = frame_layout1.find(id);

	if ( id_slot == frame_layout1.end() )
		reporter->InternalError("ID %s missing from frame layout", id->Name());

	return id_slot->second;
	}

bool ZAMCompiler::HasFrameSlot(const ID* id) const
	{
	return frame_layout1.find(id) != frame_layout1.end();
	}

int ZAMCompiler::NewSlot(bool is_managed)
	{
	char buf[8192];
	snprintf(buf, sizeof buf, "#internal-%d#", frame_sizeI);

	// In the following, all that matters is that for managed types
	// we pick a tag that will be viewed as managed, and vice versa.

	auto tag = is_managed ? TYPE_TABLE : TYPE_VOID;

	auto internal_reg = new ID(buf, SCOPE_FUNCTION, false);
	internal_reg->SetType(base_type(tag));

	return AddToFrame(internal_reg);
	}

int ZAMCompiler::TempForConst(const ConstExpr* c)
	{
	auto slot = NewSlot(c->GetType());

	auto z = ZInstI(OP_ASSIGN_CONST_VC, slot, c);
	z.CheckIfManaged(c->GetType());
	(void) AddInst(z);

	return slot;
	}

} // zeek::detail
