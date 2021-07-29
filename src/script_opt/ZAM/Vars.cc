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

	z.aux = new ZInstAux(0);
	z.aux->id_val = id;

	did_global_load = true;

	return AddInst(z);
	}

int ZAMCompiler::AddToFrame(ID* id)
	{
	frame_layout1[id] = frame_sizeI;
	frame_denizens.push_back(id);
	return frame_sizeI++;
	}

void ZAMCompiler::SyncGlobals(const Stmt* s)
	{
	SyncGlobals(pf->Globals(), s);
	}

void ZAMCompiler::SyncGlobals(const std::unordered_set<const ID*>& globals,
                              const Stmt* s)
	{
	// We're at a point where we need to ensure that any cached
	// value we have of a global is synchronized with external uses
	// (such as by the interpreter).
	//
	// We need to check for two situations.  (1) A modification to
	// a global makes it to this point, so we need to synchronize
	// globals in order to flush that modification.  (2) A global
	// whose value we've used (not necessarily modified) previously
	// will also be used after this point, and thus we should
	// synchronize in order to return it to the "unloaded" state
	// in case it's modified by whatever is leading us to decide
	// to synchronize globals here.  (Note that if this call is
	// happening due to finishing a function's execution, then there
	// won't be any subsequent use, and we won't bother flushing
	// unless we have a modified global.)
	//
	// We can determine the first case using reaching-defs: is
	// there a modification to a global that reaches this point?
	//
	// The second case is harder to do with full precision.  Ideally
	// we'd like to know whether there's a reference to a global
	// between this point and all previous possible global synchronization
	// points (including function entry), and then for that global
	// seeing whether there's a UseDef for it at this point, indicating
	// it'll be used subsequently.  We don't have the data structures
	// built up to do this.  However, can approximate the notion by
	// (1) tracking whether *any* LoadGlobal has happened so far,
	// and (2) seeing whether *any* global has a UseDef at this point.

	bool need_sync = false;

	// First case: look for modifications that reach this point.
	auto mgr = reducer->GetDefSetsMgr();
	auto curr_rds = s ? mgr->GetPreMaxRDs(s) :
	                    mgr->GetPostMaxRDs(LastStmt(body.get()));

	// Note that curr_rds might be nil, for functions that only access
	// (but don't modify) globals, and have no modified locals, at the
	// point of interest.

	if ( curr_rds )
		{
		auto entry_rds = mgr->GetPreMaxRDs(body.get());

		for ( auto g : globals )
			{
			auto g_di = mgr->GetConstID_DI(g);
			auto entry_dps = entry_rds->GetDefPoints(g_di);
			auto curr_dps = curr_rds->GetDefPoints(g_di);

			if ( ! entry_rds->SameDefPoints(entry_dps, curr_dps) )
				{
				modified_globals.insert(g);
				need_sync = true;
				}
			}
		}

	// Second case: we've already loaded some globals, and there are
	// globals used after this point.
	if ( did_global_load && s )
		{
		auto uds = ud->GetUsage(s);

		if ( uds )
			for ( auto g : globals )
				if ( uds->HasID(g) )
					{
					need_sync = true;
					break;
					}
		}

	if ( need_sync )
		(void) AddInst(ZInstI(OP_SYNC_GLOBALS_X));
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
