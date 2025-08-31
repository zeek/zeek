// See the file "COPYING" in the main distribution directory for copyright.

// Methods for dealing with variables (both ZAM and script-level).

#include "zeek/Desc.h"
#include "zeek/Reporter.h"
#include "zeek/script_opt/ZAM/Compile.h"

namespace zeek::detail {

bool ZAMCompiler::IsUnused(const IDPtr& id, const Stmt* where) const {
    if ( ! ud->HasUsage(where) )
        return true;

    auto usage = ud->GetUsage(where);

    // "usage" can be nil if due to constant propagation we've prune
    // all of the uses of the given identifier.

    return ! usage || ! usage->HasID(id);
}

bool ZAMCompiler::IsCapture(const IDPtr& id) const {
    const auto& c = pf->CapturesOffsets();
    return c.contains(id);
}

int ZAMCompiler::CaptureOffset(const IDPtr& id) const {
    auto id_offset = pf->CapturesOffsets().find(id);
    ASSERT(id_offset != pf->CapturesOffsets().end());
    return id_offset->second;
}

void ZAMCompiler::LoadParam(const IDPtr& id) {
    if ( id->IsType() )
        reporter->InternalError("don't know how to compile local variable that's a type not a value");

    bool is_any = IsAny(id->GetType());

    ZOp op;

    op = AssignmentFlavor(OP_LOAD_VAL_Vi, id->GetType()->Tag());

    int slot = AddToFrame(id);

    ZInstI z(op, slot, id->Offset());
    z.SetType(id->GetType());
    z.op_type = OP_VV_FRAME;

    (void)AddInst(z);
}

const ZAMStmt ZAMCompiler::LoadGlobal(const IDPtr& id) {
    ZOp op;

    if ( id->IsType() )
        // Need a special load for these, as they don't fit
        // with the usual template.
        op = OP_LOAD_GLOBAL_TYPE_Vg;
    else
        op = AssignmentFlavor(OP_LOAD_GLOBAL_Vg, id->GetType()->Tag());

    auto slot = RawSlot(id);

    ZInstI z(op, slot, global_id_to_info[id]);
    z.SetType(id->GetType());
    z.op_type = OP_VV_I2;

    // We use the id_val for reporting used-but-not-set errors.
    z.aux = new ZInstAux(0);
    z.aux->id_val = std::move(id);

    return AddInst(z, true);
}

const ZAMStmt ZAMCompiler::LoadCapture(const IDPtr& id) {
    ZOp op;

    if ( ZVal::IsManagedType(id->GetType()) )
        op = OP_LOAD_MANAGED_CAPTURE_Vi;
    else
        op = OP_LOAD_CAPTURE_Vi;

    auto slot = RawSlot(id);

    ZInstI z(op, slot, CaptureOffset(id));
    z.SetType(id->GetType());
    z.op_type = OP_VV_I2;

    return AddInst(z, true);
}

int ZAMCompiler::AddToFrame(const IDPtr& id) {
    frame_layout1[id] = frame_sizeI;
    frame_denizens.push_back(id);
    return frame_sizeI++;
}

int ZAMCompiler::FrameSlot(const IDPtr& id) {
    auto slot = RawSlot(id);

    if ( id->IsGlobal() )
        (void)LoadGlobal(id);

    else if ( IsCapture(id) )
        (void)LoadCapture(id);

    return slot;
}

int ZAMCompiler::Frame1Slot(const IDPtr& id, ZAMOp1Flavor fl) {
    if ( fl == OP1_READ )
        return FrameSlot(id);

    if ( fl == OP1_INTERNAL )
        return RawSlot(id);

    ASSERT(fl == OP1_WRITE || fl == OP1_READ_WRITE);

    // Important: get the slot *before* tracking non-locals, so we don't
    // prematurely generate a Store for the read/write case.
    auto slot = fl == OP1_READ_WRITE ? FrameSlot(id) : RawSlot(id);

    if ( id->IsGlobal() )
        pending_global_store = global_id_to_info[id];

    else if ( IsCapture(id) )
        pending_capture_store = CaptureOffset(id);

    // Make sure we don't think we're storing to both a global and
    // a capture.
    ASSERT(pending_global_store == -1 || pending_capture_store == -1);

    return slot;
}

int ZAMCompiler::RawSlot(const IDPtr& id) {
    auto id_slot = frame_layout1.find(id);

    if ( id_slot == frame_layout1.end() )
        reporter->InternalError("ID %s missing from frame layout", id->Name());

    return id_slot->second;
}

bool ZAMCompiler::HasFrameSlot(const IDPtr& id) const { return frame_layout1.contains(id); }

int ZAMCompiler::NewSlot(bool is_managed) {
    char buf[8192];
    snprintf(buf, sizeof buf, "#internal-%d#", frame_sizeI);

    // In the following, all that matters is that for managed types
    // we pick a tag that will be viewed as managed, and vice versa.

    auto tag = is_managed ? TYPE_TABLE : TYPE_VOID;

    auto internal_reg = make_intrusive<ID>(buf, SCOPE_FUNCTION, false);
    internal_reg->SetType(base_type(tag));

    return AddToFrame(internal_reg);
}

int ZAMCompiler::TempForConst(const ConstExpr* c) {
    auto slot = NewSlot(c->GetType());

    auto z = ZInstI(OP_ASSIGN_CONST_VC, slot, c);
    z.CheckIfManaged(c->GetType());
    (void)AddInst(z);

    return slot;
}

} // namespace zeek::detail
