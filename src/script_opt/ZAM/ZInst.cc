// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/ZAM/ZInst.h"

#include "zeek/Desc.h"
#include "zeek/Func.h"
#include "zeek/Reporter.h"
#include "zeek/module_util.h"

using std::string;

namespace zeek::detail {

void ZInst::Dump(FILE* f, zeek_uint_t inst_num, const FrameReMap* mappings, const string& prefix) const {
    // fprintf(f, "v%d ", n);

    auto id1 = VName(1, inst_num, mappings);
    auto id2 = VName(2, inst_num, mappings);
    auto id3 = VName(3, inst_num, mappings);
    auto id4 = VName(4, inst_num, mappings);

    Dump(f, prefix, id1, id2, id3, id4);
}

void ZInst::Dump(FILE* f, const string& prefix, const string& id1, const string& id2, const string& id3,
                 const string& id4) const {
    fprintf(f, "%s ", ZOP_name(op));
    // fprintf(f, "(%s) ", op_type_name(op_type));
    if ( t && false )
        fprintf(f, "(%s) ", type_name(t->Tag()));

    switch ( op_type ) {
        case OP_X: break;

        case OP_V: fprintf(f, "%s", id1.c_str()); break;

        case OP_VV: fprintf(f, "%s, %s", id1.c_str(), id2.c_str()); break;

        case OP_VVV: fprintf(f, "%s, %s, %s", id1.c_str(), id2.c_str(), id3.c_str()); break;

        case OP_VVVV: fprintf(f, "%s, %s, %s, %s", id1.c_str(), id2.c_str(), id3.c_str(), id4.c_str()); break;

        case OP_VVVC: fprintf(f, "%s, %s, %s, %s", id1.c_str(), id2.c_str(), id3.c_str(), ConstDump().c_str()); break;

        case OP_C: fprintf(f, "%s", ConstDump().c_str()); break;

        case OP_VC: fprintf(f, "%s, %s", id1.c_str(), ConstDump().c_str()); break;

        case OP_VVC: fprintf(f, "%s, %s, %s", id1.c_str(), id2.c_str(), ConstDump().c_str()); break;

        case OP_V_I1: fprintf(f, "%d", v1); break;

        case OP_VC_I1: fprintf(f, "%d %s", v1, ConstDump().c_str()); break;

        case OP_VV_FRAME: fprintf(f, "%s, interpreter frame[%d]", id1.c_str(), v2); break;

        case OP_VV_I2: fprintf(f, "%s, %d", id1.c_str(), v2); break;

        case OP_VV_I1_I2: fprintf(f, "%d, %d", v1, v2); break;

        case OP_VVC_I2: fprintf(f, "%s, %d, %s", id1.c_str(), v2, ConstDump().c_str()); break;

        case OP_VVV_I3: fprintf(f, "%s, %s, %d", id1.c_str(), id2.c_str(), v3); break;

        case OP_VVV_I2_I3: fprintf(f, "%s, %d, %d", id1.c_str(), v2, v3); break;

        case OP_VVVV_I4: fprintf(f, "%s, %s, %s, %d", id1.c_str(), id2.c_str(), id3.c_str(), v4); break;

        case OP_VVVV_I3_I4: fprintf(f, "%s, %s, %d, %d", id1.c_str(), id2.c_str(), v3, v4); break;

        case OP_VVVV_I2_I3_I4: fprintf(f, "%s, %d, %d, %d", id1.c_str(), v2, v3, v4); break;

        case OP_VVVC_I3: fprintf(f, "%s, %s, %d, %s", id1.c_str(), id2.c_str(), v3, ConstDump().c_str()); break;

        case OP_VVVC_I2_I3: fprintf(f, "%s, %d, %d, %s", id1.c_str(), v2, v3, ConstDump().c_str()); break;

        case OP_VVVC_I1_I2_I3: fprintf(f, "%d, %d, %d, %s", v1, v2, v3, ConstDump().c_str()); break;
    }

    auto func = aux ? aux->func : nullptr;

    if ( func )
        fprintf(f, " (func %s)", func->GetName().c_str());

    if ( loc ) {
        auto l = loc->Describe(true);
        if ( func && (func->GetBodies().empty() || func->GetBodies()[0].stmts->Tag() != STMT_ZAM) )
            l = l + ";" + func->GetName();
        if ( ! prefix.empty() )
            l = prefix + l;
        fprintf(f, " // %s", l.c_str());
    }

    fprintf(f, "\n");
}

int ZInst::NumFrameSlots() const {
    switch ( op_type ) {
        case OP_X:
        case OP_C:
        case OP_V_I1:
        case OP_VC_I1:
        case OP_VV_I1_I2:
        case OP_VVVC_I1_I2_I3: return 0;

        case OP_V:
        case OP_VC:
        case OP_VV_FRAME:
        case OP_VV_I2:
        case OP_VVC_I2:
        case OP_VVV_I2_I3:
        case OP_VVVC_I2_I3:
        case OP_VVVV_I2_I3_I4: return 1;

        case OP_VV:
        case OP_VVC:
        case OP_VVV_I3:
        case OP_VVVC_I3:
        case OP_VVVV_I3_I4: return 2;

        case OP_VVV:
        case OP_VVVC:
        case OP_VVVV_I4: return 3;

        case OP_VVVV: return 4;
    }

    return -1;
}

int ZInst::NumSlots() const {
    switch ( op_type ) {
        case OP_C:
        case OP_X: return 0;

        case OP_V:
        case OP_V_I1:
        case OP_VC:
        case OP_VC_I1: return 1;

        case OP_VV:
        case OP_VVC:
        case OP_VV_FRAME:
        case OP_VV_I2:
        case OP_VVC_I2:
        case OP_VV_I1_I2: return 2;

        case OP_VVV:
        case OP_VVV_I3:
        case OP_VVV_I2_I3:
        case OP_VVVC:
        case OP_VVVC_I3:
        case OP_VVVC_I2_I3:
        case OP_VVVC_I1_I2_I3: return 3;

        case OP_VVVV:
        case OP_VVVV_I4:
        case OP_VVVV_I3_I4:
        case OP_VVVV_I2_I3_I4: return 4;
    }

    return -1;
}

string ZInst::VName(int n, zeek_uint_t inst_num, const FrameReMap* mappings) const {
    if ( n > NumFrameSlots() )
        return "";

    int slot = n == 1 ? v1 : (n == 2 ? v2 : (n == 3 ? v3 : v4));

    if ( slot < 0 )
        return "<special>";

    // Find which identifier manifests at this instruction.
    ASSERT(slot >= 0 && static_cast<zeek_uint_t>(slot) < mappings->size());

    auto& map = (*mappings)[slot];

    unsigned int i;
    for ( i = 0; i < map.id_start.size(); ++i ) {
        // If the slot is right at the boundary between two identifiers, then
        // it matters whether this is an assigned slot (starts right here) vs.
        // not assigned (ignore change right at the boundary and stick with
        // older value).
        auto target_inst = AssignsToSlot(n) ? inst_num + 1 : inst_num;
        if ( map.id_start[i] >= target_inst )
            // Went too far.
            break;
    }

    if ( i < map.id_start.size() ) {
        ASSERT(i > 0);
    }

    auto id = map.names.empty() ? map.ids[i - 1]->Name() : map.names[i - 1];

    return util::fmt("%d (%s)", slot, id);
}

ValPtr ZInst::ConstVal() const {
    switch ( op_type ) {
        case OP_C:
        case OP_VC:
        case OP_VC_I1:
        case OP_VVC:
        case OP_VVC_I2:
        case OP_VVVC:
        case OP_VVVC_I3:
        case OP_VVVC_I2_I3:
        case OP_VVVC_I1_I2_I3: return c.ToVal(t);

        case OP_X:
        case OP_V:
        case OP_VV:
        case OP_VVV:
        case OP_VVVV:
        case OP_V_I1:
        case OP_VV_FRAME:
        case OP_VV_I2:
        case OP_VV_I1_I2:
        case OP_VVV_I3:
        case OP_VVV_I2_I3:
        case OP_VVVV_I4:
        case OP_VVVV_I3_I4:
        case OP_VVVV_I2_I3_I4: return nullptr;
    }

    return nullptr;
}

bool ZInst::IsLoopIterationAdvancement() const {
    switch ( op ) {
        case OP_NEXT_TABLE_ITER_fb:
        case OP_NEXT_TABLE_ITER_NO_VARS_fb:
        case OP_NEXT_TABLE_ITER_VAL_VAR_Vfb:
        case OP_NEXT_TABLE_ITER_VAL_VAR_NO_VARS_Vfb:
        case OP_NEXT_VECTOR_ITER_Vsb:
        case OP_NEXT_VECTOR_BLANK_ITER_sb:
        case OP_NEXT_VECTOR_ITER_VAL_VAR_VVsb:
        case OP_NEXT_VECTOR_BLANK_ITER_VAL_VAR_Vsb:
        case OP_NEXT_STRING_ITER_Vsb:
        case OP_NEXT_STRING_BLANK_ITER_sb: return true;

        default: return false;
    }
}

bool ZInst::AssignsToSlot1() const {
    switch ( op_type ) {
        case OP_X:
        case OP_C:
        case OP_V_I1:
        case OP_VC_I1:
        case OP_VV_I1_I2:
        case OP_VVVC_I1_I2_I3: return false;

        // We use this ginormous set of cases rather than "default" so
        // that when we add a new operand type, we have to consider
        // its behavior here.  (Same for many of the other switch's
        // used for ZInst/ZinstI.)
        case OP_V:
        case OP_VC:
        case OP_VV_FRAME:
        case OP_VV_I2:
        case OP_VVC_I2:
        case OP_VVV_I2_I3:
        case OP_VVVC_I2_I3:
        case OP_VVVV_I2_I3_I4:
        case OP_VV:
        case OP_VVC:
        case OP_VVV_I3:
        case OP_VVVV_I3_I4:
        case OP_VVVC_I3:
        case OP_VVV:
        case OP_VVVC:
        case OP_VVVV_I4:
        case OP_VVVV: auto fl = op1_flavor[op]; return fl == OP1_WRITE || fl == OP1_READ_WRITE;
    }

    return false;
}

bool ZInst::AssignsToSlot(int slot) const {
    switch ( op ) {
        case OP_NEXT_VECTOR_ITER_VAL_VAR_VVsb: return slot == 1 || slot == 2;

        default: return slot == 1 && AssignsToSlot1();
    }
}

void ZInst::TrackRecordTypeForField(const RecordTypePtr& rt, int f) {
    if ( ! aux )
        aux = new ZInstAux(0);

    ASSERT(aux->types.empty());
    aux->types.push_back(rt);
}

void ZInst::TrackRecordTypesForFields(const RecordTypePtr& rt1, int f1, const RecordTypePtr& rt2, int f2) {
    if ( ! aux )
        aux = new ZInstAux(0);

    ASSERT(aux->types.empty());
    aux->types.push_back(rt1);
    aux->types.push_back(rt2);
}

string ZInst::ConstDump() const {
    auto v = ConstVal();

    ODesc d;

    d.Clear();
    v->Describe(&d);

    return d.Description();
}

TraversalCode ZInst::Traverse(TraversalCallback* cb) const {
    TraversalCode tc;
    if ( t ) {
        tc = t->Traverse(cb);
        HANDLE_TC_STMT_PRE(tc);
        if ( t2 ) {
            tc = t2->Traverse(cb);
            HANDLE_TC_STMT_PRE(tc);
        }
    }

    if ( aux ) {
        tc = aux->Traverse(cb);
        HANDLE_TC_STMT_POST(tc);
    }

    return TC_CONTINUE;
}

TraversalCode ZInstAux::Traverse(TraversalCallback* cb) const {
    TraversalCode tc;

    if ( id_val ) {
        tc = id_val->Traverse(cb);
        HANDLE_TC_STMT_PRE(tc);
    }

    // Don't traverse the "func" field, as if it's a recursive function
    // we can wind up right back here.

    if ( lambda ) {
        tc = lambda->Traverse(cb);
        HANDLE_TC_STMT_PRE(tc);
    }

    if ( event_handler ) {
        auto g = lookup_ID(event_handler->Name(), GLOBAL_MODULE_NAME, false, false, false);
        ASSERT(g);
        tc = g->Traverse(cb);
        HANDLE_TC_STMT_PRE(tc);
    }

    if ( attrs ) {
        tc = attrs->Traverse(cb);
        HANDLE_TC_STMT_PRE(tc);
    }

    if ( value_var_type ) {
        tc = value_var_type->Traverse(cb);
        HANDLE_TC_STMT_PRE(tc);
    }

    for ( auto& lvt : types ) {
        tc = lvt->Traverse(cb);
        HANDLE_TC_STMT_PRE(tc);
    }

    if ( elems ) {
        for ( int i = 0; i < n; ++i ) {
            auto& e_i = elems[i];

            auto& c = e_i.Constant();
            if ( c ) {
                tc = c->GetType()->Traverse(cb);
                HANDLE_TC_STMT_PRE(tc);
            }

            auto& t = e_i.GetType();
            if ( t ) {
                tc = t->Traverse(cb);
                HANDLE_TC_STMT_PRE(tc);
            }
        }
    }

    return TC_CONTINUE;
}

void ZInstI::Dump(FILE* f, const FrameMap* frame_ids, const FrameReMap* remappings) const {
    int n = NumFrameSlots();
    // fprintf(f, "v%d ", n);

    auto id1 = VName(1, frame_ids, remappings);
    auto id2 = VName(2, frame_ids, remappings);
    auto id3 = VName(3, frame_ids, remappings);
    auto id4 = VName(4, frame_ids, remappings);

    ZInst::Dump(f, "", id1, id2, id3, id4);
}

string ZInstI::VName(int n, const FrameMap* frame_ids, const FrameReMap* remappings) const {
    if ( n > NumFrameSlots() )
        return "";

    int slot = n == 1 ? v1 : (n == 2 ? v2 : (n == 3 ? v3 : v4));

    if ( slot < 0 )
        return "<special>";

    IDPtr id;

    if ( remappings && live ) { // Find which identifier manifests at this instruction.
        ASSERT(slot >= 0 && static_cast<zeek_uint_t>(slot) < remappings->size());

        auto& map = (*remappings)[slot];

        unsigned int i;
        auto inst_num_u = static_cast<zeek_uint_t>(inst_num);
        for ( i = 0; i < map.id_start.size(); ++i ) {
            // See discussion for ZInst::VName, though this is
            // a tad different since we have the general notion
            // of AssignsToSlot().
            if ( AssignsToSlot(n) ) {
                if ( map.id_start[i] > inst_num_u )
                    break;
            }

            else if ( map.id_start[i] >= inst_num_u )
                // Went too far.
                break;
        }

        if ( i < map.id_start.size() ) {
            ASSERT(i > 0);
        }

        // For ZInstI's, map.ids is always populated.
        id = map.ids[i - 1];
    }

    else
        id = (*frame_ids)[slot];

    return util::fmt("%d (%s)", slot, id->Name());
}

bool ZInstI::DoesNotContinue() const {
    switch ( op ) {
        case OP_GOTO_b:
        case OP_HOOK_BREAK_X:
        case OP_WHEN_RETURN_X:
        case OP_RETURN_C:
        case OP_RETURN_V:
        case OP_RETURN_X: return true;

        default: return false;
    }
}

bool ZInstI::IsDirectAssignment() const {
    if ( op_type != OP_VV )
        return false;

    switch ( op ) {
        case OP_ASSIGN_VV_A:
        case OP_ASSIGN_VV_D:
        case OP_ASSIGN_VV_F:
        case OP_ASSIGN_VV_I:
        case OP_ASSIGN_VV_L:
        case OP_ASSIGN_VV_N:
        case OP_ASSIGN_VV_O:
        case OP_ASSIGN_VV_P:
        case OP_ASSIGN_VV_R:
        case OP_ASSIGN_VV_S:
        case OP_ASSIGN_VV_T:
        case OP_ASSIGN_VV_U:
        case OP_ASSIGN_VV_V:
        case OP_ASSIGN_VV_a:
        case OP_ASSIGN_VV_f:
        case OP_ASSIGN_VV_t:
        case OP_ASSIGN_VV: return true;

        default: return false;
    }
}

bool ZInstI::HasCaptures() const {
    switch ( op ) {
        case OP_LAMBDA_Vi:
        case OP_WHEN_V:
        case OP_WHEN_TIMEOUT_VV:
        case OP_WHEN_TIMEOUT_VC: return true;

        default: return false;
    }
}

bool ZInstI::HasSideEffects() const { return op_side_effects[op]; }

bool ZInstI::UsesSlot(int slot) const {
    auto fl = op1_flavor[op];
    auto v1_relevant = fl == OP1_READ || fl == OP1_READ_WRITE;
    auto v1_match = v1_relevant && v1 == slot;

    switch ( op_type ) {
        case OP_X:
        case OP_C:
        case OP_V_I1:
        case OP_VC_I1:
        case OP_VV_I1_I2:
        case OP_VVVC_I1_I2_I3: return false;

        case OP_V:
        case OP_VC:
        case OP_VV_FRAME:
        case OP_VV_I2:
        case OP_VVC_I2:
        case OP_VVV_I2_I3:
        case OP_VVVC_I2_I3:
        case OP_VVVV_I2_I3_I4: return v1_match;

        case OP_VV:
        case OP_VVC:
        case OP_VVV_I3:
        case OP_VVVV_I3_I4:
        case OP_VVVC_I3: return v1_match || v2 == slot;

        case OP_VVV:
        case OP_VVVC:
        case OP_VVVV_I4: return v1_match || v2 == slot || v3 == slot;

        case OP_VVVV: return v1_match || v2 == slot || v3 == slot || v4 == slot;
    }

    return false;
}

bool ZInstI::UsesSlots(int& s1, int& s2, int& s3, int& s4) const {
    s1 = s2 = s3 = s4 = -1;

    auto fl = op1_flavor[op];
    auto v1_relevant = fl == OP1_READ || fl == OP1_READ_WRITE;

    switch ( op_type ) {
        case OP_X:
        case OP_C:
        case OP_V_I1:
        case OP_VC_I1:
        case OP_VV_I1_I2:
        case OP_VVVC_I1_I2_I3: return false;

        case OP_V:
        case OP_VC:
        case OP_VV_FRAME:
        case OP_VV_I2:
        case OP_VVC_I2:
        case OP_VVV_I2_I3:
        case OP_VVVC_I2_I3:
        case OP_VVVV_I2_I3_I4:
            if ( ! v1_relevant )
                return false;

            s1 = v1;
            return true;

        case OP_VV:
        case OP_VVC:
        case OP_VVV_I3:
        case OP_VVVV_I3_I4:
        case OP_VVVC_I3:
            s1 = v2;

            if ( v1_relevant )
                s2 = v1;

            return true;

        case OP_VVV:
        case OP_VVVC:
        case OP_VVVV_I4:
            s1 = v2;
            s2 = v3;

            if ( v1_relevant )
                s3 = v1;

            return true;

        case OP_VVVV:
            s1 = v2;
            s2 = v3;
            s3 = v4;

            if ( v1_relevant )
                s4 = v1;

            return true;
    }

    return false;
}

void ZInstI::UpdateSlots(std::vector<int>& slot_mapping) {
    switch ( op_type ) {
        case OP_X:
        case OP_C:
        case OP_V_I1:
        case OP_VC_I1:
        case OP_VV_I1_I2:
        case OP_VVVC_I1_I2_I3: return; // so we don't do any v1 remapping.

        case OP_V:
        case OP_VC:
        case OP_VV_FRAME:
        case OP_VV_I2:
        case OP_VVC_I2:
        case OP_VVV_I2_I3:
        case OP_VVVC_I2_I3:
        case OP_VVVV_I2_I3_I4: break;

        case OP_VV:
        case OP_VVC:
        case OP_VVV_I3:
        case OP_VVVV_I3_I4:
        case OP_VVVC_I3: v2 = slot_mapping[v2]; break;

        case OP_VVV:
        case OP_VVVC:
        case OP_VVVV_I4:
            v2 = slot_mapping[v2];
            v3 = slot_mapping[v3];
            break;

        case OP_VVVV:
            v2 = slot_mapping[v2];
            v3 = slot_mapping[v3];
            v4 = slot_mapping[v4];
            break;
    }

    // Note, unlike for UsesSlots() we do *not* include OP1_READ_WRITE
    // here, because such instructions will already have v1 remapped
    // given it's an assignment target.
    if ( op1_flavor[op] == OP1_READ && v1 >= 0 )
        v1 = slot_mapping[v1];
}

bool ZInstI::IsGlobalLoad() const {
    if ( op == OP_LOAD_GLOBAL_TYPE_Vg )
        // These don't have flavors.
        return true;

    static std::unordered_set<ZOp> global_ops;

    if ( global_ops.empty() ) { // Initialize the set.
        for ( int t = 0; t < NUM_TYPES; ++t ) {
            TypeTag tag = TypeTag(t);
            ZOp global_op_flavor = AssignmentFlavor(OP_LOAD_GLOBAL_Vg, tag, false);

            if ( global_op_flavor != OP_NOP )
                global_ops.insert(global_op_flavor);
        }
    }

    return global_ops.contains(op);
}

bool ZInstI::IsCaptureLoad() const { return op == OP_LOAD_CAPTURE_Vi || op == OP_LOAD_MANAGED_CAPTURE_Vi; }

void ZInstI::InitConst(const ConstExpr* ce) {
    auto v = ce->ValuePtr();
    SetType(ce->GetType());
    c = ZVal(v, t);

    if ( ZAM_error )
        reporter->InternalError("bad value compiling code");
}

} // namespace zeek::detail
