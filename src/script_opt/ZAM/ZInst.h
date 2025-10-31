// See the file "COPYING" in the main distribution directory for copyright.

// Operators and instructions used in ZAM execution.

#pragma once

#include "zeek/script_opt/ZAM/Support.h"
#include "zeek/script_opt/ZAM/ZInstAux.h"
#include "zeek/script_opt/ZAM/ZOp.h"

namespace zeek::detail {

class ConstExpr;

// A ZAM instruction.  This base class has all the information for
// execution, but omits information and methods only necessary for
// compiling.
class ZInst {
public:
    ZInst(ZOp _op, ZAMOpType _op_type) {
        op = _op;
        op_type = _op_type;
        ASSERT(ZAM::curr_loc);
        loc = ZAM::curr_loc;
    }

    // Create a stub instruction that will be populated later.
    ZInst() {
        ASSERT(ZAM::curr_loc);
        loc = ZAM::curr_loc;
    }

    virtual ~ZInst() = default;

    // Methods for printing out the instruction for debugging/profiling.
    void Dump(FILE* f, zeek_uint_t inst_num, const FrameReMap* mappings, const std::string& prefix) const;
    void Dump(FILE* f, const std::string& prefix, const std::string& id1, const std::string& id2,
              const std::string& id3, const std::string& id4) const;

    // Returns the name to use in identifying one of the slots/integer
    // values (designated by "n").  "inst_num" identifies the instruction
    // by its number within a larger set.  "mappings" provides the
    // mappings used to translate raw slots to the corresponding
    // script variable(s).
    std::string VName(int n, zeek_uint_t inst_num, const FrameReMap* mappings) const;

    // Number of slots that refer to a frame element.  These always
    // come first, if we use additional slots.
    int NumFrameSlots() const;

    // Total number of slots in use.  >= NumFrameSlots()
    int NumSlots() const;

    // Returns nil if this instruction doesn't have an associated constant.
    ValPtr ConstVal() const;

    // Returns true if this instruction represents a form of advancing
    // a loop iteration, false otherwise.
    bool IsLoopIterationAdvancement() const;

    // True if the given instruction assigns to the frame location
    // given by slot 1 (v1).
    bool AssignsToSlot1() const;

    // True if the given instruction assigns to the frame location
    // corresponding to the given slot.
    bool AssignsToSlot(int slot) const;

    // The following is to support robust operation in the face of potential
    // record "redef ... +=" extensions that add fields to records and
    // make hardwired record field offsets incorrect. This method tracks -
    // if necessary - a given record type and offset associated with a
    // record-field operation.
    void TrackRecordTypeForField(const RecordTypePtr& rt, int f);
    void TrackRecordTypesForFields(const RecordTypePtr& rt1, int f1, const RecordTypePtr& rt2, int f2);

    // Returns a string describing the constant.
    std::string ConstDump() const;

    TraversalCode Traverse(TraversalCallback* cb) const;

    ZOp op = OP_NOP;
    ZAMOpType op_type = OP_X;

    // Usually indices into frame, though sometimes hold integer constants.
    // When an instruction has both frame slots and integer constants,
    // the former always come first, even if conceptually in the operation
    // the constant is an "earlier" operand.
    //
    // Initialized here to keep Coverity happy.
    int v1 = -1, v2 = -1, v3 = -1, v4 = -1;

    ZVal c; // constant associated with instruction, if any

    // Meta-data associated with the execution.

protected:
    // These are protected to ensure that setting 't' is done via SetType(),
    // so we can keep is_managed consistent with it. We don't need that
    // for 't2' but keep them together for consistency.

    // Type, usually for interpreting the constant.
    TypePtr t;

    TypePtr t2; // just a few ops need two types

public:
    const TypePtr& GetType() const { return t; }
    const TypePtr& GetType2() const { return t2; }

    // Auxiliary information.  We could in principle use this to
    // consolidate a bunch of the above, though at the cost of
    // slightly slower access.  Most instructions don't need "aux",
    // which is why we bundle these separately.
    ZInstAux* aux = nullptr;

    // Location associated with this instruction, for error reporting
    // and profiling.
    std::shared_ptr<ZAMLocInfo> loc;

    // Whether v1 represents a frame slot type for which we
    // explicitly manage the memory.
    std::optional<bool> is_managed;
};

// A intermediary ZAM instruction, one that includes information/methods
// needed for compiling.  Intermediate instructions use pointers to other
// such instructions for branches, rather than concrete instruction
// numbers.  This allows the AM optimizer to easily prune instructions.
class ZInstI : public ZInst {
public:
    // These constructors can be used directly, but often instead
    // they'll be generated via the use of Inst-Gen methods.
    ZInstI(ZOp _op) : ZInst(_op, OP_X) {
        op = _op;
        op_type = OP_X;
    }

    ZInstI(ZOp _op, int _v1) : ZInst(_op, OP_V) { v1 = _v1; }

    ZInstI(ZOp _op, int _v1, int _v2) : ZInst(_op, OP_VV) {
        v1 = _v1;
        v2 = _v2;
    }

    ZInstI(ZOp _op, int _v1, int _v2, int _v3) : ZInst(_op, OP_VVV) {
        v1 = _v1;
        v2 = _v2;
        v3 = _v3;
    }

    ZInstI(ZOp _op, int _v1, int _v2, int _v3, int _v4) : ZInst(_op, OP_VVVV) {
        v1 = _v1;
        v2 = _v2;
        v3 = _v3;
        v4 = _v4;
    }

    ZInstI(ZOp _op, const ConstExpr* ce) : ZInst(_op, OP_C) { InitConst(ce); }

    ZInstI(ZOp _op, int _v1, const ConstExpr* ce) : ZInst(_op, OP_VC) {
        v1 = _v1;
        InitConst(ce);
    }

    ZInstI(ZOp _op, int _v1, int _v2, const ConstExpr* ce) : ZInst(_op, OP_VVC) {
        v1 = _v1;
        v2 = _v2;
        InitConst(ce);
    }

    ZInstI(ZOp _op, int _v1, int _v2, int _v3, const ConstExpr* ce) : ZInst(_op, OP_VVVC) {
        v1 = _v1;
        v2 = _v2;
        v3 = _v3;
        InitConst(ce);
    }

    // Constructor used when we're going to just copy in another ZInstI.
    ZInstI() {}

    // If "remappings" is non-nil, then it is used instead of frame_ids.
    void Dump(FILE* f, const FrameMap* frame_ids, const FrameReMap* remappings) const;

    // Note that this is *not* an override of the base class's VName
    // but instead a method with similar functionality but somewhat
    // different behavior (namely, being cognizant of frame_ids).
    std::string VName(int n, const FrameMap* frame_ids, const FrameReMap* remappings) const;

    // True if this instruction definitely won't proceed to the one
    // after it.
    bool DoesNotContinue() const;

    // True if this instruction always branches elsewhere.  Different
    // from DoesNotContinue() in that returns & hook breaks do not
    // continue, but they are not branches.
    bool IsUnconditionalBranch() const { return op == OP_GOTO_b; }

    // True if this instruction is of the form "v1 = v2".
    bool IsDirectAssignment() const;

    // True if this instruction includes captures in its aux slots.
    bool HasCaptures() const;

    // True if this instruction has side effects when executed, so
    // should not be pruned even if it has a dead assignment.
    bool HasSideEffects() const;

    // True if the given instruction uses the value in the given frame
    // slot. (Assigning to the slot does not constitute using the value.)
    bool UsesSlot(int slot) const;

    // Returns the slots used (not assigned to).  Any slot not used
    // is set to -1.  Returns true if at least one slot was used.
    bool UsesSlots(int& s1, int& s2, int& s3, int& s4) const;

    // Updates used (not assigned) slots per the given mapping.
    void UpdateSlots(std::vector<int>& slot_mapping);

    // True if the instruction corresponds to loading a global into
    // the ZAM frame.
    bool IsGlobalLoad() const;

    // True if the instruction corresponds to loading a capture into
    // the ZAM frame.
    bool IsCaptureLoad() const;

    // True if the instruction does not correspond to a load from the
    // ZAM frame.
    bool IsNonLocalLoad() const { return IsGlobalLoad() || IsCaptureLoad(); }

    // True if the instruction corresponds to some sort of load,
    // either from the interpreter frame or of a global/capture.
    bool IsLoad() const { return op_type == OP_VV_FRAME || IsNonLocalLoad(); }

    // True if the instruction corresponds to storing a global.
    bool IsGlobalStore() const { return op == OP_STORE_GLOBAL_g; }

    void CheckIfManaged(const TypePtr& t) { is_managed = ZVal::IsManagedType(t); }

    void SetType(TypePtr _t) {
        t = std::move(_t);
        ASSERT(t);
        if ( t )
            CheckIfManaged(t);
    }

    void SetType2(TypePtr _t) { t2 = std::move(_t); }

    // Whether the instruction should be included in final code
    // generation.
    bool live = true;

    // Whether the instruction is the beginning of a loop, meaning
    // it's the target of backward control flow.
    bool loop_start = false;

    // How deep the instruction is within loop bodies (for all
    // instructions in a loop, not just their beginnings).  For
    // example, a value of 2 means the instruction is inside a
    // loop that itself is inside one more loop.
    int loop_depth = 0;

    // Branch target, prior to concretizing into PC target.
    ZInstI* target = nullptr;
    int target_slot = 0; // which of v1/v2/v3 should hold the target

    // The final PC location of the statement.  -1 indicates not
    // yet assigned.
    int inst_num = -1;

    // Number of associated label(s) (indicating the statement is
    // a branch target).
    int num_labels = 0;

private:
    // Initialize 'c' from the given ConstExpr.
    void InitConst(const ConstExpr* ce);
};

// Returns a human-readable version of the given ZAM op-code.
extern const char* ZOP_name(ZOp op);

// Maps a generic operation to a specific one associated with the given type.
// The third argument governs what to do if the given type has no assignment
// flavor.  If true, this leads to an assertion failure.  If false, and
// if there's no flavor for the type, then OP_NOP is returned.
extern ZOp AssignmentFlavor(ZOp orig, TypeTag tag, bool strict = true);

// The following all use initializations produced by Gen-ZAM.

// Maps first operands, and then type tags, to operands.
extern std::unordered_map<ZOp, std::unordered_map<TypeTag, ZOp>> assignment_flavor;

// Maps flavorful assignments to their non-assignment counterpart.
// Used for optimization when we determine that the assigned-to
// value is superfluous.
extern std::unordered_map<ZOp, ZOp> assignmentless_op;

// Maps flavorful assignments to what operand class their non-assignment
// counterpart uses.
extern std::unordered_map<ZOp, ZAMOpType> assignmentless_op_class;

} // namespace zeek::detail
