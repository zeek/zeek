// See the file "COPYING" in the main distribution directory for copyright.

// Operators and instructions used in ZAM execution.

#pragma once

#include "zeek/Func.h"
#include "zeek/TraverseTypes.h"
#include "zeek/script_opt/ZAM/BuiltInSupport.h"
#include "zeek/script_opt/ZAM/Support.h"
#include "zeek/script_opt/ZAM/ZOp.h"

namespace zeek::detail {

class Expr;
class ConstExpr;
class Attributes;
class Stmt;

using AttributesPtr = IntrusivePtr<Attributes>;

// Maps ZAM frame slots to associated identifiers.
using FrameMap = std::vector<const ID*>;

// Maps ZAM frame slots to information for sharing the slot across
// multiple script variables.
class FrameSharingInfo {
public:
    // The variables sharing the slot.  ID's need to be non-const so we
    // can manipulate them, for example by changing their interpreter
    // frame offset.
    std::vector<const ID*> ids;

    // A parallel vector, only used for fully compiled code, which
    // gives the names of the identifiers.  When in use, the above
    // "ids" member variable may be empty.
    std::vector<const char*> names;

    // The ZAM instruction number where a given identifier starts its
    // scope, parallel to "ids".
    std::vector<zeek_uint_t> id_start;

    // The current end of the frame slot's scope.  Gets updated as
    // new IDs are added to share the slot.
    int scope_end = -1;

    // Whether this is a managed slot.
    bool is_managed = false;
};

using FrameReMap = std::vector<FrameSharingInfo>;

class ZInstAux;

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

// Class for tracking one element of auxiliary information. This can be an
// integer, often specifying a frame slot, or a Val representing a constant.
// The class also tracks any associated type and caches whether it's "managed".
class AuxElem {
public:
    AuxElem() {}

    // Different ways of setting the specifics of the element.
    void SetInt(int _i) { i = _i; }
    void SetInt(int _i, TypePtr _t) {
        i = _i;
        SetType(std::move(_t));
    }
    void SetSlot(int slot) { i = slot; }
    void SetConstant(ValPtr _c) {
        c = std::move(_c);
        // c might be null in some contexts.
        if ( c ) {
            SetType(c->GetType());
            zc = ZVal(c, t);
        }
    }

    // Returns the element as a Val object.
    ValPtr ToVal(const ZVal* frame) const {
        if ( c )
            return c;
        else
            return frame[i].ToVal(t);
    }

    // Returns the element as a ZVal object.
    ZVal ToZVal(const ZVal* frame) const {
        ZVal zv = c ? zc : frame[i];
        if ( is_managed )
            Ref(zv.ManagedVal());
        return zv;
    }

    // The same, but for read-only access for which memory-management is
    // not required.
    const ZVal& ToDirectZVal(const ZVal* frame) const {
        if ( c )
            return zc;
        if ( i >= 0 )
            return frame[i];

        // Currently the way we use AuxElem's we shouldn't get here, but
        // just in case we do, return something sound rather than mis-indexing
        // the frame.
        static ZVal null_zval;
        return null_zval;
    }

    int Slot() const { return i; }
    int IntVal() const { return i; }
    const ValPtr& Constant() const { return c; }
    ZVal ZConstant() const { return zc; }
    const TypePtr& GetType() const { return t; }
    bool IsManaged() const { return is_managed; }

private:
    void SetType(TypePtr _t) {
        t = std::move(_t);
        is_managed = t ? ZVal::IsManagedType(t) : false;
    }

    int i = -1; // -1 = "not a slot"
    ValPtr c;
    ZVal zc;
    TypePtr t;
    bool is_managed = false;
};

enum ControlFlowType {
    CFT_IF,
    CFT_BLOCK_END,
    CFT_ELSE,
    CFT_LOOP,
    CFT_LOOP_COND,
    CFT_LOOP_END,
    CFT_NEXT,
    CFT_BREAK,
    CFT_DEFAULT,
    CFT_INLINED_RETURN,

    CFT_NONE,
};

// Auxiliary information, used when the fixed ZInst layout lacks
// sufficient expressiveness to represent all of the elements that
// an instruction needs.
class ZInstAux {
public:
    // if n is positive then it gives the size of parallel arrays
    // tracking slots, constants, and types.
    ZInstAux(int _n) {
        n = _n;
        if ( n > 0 )
            elems = new AuxElem[n];
    }

    ~ZInstAux() {
        delete[] elems;
        delete[] cat_args;
    }

    // Returns the i'th element of the elements as a ValPtr.
    ValPtr ToVal(const ZVal* frame, int i) const { return elems[i].ToVal(frame); }
    ZVal ToZVal(const ZVal* frame, int i) const { return elems[i].ToZVal(frame); }

    // Returns the elements as a ListValPtr.
    ListValPtr ToListVal(const ZVal* frame) const {
        auto lv = make_intrusive<ListVal>(TYPE_ANY);
        for ( auto i = 0; i < n; ++i )
            lv->Append(elems[i].ToVal(frame));

        return lv;
    }

    // Converts the elements to a ListValPtr suitable for use as indices
    // for indexing a table or set.  "offset" specifies which index we're
    // looking for (there can be a bunch for constructors), and "width"
    // the number of elements in a single index.
    ListValPtr ToIndices(const ZVal* frame, int offset, int width) const {
        auto lv = make_intrusive<ListVal>(TYPE_ANY);
        for ( auto i = 0; i < 0 + width; ++i )
            lv->Append(elems[offset + i].ToVal(frame));

        return lv;
    }

    // Returns the elements converted to a vector of ValPtr's.
    const ValVec& ToValVec(const ZVal* frame) {
        vv.clear();
        FillValVec(vv, frame);
        return vv;
    }

    // Populates the given vector of ValPtr's with the conversion
    // of the elements.
    void FillValVec(ValVec& vec, const ZVal* frame) const {
        for ( auto i = 0; i < n; ++i )
            vec.push_back(elems[i].ToVal(frame));
    }

    // Returns the elements converted to a vector of ZVal's.
    const auto& ToZValVec(const ZVal* frame) {
        for ( auto i = 0; i < n; ++i )
            zvec[i] = elems[i].ToZVal(frame);
        return zvec;
    }

    // Same, but using the "map" to determine where to place the values.
    // Returns a non-const value because in this situation other updates
    // may be coming to the vector, too.
    auto& ToZValVecWithMap(const ZVal* frame) {
        for ( auto i = 0; i < n; ++i )
            zvec[map[i]] = elems[i].ToZVal(frame);
        return zvec;
    }

    // When building up a ZInstAux, sets one element to a given frame slot
    // and type.
    void Add(int i, int slot, TypePtr t) { elems[i].SetInt(slot, t); }

    // Same, but for non-slot integers.
    void Add(int i, int v_i) { elems[i].SetInt(v_i); }

    // Same but for constants.
    void Add(int i, ValPtr c) { elems[i].SetConstant(c); }

    TraversalCode Traverse(TraversalCallback* cb) const;

    // Member variables.  We could add accessors for manipulating
    // these (and make the variables private), but for convenience we
    // make them directly available.

    int n; // size of elements
    AuxElem* elems = nullptr;
    bool elems_has_slots = true;

    // Info for constructing lambdas.
    LambdaExprPtr lambda;

    // For "when" statements.
    std::shared_ptr<WhenInfo> wi;

    // A parallel array for the cat() built-in replacement.
    std::unique_ptr<CatArg>* cat_args = nullptr;

    // Used for accessing function names.
    IDPtr id_val;

    // Interpreter call expression associated with this instruction,
    // for error reporting and stack backtraces.
    CallExprPtr call_expr;

    // Used for direct calls.
    Func* func = nullptr;

    // Whether we know that we're calling a BiF.
    bool is_BiF_call = false;

    // Associated control flow information.
    std::map<ControlFlowType, int> cft;

    // Used for referring to events.
    EventHandler* event_handler = nullptr;

    // Used for things like constructors.
    AttributesPtr attrs;

    // Whether the instruction can lead to globals/captures changing.
    // Currently only needed by the optimizer, but convenient to
    // store here.
    bool can_change_non_locals = false;

    // The following is used for constructing records or in record chain
    // operations, to map elements in slots/constants/types to record field
    // offsets.
    std::vector<int> map;

    // The following is used when we need two maps, a LHS one (done with
    // the above) and a RHS one.
    std::vector<int> rhs_map;

    // ... and the following when we need *three* (for constructing certain
    // types of records). We could hack it in by adding onto "map" but
    // this is cleaner, and we're not really concerned with the size of
    // ZAM auxiliary information as it's not that commonly used, and doesn't
    // grow during execution.
    std::vector<int> lhs_map;

    // For operations that need to track types corresponding to other vectors.
    std::vector<TypePtr> types;

    // For operations that mix managed and unmanaged assignments.
    std::vector<bool> is_managed;

    ///// The following four apply to looping over the elements of tables.

    // Frame slots of iteration variables, such as "[v1, v2, v3] in aggr".
    // A negative value means "skip assignment".
    std::vector<int> loop_vars;

    // Type associated with the "value" entry, for "k, value in aggr"
    // iteration.
    TypePtr value_var_type;

    // This is only used to return values stored elsewhere in this
    // object - it's not set directly.
    //
    // If we cared about memory penny-pinching, we could make this
    // a pointer and only instantiate as needed.
    ValVec vv;

    // Similar, but for ZVal's (used when constructing RecordVal's).
    std::vector<std::optional<ZVal>> zvec;

    // If non-nil, used for constructing records. Each pair gives the index
    // into the final record and the associated field initializer.
    std::unique_ptr<std::vector<std::pair<int, std::shared_ptr<detail::FieldInit>>>> field_inits;
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
