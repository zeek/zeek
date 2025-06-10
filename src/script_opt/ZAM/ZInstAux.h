// See the file "COPYING" in the main distribution directory for copyright.

// Operators and instructions used in ZAM execution.

#pragma once

#include "zeek/Expr.h"
#include "zeek/Func.h"
#include "zeek/TraverseTypes.h"
#include "zeek/script_opt/ZAM/BuiltInSupport.h"
#include "zeek/script_opt/ZAM/Frame.h"
#include "zeek/script_opt/ZAM/Support.h"

namespace zeek::detail {

class ZInst;
class ZInstI;

class Attributes;
using AttributesPtr = IntrusivePtr<Attributes>;

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

enum ControlFlowType : uint8_t {
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

} // namespace zeek::detail
