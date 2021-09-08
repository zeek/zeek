// See the file "COPYING" in the main distribution directory for copyright.

// Operators and instructions used in ZAM execution.

#pragma once

#include "zeek/script_opt/ZAM/Support.h"
#include "zeek/script_opt/ZAM/ZOp.h"

namespace zeek::detail {

class Expr;
class ConstExpr;
class Attributes;
class Stmt;

using AttributesPtr = IntrusivePtr<Attributes>;

// Maps ZAM frame slots to associated identifiers.   
using FrameMap = std::vector<ID*>;

// Maps ZAM frame slots to information for sharing the slot across
// multiple script variables.
class FrameSharingInfo {
public:
	// The variables sharing the slot.  ID's need to be non-const so we
	// can manipulate them, for example by changing their interpreter
	// frame offset.
	std::vector<ID*> ids;

	// A parallel vector, only used for fully compiled code, which
	// gives the names of the identifiers.  When in use, the above
	// "ids" member variable may be empty.
	std::vector<const char*> names;

	// The ZAM instruction number where a given identifier starts its
	// scope, parallel to "ids".
	std::vector<int> id_start;

	// The current end of the frame slot's scope.  Gets updated as
	// new IDs are added to share the slot.
	int scope_end;

	// Whether this is a managed slot.
	bool is_managed;
};

using FrameReMap = std::vector<FrameSharingInfo>;

class ZInstAux;

// A ZAM instruction.  This base class has all the information for
// execution, but omits information and methods only necessary for
// compiling.
class ZInst {
public:
	ZInst(ZOp _op, ZAMOpType _op_type)
		{
		op = _op;
		op_type = _op_type;
		}

	// Create a stub instruction that will be populated later.
	ZInst()	{ }

	virtual ~ZInst()	{ }

	// Methods for printing out the instruction for debugging/maintenance.
	void Dump(int inst_num, const FrameReMap* mappings) const;
	void Dump(const std::string& id1, const std::string& id2,
	          const std::string& id3, const std::string& id4) const;

	// Returns the name to use in identifying one of the slots/integer
	// values (designated by "n").  "inst_num" identifes the instruction
	// by its number within a larger set.  "mappings" provides the
	// mappings used to translate raw slots to the corresponding
	// script variable(s).
	std::string VName(int n, int inst_num,
	                  const FrameReMap* mappings) const;

	// Number of slots that refer to a frame element.  These always
	// come first, if we use additional slots.
	int NumFrameSlots() const;

	// Total number of slots in use.  >= NumFrameSlots()
	int NumSlots() const;

	// Returns nil if this instruction doesn't have an associated constant.
	ValPtr ConstVal() const;

	// Returns a string describing the constant.
	std::string ConstDump() const;

	ZOp op;
	ZAMOpType op_type;

	// Usually indices into frame, though sometimes hold integer constants.
	// When an instruction has both frame slots and integer constants,
	// the former always come first, even if conceptually in the operation
	// the constant is an "earlier" operand.
	int v1, v2, v3, v4;

	ZVal c;	// constant associated with instruction, if any

	// Meta-data associated with the execution.

	// Type, usually for interpreting the constant.
	TypePtr t = nullptr;
	TypePtr t2 = nullptr;	// just a few ops need two types
	const Expr* e = nullptr;	// only needed for "when" expressions
	Func* func = nullptr;	// used for calls
	EventHandler* event_handler = nullptr;	// used for referring to events
	AttributesPtr attrs = nullptr;	// used for things like constructors

	// Auxiliary information.  We could in principle use this to
	// consolidate a bunch of the above, though at the cost of
	// slightly slower access.  Most instructions don't need "aux",
	// which is why we bundle these separately.
	ZInstAux* aux = nullptr;

	// Location associated with this instruction, for error reporting.
	const Location* loc = nullptr;

	// Whether v1 represents a frame slot type for which we
	// explicitly manage the memory.
	bool is_managed = false;
};

// A intermediary ZAM instruction, one that includes information/methods
// needed for compiling.  Intermediate instructions use pointers to other
// such instructions for branches, rather than concrete instruction
// numbers.  This allows the AM optimizer to easily prune instructions.
class ZInstI : public ZInst {
public:
	// These constructors can be used directly, but often instead
	// they'll be generated via the use of Inst-Gen methods.
	ZInstI(ZOp _op) : ZInst(_op, OP_X)
		{
		op = _op;
		op_type = OP_X;
		}

	ZInstI(ZOp _op, int _v1) : ZInst(_op, OP_V)
		{
		v1 = _v1;
		}

	ZInstI(ZOp _op, int _v1, int _v2) : ZInst(_op, OP_VV)
		{
		v1 = _v1;
		v2 = _v2;
		}

	ZInstI(ZOp _op, int _v1, int _v2, int _v3) : ZInst(_op, OP_VVV)
		{
		v1 = _v1;
		v2 = _v2;
		v3 = _v3;
		}

	ZInstI(ZOp _op, int _v1, int _v2, int _v3, int _v4)
	: ZInst(_op, OP_VVVV)
		{
		v1 = _v1;
		v2 = _v2;
		v3 = _v3;
		v4 = _v4;
		}

	ZInstI(ZOp _op, const ConstExpr* ce) : ZInst(_op, OP_C)
		{
		InitConst(ce);
		}

	ZInstI(ZOp _op, int _v1, const ConstExpr* ce) : ZInst(_op, OP_VC)
		{
		v1 = _v1;
		InitConst(ce);
		}

	ZInstI(ZOp _op, int _v1, int _v2, const ConstExpr* ce)
	: ZInst(_op, OP_VVC)
		{
		v1 = _v1;
		v2 = _v2;
		InitConst(ce);
		}

	ZInstI(ZOp _op, int _v1, int _v2, int _v3, const ConstExpr* ce)
	: ZInst(_op, OP_VVVC)
		{
		v1 = _v1;
		v2 = _v2;
		v3 = _v3;
		InitConst(ce);
		}

	// Constructor used when we're going to just copy in another ZInstI.
	ZInstI() { }

	// If "remappings" is non-nil, then it is used instead of frame_ids.
	void Dump(const FrameMap* frame_ids, const FrameReMap* remappings) const;

	// Note that this is *not* an override of the base class's VName
	// but instead a method with similar functionality but somewhat
	// different behavior (namely, being cognizant of frame_ids).
	std::string VName(int n, const FrameMap* frame_ids,
	                  const FrameReMap* remappings) const;

	// True if this instruction definitely won't proceed to the one
	// after it.
	bool DoesNotContinue() const;

	// True if this instruction always branches elsewhere.  Different
	// from DoesNotContinue() in that returns & hook breaks do not
	// continue, but they are not branches.
	bool IsUnconditionalBranch() const	{ return op == OP_GOTO_V; }

	// True if this instruction is of the form "v1 = v2".
	bool IsDirectAssignment() const;

	// True if this instruction has side effects when executed, so
	// should not be pruned even if it has a dead assignment.
	bool HasSideEffects() const;

	// True if the given instruction assigns to the frame location
	// given by slot 1 (v1).
	bool AssignsToSlot1() const;

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

	// True if the instruction corresponds to some sort of load,
	// either from the interpreter frame or of a global.
	bool IsLoad() const
		{
		return op_type == OP_VV_FRAME || IsGlobalLoad();
		}

	// True if the instruction corresponds to storing a global.
	bool IsGlobalStore() const
		{
		return op == OP_STORE_GLOBAL_V;
		}

	void CheckIfManaged(const TypePtr& t)
		{ if ( ZVal::IsManagedType(t) ) is_managed = true; }

	void SetType(TypePtr _t)
		{
		t = std::move(_t);
		if ( t )
			CheckIfManaged(t);
		}

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
	int target_slot = 0;	// which of v1/v2/v3 should hold the target

	// The final PC location of the statement.  -1 indicates not
	// yet assigned.
	int inst_num = -1;

	// Number of associated label(s) (indicating the statement is
	// a branch target).
	int num_labels = 0;

	// Used for debugging.  Transformed into the ZInst "loc" field.
	const Stmt* stmt = curr_stmt;

private:
	// Initialize 'c' from the given ConstExpr.
	void InitConst(const ConstExpr* ce);
};

// Auxiliary information, used when the fixed ZInst layout lacks
// sufficient expressiveness to represent all of the elements that
// an instruction needs.
class ZInstAux {
public:
	// if n is positive then it gives the size of parallel arrays
	// tracking slots, constants, and types.
	ZInstAux(int _n)
		{
		n = _n;
		if ( n > 0 )
			{
			slots = ints = new int[n];
			constants = new ValPtr[n];
			types = new TypePtr[n];
			}
		}

	~ZInstAux()
		{
		delete [] ints;
		delete [] constants;
		delete [] types;
		}

	// Returns the i'th element of the parallel arrays as a ValPtr.
	ValPtr ToVal(const ZVal* frame, int i) const
		{
		if ( constants[i] )
			return constants[i];
		else
			return frame[slots[i]].ToVal(types[i]);
		}

	// Returns the parallel arrays as a ListValPtr.
	ListValPtr ToListVal(const ZVal* frame) const
		{
		auto lv = make_intrusive<ListVal>(TYPE_ANY);
		for ( auto i = 0; i < n; ++i )
			lv->Append(ToVal(frame, i));

		return lv;
		}

	// Converts the parallel arrays to a ListValPtr suitable for
	// use as indices for indexing a table or set.  "offset" specifies
	// which index we're looking for (there can be a bunch for
	// constructors), and "width" the number of elements in a single
	// index.
	ListValPtr ToIndices(const ZVal* frame, int offset, int width) const
		{
		auto lv = make_intrusive<ListVal>(TYPE_ANY);
		for ( auto i = 0; i < 0 + width; ++i )
			lv->Append(ToVal(frame, offset + i));

		return lv;
		}

	// Returns the parallel arrays converted to a vector of ValPtr's.
	const ValVec& ToValVec(const ZVal* frame)
		{
		vv.clear();
		FillValVec(vv, frame);
		return vv;
		}

	// Populates the given vector of ValPtr's with the conversion
	// of the parallel arrays.
	void FillValVec(ValVec& vec, const ZVal* frame) const
		{
		for ( auto i = 0; i < n; ++i )
			vec.push_back(ToVal(frame, i));
		}

	// When building up a ZInstAux, sets one element of the parallel
	// arrays to a given frame slot and type.
	void Add(int i, int slot, TypePtr t)
		{
		ints[i] = slot;
		constants[i] = nullptr;
		types[i] = t;
		}

	// Same but for constants.
	void Add(int i, ValPtr c)
		{
		ints[i] = -1;
		constants[i] = c;
		types[i] = nullptr;
		}


	// Member variables.  We could add accessors for manipulating
	// these (and make the variables private), but for convenience we
	// make them directly available.

	// These are parallel arrays, used to build up lists of values.
	// Each element is either an integer or a constant.  Usually the
	// integer is a frame slot (in which case "slots" points to "ints";
	// if not, it's nil).
	//
	// We track associated types, too, enabling us to use
	// ZVal::ToVal to convert frame slots or constants to ValPtr's.

	int n;	// size of arrays
	int* slots = nullptr;	// either nil or points to ints
	int* ints = nullptr;
	ValPtr* constants = nullptr;
	TypePtr* types = nullptr;

	// Used for accessing function names.
	ID* id_val = nullptr;

	// Whether the instruction can lead to globals changing.
	// Currently only needed by the optimizer, but convenient
	// to store here.
	bool can_change_globals = false;

	// The following is only used for OP_CONSTRUCT_KNOWN_RECORD_V,
	// to map elements in slots/constants/types to record field offsets.
	std::vector<int> map;

	///// The following three apply to looping over the elements of tables.

	// Frame slots of iteration variables, such as "[v1, v2, v3] in aggr".
	std::vector<int> loop_vars;

	// Their types.
	std::vector<TypePtr> loop_var_types;

	// Type associated with the "value" entry, for "k, value in aggr"
	// iteration.
	TypePtr value_var_type;


	// This is only used to return values stored elsewhere in this
	// object - it's not set directly.
	//
	// If we cared about memory penny-pinching, we could make this
	// a pointer and only instantiate as needed.
	ValVec vv;
};

// Returns a human-readable version of the given ZAM op-code.
extern const char* ZOP_name(ZOp op);

// Maps a generic operation to a specific one associated with the given type.
// The third argument governs what to do if the given type has no assignment
// flavor.  If true, this leads to an assertion failure.  If false, and
// if there's no flavor for the type, then OP_NOP is returned.
extern ZOp AssignmentFlavor(ZOp orig, TypeTag tag, bool strict=true);


// The following all use initializations produced by Gen-ZAM.

// Maps first operands, and then type tags, to operands.
extern std::unordered_map<ZOp, std::unordered_map<TypeTag, ZOp>> assignment_flavor;
        
// Maps flavorful assignments to their non-assignment counterpart.
// Used for optimization when we determine that the assigned-to
// value is superfluous.
extern std::unordered_map<ZOp, ZOp> assignmentless_op;

// Maps flavorful assignments to what op-type their non-assignment
// counterpart uses.
extern std::unordered_map<ZOp, ZAMOpType> assignmentless_op_type;

} // namespace zeek::detail
