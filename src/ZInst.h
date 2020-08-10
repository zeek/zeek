// See the file "COPYING" in the main distribution directory for copyright.

// Operators and instructions used in ZAM execution.

#pragma once

#include "ZVal.h"
#include "Compile.h"

class Expr;
class ConstExpr;
class EventHandler;
class Attributes;
class Stmt;

// Operands associated with ZAM instructions.
typedef enum {
#include "ZAM-OpsDefs.h"
	OP_NOP,
} ZOp;


// Possible types of statement operands in terms of which fields they use.
// Used for low-level optimization (so important that they're correct),
// and for dumping statements.
typedef enum {
	OP_X, OP_C, OP_V, OP_V_I1, OP_VC_I1,

	OP_VC,
	OP_VV,
	OP_VV_I2,
	OP_VV_I1_I2,
	OP_VV_FRAME,

	OP_VVC,
	OP_VVC_I2,
	OP_VVV,
	OP_VVV_I3,
	OP_VVV_I2_I3,

	OP_VVVC,
	OP_VVVC_I3,
	OP_VVVC_I2_I3,
	OP_VVVC_I1_I2_I3,
	OP_VVVV,
	OP_VVVV_I4,
	OP_VVVV_I3_I4,
	OP_VVVV_I2_I3_I4,

} ZAMOpType;

// Possible "flavors" for an operator's first slot.
typedef enum {
	OP1_READ,	// the slot is read, not modified
	OP1_WRITE,	// the slot is modified, not read - the most common
	OP1_READ_WRITE,	// the slot is both read and then modified, e.g. "++"
	OP1_INTERNAL,	// we're doing some internal manipulation of the slot
} ZAMOp1Flavor;

// Maps an operand to its flavor.
extern ZAMOp1Flavor op1_flavor[];

// Maps ZAM frame slots to associated identifiers.   
typedef std::vector<ID*> FrameMap;

// Maps ZAM frame slots to information for sharing across multiple identifiers.
class FrameSharingInfo {
public:
	// The IDs sharing the slot.  IDs need to be non-const so we
	// can manipulate them, for example by changing their interpreter
	// frame offset.
	std::vector<ID*> ids;

	// A parallel vector, only used for fully compiled code, which
	// gives the names of the identifiers.  When in use, "ids" may
	// be empty.
	std::vector<const char*> names;

	// The statement number where a given identifier starts its scope,
	// parallel to "ids".
	std::vector<int> id_start;

	// The current end of the frame slot's scope.  Gets updated as
	// new IDs are added to share the slot.
	int scope_end;

	// Whether this is a managed slot.
	bool is_managed;
};

typedef std::vector<FrameSharingInfo> FrameReMap;

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

	// Stub for now.
	ZInst()	{ }

	virtual ~ZInst()	{ }

	void Dump(int inst_num, const FrameReMap* mappings) const;
	void Dump(const char* id1, const char* id2, const char* id3,
			const char* id4) const;

	const char* VName(int max_n, int n, int inst_num,
				const FrameReMap* mappings) const;

	// Number of slots that refer to a frame element.  These always
	// come first, if we use additional slots.
	int NumFrameSlots() const;

	// Total number of slots in use.  >= NumFrameSlots()
	int NumSlots() const;

	// Returns nil if this instruction doesn't have an associated constant.
	IntrusivePtr<Val> ConstVal() const;
	const char* ConstDump() const;

	ZOp op;
	ZAMOpType op_type;

	// Usually indices into frame, though sometimes hold integer constants.
	int v1, v2, v3, v4;

	ZAMValUnion c;	// constant associated with instruction, if any

	// Meta-data associated with the execution.

	// Type, usually for interpreting the constant.
	BroType* t = nullptr;
	BroType* t2 = nullptr;	// just a few operations need two types

	Expr* e = nullptr;	// only needed for "when" expressions

	Func* func = nullptr;	// used for calls

	EventHandler* event_handler = nullptr;
	Attributes* attrs = nullptr;

	// Auxiliary information.  We could in principle use this to
	// consolidate a bunch of the above, though at the cost of
	// slightly slower access.
	ZInstAux* aux = nullptr;

	// Location associated with this instruction, for error reporting.
	const Location* loc = nullptr;

	// Whether v1 represents a frame slot type for which we
	// explicitly manage the memory.
	bool is_managed = false;
};

// A intermediary ZAM instruction, one that includes information/methods
// needed for compiling.
class ZInstI : public ZInst {
public:
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
	void Dump(const FrameMap* frame_ids, const FrameReMap* remappings)
			const;

	const char* VName(int max_n, int n, const FrameMap* frame_ids,
				const FrameReMap* remappings) const;

	// True if this instruction definitely won't proceed to the one
	// after it.
	bool DoesNotContinue() const;

	// True if this instruction always branches elsewhere.  Different
	// from DoesNotContinue in that returns do not continue, but they
	// are not branches.
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

	bool IsFrameStore() const
		{ return op == OP_STORE_VAL_VV || op == OP_STORE_ANY_VAL_VV; }

	bool IsLoad() const
		{
		if ( op_type == OP_VV_FRAME )
			return ! IsFrameStore();
		else
			return IsGlobalLoad();
		}

	void CheckIfManaged(const Expr* e)
		{ if ( IsManagedType(e) ) is_managed = true; }

	void CheckIfManaged(const BroType* t)
		{ if ( IsManagedType(t) ) is_managed = true; }

	void SetType(BroType* _t)
		{
		t = _t;
		if ( t )
			CheckIfManaged(t);
		}

	void SetType(const IntrusivePtr<BroType>& _t)
		{ SetType(_t.get()); }

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

	// "when" statements, alas, need two goto targets ...
	ZInstI* target2 = nullptr;
	int target2_slot = 0;	// which of v1/v2/v3 should hold the target

	// The final PC location of the statement.  -1 indicates not
	// yet assigned.
	int inst_num = -1;

	// Number of associated label(s) (indicating the statement is
	// a branch target).
	int num_labels = 0;

	// Used for debugging.  Transformed into the ZInst "loc" field.
	const Stmt* stmt = curr_stmt;

protected:
	// Initialize 'c' from the given ConstExpr.
	void InitConst(const ConstExpr* ce);
};

// Auxiliary information, used when the fixed ZInst layout lacks
// sufficient expressiveness to represent all of the elements that
// an instruction needs.
class ZInstAux {
public:
	ZInstAux(int _n)
		{
		n = _n;
		if ( n > 0 )
			{
			slots = ints = new int[n];
			constants = new IntrusivePtr<Val>[n];
			types = new IntrusivePtr<BroType>[n];
			}
		}

	~ZInstAux()
		{
		delete [] ints;
		delete [] constants;
		delete [] types;
		delete iter_info;
		}

	IntrusivePtr<Val> ToVal(const ZAMValUnion* frame, int i) const
		{
		if ( constants[i] )
			return constants[i];
		else
			return frame[slots[i]].ToVal(types[i].get());
		}

	IntrusivePtr<ListVal> ToListVal(const ZAMValUnion* frame) const
		{
		auto lv = make_intrusive<ListVal>(TYPE_ANY);
		for ( auto i = 0; i < n; ++i )
			lv->Append(ToVal(frame, i).release());

		return lv;
		}

	IntrusivePtr<ListVal> ToIndices(const ZAMValUnion* frame,
					int offset, int width) const
		{
		auto lv = make_intrusive<ListVal>(TYPE_ANY);
		for ( auto i = 0; i < 0 + width; ++i )
			lv->Append(ToVal(frame, offset + i).release());

		return lv;
		}

	const val_vec& ToValVec(const ZAMValUnion* frame)
		{
		vv.clear();
		FillValVec(vv, frame);
		return vv;
		}

	void FillValVec(val_vec& vec, const ZAMValUnion* frame) const
		{
		for ( auto i = 0; i < n; ++i )
			vec.push_back(ToVal(frame, i));
		}

	void Add(int i, int slot, IntrusivePtr<BroType> t)
		{
		ints[i] = slot;
		constants[i] = nullptr;
		types[i] = t;
		}

	void Add(int i, IntrusivePtr<Val> c)
		{
		ints[i] = -1;
		constants[i] = c;
		types[i] = nullptr;
		}

	// These are parallel arrays, used to build up lists of values.
	// Each element is either an integer or a constant.  Usually the
	// integer is a frame slot (in which case "slots" points to "ints";
	// if not, it's nil).
	//
	// We track associated types, too, enabling us to use
	// ZAMValUnion::ToVal to convert frame slots or constants to Val*'s.
	int n;	// size of arrays
	int* slots = nullptr;	// either nil or points to ints
	int* ints = nullptr;
	IntrusivePtr<Val>* constants = nullptr;
	IntrusivePtr<BroType>* types = nullptr;

	// If non-nil, then iteration information for a loop.
	IterInfo* iter_info = nullptr;

	// Used for manipulating globals.
	ID* id_val = nullptr;

	// This is only used to return values stored elsewhere in this
	// object - it's not set directly.
	//
	// If we cared about memory penny-pinching, we could make
	// this a pointer and only instantiate as needed.  
	val_vec vv;
};

extern const char* ZOP_name(ZOp op);

// Maps a generic operation to a specific one associated with the given type.
// The third argument governs what to do if the given type has no assignment
// flavor.  If true, this leads to an assertion failure.  If false, and
// if there's no flavor for the type, then OP_NOP is returned.
extern ZOp AssignmentFlavor(ZOp orig, TypeTag tag, bool strict=true);

// Maps first operands and then type tags to operands.
extern std::unordered_map<ZOp, std::unordered_map<TypeTag, ZOp>> 
        assignment_flavor;
        
// Maps flavorful assignments to their non-assignment counterpart.
// Used for optimization when we determine that the assigned-to
// value is superfluous.
extern std::unordered_map<ZOp, ZOp> assignmentless_op;

// Maps flavorful assignments to what op-type their non-assignment
// counterpart uses.
extern std::unordered_map<ZOp, ZAMOpType> assignmentless_op_type;

extern bool ZAM_error;
