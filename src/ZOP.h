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
	OP_X, OP_E, OP_C, OP_V, OP_V_I1,

	OP_VE,
	OP_VC,
	OP_VC_ID,
	OP_VV,
	OP_VV_I2,
	OP_VV_I1_I2,
	OP_VV_FRAME,

	OP_VVC,
	OP_VVC_I2,
	OP_VVc,
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
	// The IDs sharing the slot.
	std::vector<const ID*> ids;

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

// A ZAM instruction.
class ZInst {
public:
	ZInst(ZOp _op)
		{
		op = _op;
		op_type = OP_X;
		}

	ZInst(ZOp _op, int _v1)
		{
		op = _op;
		v1 = _v1;
		op_type = OP_V;
		}

	ZInst(ZOp _op, int _v1, int _v2)
		{
		op = _op;
		v1 = _v1;
		v2 = _v2;
		op_type = OP_VV;
		}

	ZInst(ZOp _op, int _v1, int _v2, int _v3)
		{
		op = _op;
		v1 = _v1;
		v2 = _v2;
		v3 = _v3;
		op_type = OP_VVV;
		}

	ZInst(ZOp _op, int _v1, int _v2, int _v3, int _v4)
		{
		op = _op;
		v1 = _v1;
		v2 = _v2;
		v3 = _v3;
		v4 = _v4;
		op_type = OP_VVVV;
		}

	ZInst(ZOp _op, const ConstExpr* ce)
		{
		op = _op;
		op_type = OP_C;
		InitConst(ce);
		}

	ZInst(ZOp _op, int _v1, const ConstExpr* ce)
		{
		op = _op;
		v1 = _v1;
		op_type = OP_VC;
		InitConst(ce);
		}

	ZInst(ZOp _op, int _v1, int _v2, const ConstExpr* ce)
		{
		op = _op;
		v1 = _v1;
		v2 = _v2;
		op_type = OP_VVC;
		InitConst(ce);
		}

	ZInst(ZOp _op, int _v1, int _v2, int _v3, const ConstExpr* ce)
		{
		op = _op;
		v1 = _v1;
		v2 = _v2;
		v3 = _v3;
		op_type = OP_VVVC;
		InitConst(ce);
		}

	ZInst(ZOp _op, const Expr* _e)
		{
		op = _op;
		e = _e;
		t = e->Type().get();
		op_type = OP_E;
		}

	ZInst(ZOp _op, int _v1, const Expr* _e)
		{
		op = _op;
		v1 = _v1;
		e = _e;
		t = e->Type().get();
		op_type = OP_VE;
		}

	// Constructor used when we're going to just copy in another ZInst.
	ZInst() { }

	// True if this instruction definitely won't proceed to the one
	// after it.
	bool DoesNotContinue() const;

	// True if this instruction always branches elsewhere.  Different
	// from DoesNotContinue in that returns do not continue, but they
	// are not branches.
	bool IsUnconditionalBranch() const	{ return op == OP_GOTO_V; }

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

	bool IsFrameLoad() const
		{ return op == OP_LOAD_VAL_VV || op == OP_LOAD_ANY_VAL_VV; }
	bool IsFrameStore() const
		{ return op == OP_STORE_VAL_VV || op == OP_STORE_ANY_VAL_VV; }

	bool IsFrameSync() const
		{ return IsFrameLoad() || IsFrameStore(); }

	const char* VName(int max_n, int n, const FrameMap* frame_ids,
				const FrameReMap* remappings) const;
	int NumFrameSlots() const;

	// If "remappings" is non-nil, then it is used instead of frame_ids.
	void Dump(const FrameMap* frame_ids, const FrameReMap* remappings)
		const;

	const char* ConstDump() const;


	// These first values are needed at run-time.  We could separate
	// them from the later values only needed at compile time to
	// shrink the size of frames.  This won't matter much in terms
	// of memory usage, as Zeek call stacks don't appear to ever
	// get that deep.  OTOH, it might be beneficial for creating
	// closures (how common is that?).  OTOOH, keeping them together
	// for now can help with certain types of compiler debugging.
	ZOp op;
	ZAMOpType op_type;

	// Indices into frame.
	int v1, v2, v3, v4;

	ZAMValUnion c;	// constant associated with instruction, if any

	// Meta-data associated with the execution.

	// Type, usually for interpreting the constant.
	BroType* t = nullptr;

	// These two could be doubled up into a union, or just grit
	// our teeth and use coercion to construct only the latter.
	const Expr* e = nullptr;
	Expr* non_const_e = nullptr;

	EventHandler* event_handler = nullptr;
	Attributes* attrs = nullptr;

	// Looks like we could remove this by changing Record-Coerce to be
	// (a new) VVVV_I4.
	int* int_ptr = nullptr;

	// Used for reporting errors during execution.
	const Stmt* stmt = curr_stmt;

	// Whether v1 represents a frame slot type for which we
	// explicitly manage the memory.
	bool is_managed = false;

	// These are only needed during compilation.
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

	// The following are only needed during compilation.

	// Whether the instruction should be included in final code
	// generation.
	bool live = true;

	// Whether the instruction is inside a block that could be
	// visited more than once due to backware control flow.
	bool inside_loop = false;

	// Branch target, prior to concretizing into PC target.
	ZInst* target = nullptr;
	int target_slot = 0;	// which of v1/v2/v3 should hold the target

	// The final PC location of the statement.  -1 indicates not
	// yet assigned.
	int inst_num = -1;

	// Number of associated label(s) (indicating the statement is
	// a branch target).
	int num_labels = 0;

protected:
	// Initialize 'c' from the given ConstExpr.
	void InitConst(const ConstExpr* ce);
};

extern const char* ZOP_name(ZOp op);

extern bool ZAM_error;
