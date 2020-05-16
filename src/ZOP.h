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
	OP_NOP,
#include "ZAM-OpsDefs.h"
} ZOp;


// Possible types of statement operands in terms of which fields they use.
// Used for dumping statements.
typedef enum {
	OP_X, OP_V, OP_VV, OP_VVV, OP_VVVV, OP_VVVC, OP_C, OP_VC, OP_VVC,
	OP_E, OP_VE, OP_VV_FRAME, OP_VC_ID,
	OP_V_I1, OP_VV_I2, OP_VVC_I2, OP_VVV_I3, OP_VVV_I2_I3,
} ZAMOpType;

// Maps ZAM frame slots to associated identifiers.   
typedef std::vector<const ID*> frame_map;

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

	// Constructor used when we're going to just copy in another ZAM.
	ZInst() { }

	const char* VName(int max_n, int n, const frame_map& frame_ids) const;
	int NumFrameSlots() const;
	void Dump(const frame_map& frame_ids) const;
	const char* ConstDump() const;

	ZOp op;

	// Indices into frame.
	int v1, v2, v3, v4;
	BroType* t = nullptr;
	const Expr* e = nullptr;
	Expr* non_const_e = nullptr;
	int* int_ptr = nullptr;
	EventHandler* event_handler = nullptr;
	Attributes* attrs = nullptr;
	const Stmt* stmt = curr_stmt;

	ZAMValUnion c;	// constant associated with instruction

	ZAMOpType op_type;

protected:
	// Initialize 'c' from the given ConstExpr.
	void InitConst(const ConstExpr* ce);
};
