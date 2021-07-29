// See the file "COPYING" in the main distribution directory for copyright.

// Helper functions for generating ZAM code.

#include "zeek/script_opt/ZAM/Compile.h"


namespace zeek::detail {

ZInstI ZAMCompiler::GenInst(ZOp op)
	{
	return ZInstI(op);
	}

ZInstI ZAMCompiler::GenInst(ZOp op, const NameExpr* v1)
	{
	return ZInstI(op, Frame1Slot(v1, op));
	}

ZInstI ZAMCompiler::GenInst(ZOp op, const NameExpr* v1, int i)
	{
	auto z = ZInstI(op, Frame1Slot(v1, op), i);
	z.op_type = OP_VV_I2;
	return z;
	}

ZInstI ZAMCompiler::GenInst(ZOp op, const ConstExpr* c, const NameExpr* v1,
                            int i)
	{
	auto z = ZInstI(op, Frame1Slot(v1, op), i, c);
	z.op_type = OP_VVC_I2;
	return z;
	}

ZInstI ZAMCompiler::GenInst(ZOp op, const NameExpr* v1, const NameExpr* v2)
	{
	int nv2 = FrameSlot(v2);
	return ZInstI(op, Frame1Slot(v1, op), nv2);
	}

ZInstI ZAMCompiler::GenInst(ZOp op, const NameExpr* v1, const NameExpr* v2,
                            const NameExpr* v3)
	{
	int nv2 = FrameSlot(v2);
	int nv3 = FrameSlot(v3);
	return ZInstI(op, Frame1Slot(v1, op), nv2, nv3);
	}

ZInstI ZAMCompiler::GenInst(ZOp op, const NameExpr* v1, const NameExpr* v2,
                            const NameExpr* v3, const NameExpr* v4)
	{
	int nv2 = FrameSlot(v2);
	int nv3 = FrameSlot(v3);
	int nv4 = FrameSlot(v4);
	return ZInstI(op, Frame1Slot(v1, op), nv2, nv3, nv4);
	}

ZInstI ZAMCompiler::GenInst(ZOp op, const ConstExpr* ce)
	{
	return ZInstI(op, ce);
	}

ZInstI ZAMCompiler::GenInst(ZOp op, const NameExpr* v1, const ConstExpr* ce)
	{
	return ZInstI(op, Frame1Slot(v1, op), ce);
	}

ZInstI ZAMCompiler::GenInst(ZOp op, const ConstExpr* ce, const NameExpr* v1)
	{
	return ZInstI(op, Frame1Slot(v1, op), ce);
	}

ZInstI ZAMCompiler::GenInst(ZOp op, const NameExpr* v1, const ConstExpr* ce,
                            const NameExpr* v2)
	{
	int nv2 = FrameSlot(v2);
	return ZInstI(op, Frame1Slot(v1, op), nv2, ce);
	}

ZInstI ZAMCompiler::GenInst(ZOp op, const NameExpr* v1, const NameExpr* v2,
                            const ConstExpr* ce)
	{
	int nv2 = FrameSlot(v2);
	return ZInstI(op, Frame1Slot(v1, op), nv2, ce);
	}

ZInstI ZAMCompiler::GenInst(ZOp op, const NameExpr* v1, const NameExpr* v2,
                            const NameExpr* v3, const ConstExpr* ce)
	{
	int nv2 = FrameSlot(v2);
	int nv3 = FrameSlot(v3);
	return ZInstI(op, Frame1Slot(v1, op), nv2, nv3, ce);
	}

ZInstI ZAMCompiler::GenInst(ZOp op, const NameExpr* v1, const NameExpr* v2,
                            const ConstExpr* ce, const NameExpr* v3)
	{
	// Note that here we reverse the order of the arguments; saves
	// us from needing to implement a redundant constructor.
	int nv2 = FrameSlot(v2);
	int nv3 = FrameSlot(v3);
	return ZInstI(op, Frame1Slot(v1, op), nv2, nv3, ce);
	}

ZInstI ZAMCompiler::GenInst(ZOp op, const NameExpr* v1, const ConstExpr* c,
                            int i)
	{
	auto z = ZInstI(op, Frame1Slot(v1, op), i, c);
	z.op_type = OP_VVC_I2;
	return z;
	}

ZInstI ZAMCompiler::GenInst(ZOp op, const NameExpr* v1, const NameExpr* v2,
                            int i)
	{
	int nv2 = FrameSlot(v2);
	auto z = ZInstI(op, Frame1Slot(v1, op), nv2, i);
	z.op_type = OP_VVV_I3;
	return z;
	}

ZInstI ZAMCompiler::GenInst(ZOp op, const NameExpr* v1, const NameExpr* v2,
                            int i1, int i2)
	{
	int nv2 = FrameSlot(v2);
	auto z = ZInstI(op, Frame1Slot(v1, op), nv2, i1, i2);
	z.op_type = OP_VVVV_I3_I4;
	return z;
	}

ZInstI ZAMCompiler::GenInst(ZOp op, const NameExpr* v, const ConstExpr* c,
                            int i1, int i2)
	{
	auto z = ZInstI(op, Frame1Slot(v, op), i1, i2, c);
	z.op_type = OP_VVVC_I2_I3;
	return z;
	}

ZInstI ZAMCompiler::GenInst(ZOp op, const NameExpr* v1, const NameExpr* v2,
                            const NameExpr* v3, int i)
	{
	int nv2 = FrameSlot(v2);
	int nv3 = FrameSlot(v3);
	auto z = ZInstI(op, Frame1Slot(v1, op), nv2, nv3, i);
	z.op_type = OP_VVVV_I4;
	return z;
	}

ZInstI ZAMCompiler::GenInst(ZOp op, const NameExpr* v1, const NameExpr* v2,
                            const ConstExpr* c, int i)
	{
	int nv2 = FrameSlot(v2);
	auto z = ZInstI(op, Frame1Slot(v1, op), nv2, i, c);
	z.op_type = OP_VVVC_I3;
	return z;
	}

ZInstI ZAMCompiler::GenInst(ZOp op, const NameExpr* v1, const ConstExpr* c,
                            const NameExpr* v2, int i)
	{
	int nv2 = FrameSlot(v2);
	auto z = ZInstI(op, Frame1Slot(v1, op), nv2, i, c);
	z.op_type = OP_VVVC_I3;
	return z;
	}

} // zeek::detail
