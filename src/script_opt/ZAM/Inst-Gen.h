// See the file "COPYING" in the main distribution directory for copyright.

// Methods for generating ZAM instructions, mainly to aid in translating
// NameExpr*'s to slots.  Some aren't needed, but we provide a complete
// set mirroring the ZInstI constructors for consistency.
//
// Maintained separately from Compile.h to make it conceptually simple to
// add new helpers.

ZInstI GenInst(ZOp op);
ZInstI GenInst(ZOp op, const NameExpr* v1);
ZInstI GenInst(ZOp op, const NameExpr* v1, int i);
ZInstI GenInst(ZOp op, const ConstExpr* c, const NameExpr* v1, int i);
ZInstI GenInst(ZOp op, const NameExpr* v1, const NameExpr* v2);
ZInstI GenInst(ZOp op, const NameExpr* v1, const NameExpr* v2,
               const NameExpr* v3);
ZInstI GenInst(ZOp op, const NameExpr* v1, const NameExpr* v2,
               const NameExpr* v3, const NameExpr* v4);
ZInstI GenInst(ZOp op, const ConstExpr* ce);
ZInstI GenInst(ZOp op, const NameExpr* v1, const ConstExpr* ce);
ZInstI GenInst(ZOp op, const ConstExpr* ce, const NameExpr* v1);
ZInstI GenInst(ZOp op, const NameExpr* v1, const ConstExpr* ce,
               const NameExpr* v2);
ZInstI GenInst(ZOp op, const NameExpr* v1, const NameExpr* v2,
               const ConstExpr* ce);
ZInstI GenInst(ZOp op, const NameExpr* v1, const NameExpr* v2,
               const NameExpr* v3, const ConstExpr* ce);
ZInstI GenInst(ZOp op, const NameExpr* v1, const NameExpr* v2,
               const ConstExpr* ce, const NameExpr* v3);
ZInstI GenInst(ZOp op, const NameExpr* v1, const ConstExpr* c, int i);
ZInstI GenInst(ZOp op, const NameExpr* v1, const NameExpr* v2, int i);
ZInstI GenInst(ZOp op, const NameExpr* v1, const NameExpr* v2, int i1, int i2);
ZInstI GenInst(ZOp op, const NameExpr* v, const ConstExpr* c, int i1, int i2);
ZInstI GenInst(ZOp op, const NameExpr* v1, const NameExpr* v2,
               const NameExpr* v3, int i);
ZInstI GenInst(ZOp op, const NameExpr* v1, const NameExpr* v2,
               const ConstExpr* c, int i);
ZInstI GenInst(ZOp op, const NameExpr* v1, const ConstExpr* c,
               const NameExpr* v2, int i);
