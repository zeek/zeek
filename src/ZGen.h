// See the file "COPYING" in the main distribution directory for copyright.

// Helper functions for generating ZAM code.

extern ZInstI GenInst(ZAM* m, ZOp op);
extern ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v1);
extern ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v1, int i);
extern ZInstI GenInst(ZAM* m, ZOp op, const ConstExpr* c, const NameExpr* v1,
			int i);
extern ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2);
extern ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2,
			const NameExpr* v3);
extern ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2,
			const NameExpr* v3, const NameExpr* v4);
extern ZInstI GenInst(ZAM* m, ZOp op, const ConstExpr* ce);
extern ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v1, const ConstExpr* ce);
extern ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v1, const ConstExpr* ce,
			const NameExpr* v2);
extern ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2,
			const ConstExpr* ce);
extern ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2,
			const NameExpr* v3, const ConstExpr* ce);
extern ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2,
			const ConstExpr* ce, const NameExpr* v3);
extern ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v1, const ConstExpr* c,
			int i);
extern ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2,
			int i);
extern ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2,
			int i1, int i2);
extern ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v, const ConstExpr* c,
			int i1, int i2);
extern ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2,
			const NameExpr* v3, int i);
extern ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v1, const NameExpr* v2,
			const ConstExpr* c, int i);
extern ZInstI GenInst(ZAM* m, ZOp op, const NameExpr* v1, const ConstExpr* c,
			const NameExpr* v2, int i);
