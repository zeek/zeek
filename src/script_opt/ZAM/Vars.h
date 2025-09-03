// See the file "COPYING" in the main distribution directory for copyright.

// Methods for managing Zeek function variables.
//
// This file is included by Compile.h to insert into the ZAMCompiler class.

bool IsUnused(const IDPtr& id, const Stmt* where) const;

bool IsCapture(const IDPtr& id) const;
int CaptureOffset(const IDPtr& id) const;

void LoadParam(const IDPtr& id);
const ZAMStmt LoadGlobal(const IDPtr& id);
const ZAMStmt LoadCapture(const IDPtr& id);

int AddToFrame(const IDPtr&);

int FrameSlot(const IDPtr& id);
int FrameSlotIfName(const Expr* e) {
    auto n = e->Tag() == EXPR_NAME ? e->AsNameExpr() : nullptr;
    return n ? FrameSlot(n->IdPtr()) : -1;
}

int FrameSlot(const NameExpr* n) { return FrameSlot(n->IdPtr()); }
int Frame1Slot(const NameExpr* n, ZOp op) { return Frame1Slot(n->IdPtr(), op); }

int Frame1Slot(const IDPtr& id, ZOp op) { return Frame1Slot(id, op1_flavor[op]); }
int Frame1Slot(const NameExpr* n, ZAMOp1Flavor fl) { return Frame1Slot(n->IdPtr(), fl); }
int Frame1Slot(const IDPtr& id, ZAMOp1Flavor fl);

// The slot without doing any global-related checking.
int RawSlot(const NameExpr* n) { return RawSlot(n->IdPtr()); }
int RawSlot(const IDPtr& id);

bool HasFrameSlot(const IDPtr& id) const;

int NewSlot(const TypePtr& t) { return NewSlot(ZVal::IsManagedType(t)); }
int NewSlot(bool is_managed);

int TempForConst(const ConstExpr* c);
