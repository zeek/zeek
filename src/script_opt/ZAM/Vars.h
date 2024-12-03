// See the file "COPYING" in the main distribution directory for copyright.

// Methods for managing Zeek function variables.
//
// This file is included by Compile.h to insert into the ZAMCompiler class.

bool IsUnused(const IDPtr& id, const Stmt* where) const;

bool IsCapture(const IDPtr& id) const { return IsCapture(id.get()); }
bool IsCapture(const ID* id) const;

int CaptureOffset(const IDPtr& id) const { return IsCapture(id.get()); }
int CaptureOffset(const ID* id) const;

void LoadParam(const ID* id);
const ZAMStmt LoadGlobal(const ID* id);
const ZAMStmt LoadCapture(const ID* id);

int AddToFrame(const ID*);

int FrameSlot(const IDPtr& id) { return FrameSlot(id.get()); }
int FrameSlot(const ID* id);
int FrameSlotIfName(const Expr* e) {
    auto n = e->Tag() == EXPR_NAME ? e->AsNameExpr() : nullptr;
    return n ? FrameSlot(n->Id()) : -1;
}

int FrameSlot(const NameExpr* n) { return FrameSlot(n->Id()); }
int Frame1Slot(const NameExpr* n, ZOp op) { return Frame1Slot(n->Id(), op); }

int Frame1Slot(const ID* id, ZOp op) { return Frame1Slot(id, op1_flavor[op]); }
int Frame1Slot(const NameExpr* n, ZAMOp1Flavor fl) { return Frame1Slot(n->Id(), fl); }
int Frame1Slot(const ID* id, ZAMOp1Flavor fl);

// The slot without doing any global-related checking.
int RawSlot(const NameExpr* n) { return RawSlot(n->Id()); }
int RawSlot(const ID* id);

bool HasFrameSlot(const ID* id) const;

int NewSlot(const TypePtr& t) { return NewSlot(ZVal::IsManagedType(t)); }
int NewSlot(bool is_managed);

int TempForConst(const ConstExpr* c);
