// See the file "COPYING" in the main distribution directory for copyright.

// Methods for ZAM compilation of expression AST nodes (Expr's).
//
// This file is included by Compile.h to insert into the ZAMCompiler class.

const ZAMStmt CompileExpr(const ExprPtr& e) { return CompileExpr(e.get()); }
const ZAMStmt CompileExpr(const Expr* body);

const ZAMStmt CompileIncrExpr(const IncrExpr* e);
const ZAMStmt CompileAppendToExpr(const AppendToExpr* e);
const ZAMStmt CompileAdd(const AggrAddExpr* e);
const ZAMStmt CompileDel(const AggrDelExpr* e);
const ZAMStmt CompileAddToExpr(const AddToExpr* e);
const ZAMStmt CompileRemoveFromExpr(const RemoveFromExpr* e);
const ZAMStmt CompileAssignExpr(const AssignExpr* e);
const ZAMStmt CompileRecFieldUpdates(const RecordFieldUpdatesExpr* e);
const ZAMStmt CompileZAMBuiltin(const NameExpr* lhs, const ScriptOptBuiltinExpr* zbi);
const ZAMStmt CompileAssignToIndex(const NameExpr* lhs, const IndexExpr* rhs);
const ZAMStmt CompileFieldLHSAssignExpr(const FieldLHSAssignExpr* e);
const ZAMStmt CompileScheduleExpr(const ScheduleExpr* e);
const ZAMStmt CompileSchedule(const NameExpr* n, const ConstExpr* c, int is_interval, EventHandler* h,
                              const ListExpr* l);
const ZAMStmt CompileEvent(EventHandler* h, const ListExpr* l);

const ZAMStmt CompileInExpr(const NameExpr* n1, const NameExpr* n2, const NameExpr* n3) {
    return CompileInExpr(n1, n2, nullptr, n3, nullptr);
}

const ZAMStmt CompileInExpr(const NameExpr* n1, const NameExpr* n2, const ConstExpr* c) {
    return CompileInExpr(n1, n2, nullptr, nullptr, c);
}

const ZAMStmt CompileInExpr(const NameExpr* n1, const ConstExpr* c, const NameExpr* n3) {
    return CompileInExpr(n1, nullptr, c, n3, nullptr);
}

// In the following, one of n2 or c2 (likewise, n3/c3) will be nil.
const ZAMStmt CompileInExpr(const NameExpr* n1, const NameExpr* n2, const ConstExpr* c2, const NameExpr* n3,
                            const ConstExpr* c3);

const ZAMStmt CompileInExpr(const NameExpr* n1, const ListExpr* l, const NameExpr* n2) {
    return CompileInExpr(n1, l, n2, nullptr);
}

const ZAMStmt CompileInExpr(const NameExpr* n, const ListExpr* l, const ConstExpr* c) {
    return CompileInExpr(n, l, nullptr, c);
}

const ZAMStmt CompileInExpr(const NameExpr* n1, const ListExpr* l, const NameExpr* n2, const ConstExpr* c);

const ZAMStmt CompileIndex(const NameExpr* n1, const NameExpr* n2, const ListExpr* l, bool in_when);
const ZAMStmt CompileIndex(const NameExpr* n1, const ConstExpr* c, const ListExpr* l, bool in_when);
const ZAMStmt CompileIndex(const NameExpr* n1, int n2_slot, const TypePtr& n2_type, const ListExpr* l, bool in_when);

const ZAMStmt BuildLambda(const NameExpr* n, ExprPtr le);
const ZAMStmt BuildLambda(int n_slot, ExprPtr le);

const ZAMStmt AssignVecElems(const Expr* e);
const ZAMStmt AssignTableElem(const Expr* e);

const ZAMStmt Call(const ExprStmt* e);
const ZAMStmt AssignToCall(const ExprStmt* e);
bool CheckForBuiltIn(const ExprPtr& e, CallExprPtr c);
const ZAMStmt DoCall(const CallExpr* c, const NameExpr* n);

const ZAMStmt ConstructTable(const NameExpr* n, const Expr* e);
const ZAMStmt ConstructSet(const NameExpr* n, const Expr* e);
const ZAMStmt ConstructRecord(const NameExpr* n, const Expr* e) { return ConstructRecord(n, e, false); }
const ZAMStmt ConstructRecordFromRecord(const NameExpr* n, const Expr* e) { return ConstructRecord(n, e, true); }
const ZAMStmt ConstructRecord(const NameExpr* n, const Expr* e, bool is_from_rec);
const ZAMStmt ConstructVector(const NameExpr* n, const Expr* e);

const ZAMStmt ArithCoerce(const NameExpr* n, const Expr* e);
const ZAMStmt RecordCoerce(const NameExpr* n, const Expr* e);
const ZAMStmt TableCoerce(const NameExpr* n, const Expr* e);
const ZAMStmt VectorCoerce(const NameExpr* n, const Expr* e);

const ZAMStmt Is(const NameExpr* n, const Expr* e);
