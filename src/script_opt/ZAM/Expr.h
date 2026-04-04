// See the file "COPYING" in the main distribution directory for copyright.

// Methods for ZAM compilation of expression AST nodes (Expr's).
//
// This file is included by Compile.h to insert into the ZAMCompiler class.

ZAMStmt CompileExpr(const ExprPtr& e) { return CompileExpr(e.get()); }
ZAMStmt CompileExpr(const Expr* body);

ZAMStmt CompileIncrExpr(const IncrExpr* e);
ZAMStmt CompileAppendToExpr(const AppendToExpr* e);
ZAMStmt CompileAdd(const AggrAddExpr* e);
ZAMStmt CompileDel(const AggrDelExpr* e);
ZAMStmt CompileAddToExpr(const AddToExpr* e);
ZAMStmt CompileRemoveFromExpr(const RemoveFromExpr* e);
ZAMStmt CompileAssignExpr(const AssignExpr* e);
ZAMStmt CompileRecFieldUpdates(const RecordFieldUpdatesExpr* e);
ZAMStmt CompileZAMBuiltin(const NameExpr* lhs, const ScriptOptBuiltinExpr* zbi);
ZAMStmt CompileAssignToIndex(const NameExpr* lhs, const IndexExpr* rhs);
ZAMStmt CompileFieldLHSAssignExpr(const FieldLHSAssignExpr* e);
ZAMStmt CompileScheduleExpr(const ScheduleExpr* e);
ZAMStmt CompileSchedule(const NameExpr* n, const ConstExpr* c, int is_interval, EventHandler* h, const ListExpr* l);
ZAMStmt CompileEvent(EventHandler* h, const ListExpr* l);

ZAMStmt CompileInExpr(const NameExpr* n1, const NameExpr* n2, const NameExpr* n3) {
    return CompileInExpr(n1, n2, nullptr, n3, nullptr);
}

ZAMStmt CompileInExpr(const NameExpr* n1, const NameExpr* n2, const ConstExpr* c) {
    return CompileInExpr(n1, n2, nullptr, nullptr, c);
}

ZAMStmt CompileInExpr(const NameExpr* n1, const ConstExpr* c, const NameExpr* n3) {
    return CompileInExpr(n1, nullptr, c, n3, nullptr);
}

// In the following, one of n2 or c2 (likewise, n3/c3) will be nil.
ZAMStmt CompileInExpr(const NameExpr* n1, const NameExpr* n2, const ConstExpr* c2, const NameExpr* n3,
                      const ConstExpr* c3);

ZAMStmt CompileInExpr(const NameExpr* n1, const ListExpr* l, const NameExpr* n2) {
    return CompileInExpr(n1, l, n2, nullptr);
}

ZAMStmt CompileInExpr(const NameExpr* n, const ListExpr* l, const ConstExpr* c) {
    return CompileInExpr(n, l, nullptr, c);
}

ZAMStmt CompileInExpr(const NameExpr* n1, const ListExpr* l, const NameExpr* n2, const ConstExpr* c);

ZAMStmt CompileIndex(const NameExpr* n1, const NameExpr* n2, const ListExpr* l, bool in_when);
ZAMStmt CompileIndex(const NameExpr* n1, const ConstExpr* c, const ListExpr* l, bool in_when);
ZAMStmt CompileIndex(const NameExpr* n1, int n2_slot, const TypePtr& n2_type, const ListExpr* l, bool in_when);

ZAMStmt BuildLambda(const NameExpr* n, ExprPtr le);
ZAMStmt BuildLambda(int n_slot, ExprPtr le);

ZAMStmt AssignVecElems(const Expr* e);
ZAMStmt AssignTableElem(const Expr* e);

ZAMStmt Call(const ExprStmt* e);
ZAMStmt AssignToCall(const ExprStmt* e);
bool CheckForBuiltIn(const ExprPtr& e, CallExprPtr c);
ZAMStmt DoCall(const CallExpr* c, const NameExpr* n);

ZAMStmt ConstructTable(const NameExpr* n, const Expr* e);
ZAMStmt ConstructSet(const NameExpr* n, const Expr* e);
ZAMStmt ConstructRecord(const NameExpr* n, const Expr* e) { return ConstructRecord(n, e, false); }
ZAMStmt ConstructRecordFromRecord(const NameExpr* n, const Expr* e) { return ConstructRecord(n, e, true); }
ZAMStmt ConstructRecord(const NameExpr* n, const Expr* e, bool is_from_rec);
ZAMStmt ConstructVector(const NameExpr* n, const Expr* e);

ZAMStmt ArithCoerce(const NameExpr* n, const Expr* e);
ZAMStmt RecordCoerce(const NameExpr* n, const Expr* e);
ZAMStmt TableCoerce(const NameExpr* n, const Expr* e);
ZAMStmt VectorCoerce(const NameExpr* n, const Expr* e);

ZAMStmt Is(const NameExpr* n, const Expr* e);
