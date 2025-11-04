// See the file "COPYING" in the main distribution directory for copyright.

// Methods for ZAM compilation of statement AST nodes (Stmt's).
//
// This file is included by Compile.h to insert into the ZAMCompiler class.

// Note, we first list the AST nodes and then the helper functions, though
// in the definitions source these are intermingled.
ZAMStmt CompileStmt(const StmtPtr& body) { return CompileStmt(body.get()); }
ZAMStmt CompileStmt(const Stmt* body);

ZAMStmt CompilePrint(const PrintStmt* ps);
ZAMStmt CompileExpr(const ExprStmt* es);
ZAMStmt CompileIf(const IfStmt* is);
ZAMStmt CompileSwitch(const SwitchStmt* sw);
ZAMStmt CompileWhile(const WhileStmt* ws);
ZAMStmt CompileFor(const ForStmt* f);
ZAMStmt CompileReturn(const ReturnStmt* r);
ZAMStmt CompileCatchReturn(const CatchReturnStmt* cr);
ZAMStmt CompileStmts(const StmtList* sl);
ZAMStmt CompileInit(const InitStmt* is);
ZAMStmt CompileWhen(const WhenStmt* ws);
ZAMStmt CompileAssert(const AssertStmt* ws);

ZAMStmt CompileNext() { return GenGoTo(nexts.back()); }
ZAMStmt CompileBreak() { return GenGoTo(breaks.back()); }
ZAMStmt CompileFallThrough() { return GenGoTo(fallthroughs.back()); }
ZAMStmt CompileCatchReturn() { return GenGoTo(catches.back()); }

ZAMStmt IfElse(const Expr* e, const Stmt* s1, const Stmt* s2);
// Second argument is which instruction slot holds the branch target.
ZAMStmt GenCond(const Expr* e, int& branch_v);

ZAMStmt While(const Stmt* cond_stmt, const Expr* cond, const Stmt* body);

ZAMStmt ValueSwitch(const SwitchStmt* sw, const NameExpr* v, const ConstExpr* c);
ZAMStmt TypeSwitch(const SwitchStmt* sw, const NameExpr* v, const ConstExpr* c);
ZAMStmt GenSwitch(const SwitchStmt* sw, int slot, InternalTypeTag it);

ZAMStmt LoopOverTable(const ForStmt* f, const NameExpr* val);
ZAMStmt LoopOverVector(const ForStmt* f, const NameExpr* val);
ZAMStmt LoopOverString(const ForStmt* f, const Expr* e);

ZAMStmt Loop(const Stmt* body);
ZAMStmt FinishLoop(ZAMStmt iter_head, ZInstI& iter_stmt, const Stmt* body, int iter_slot, bool is_table);

ZAMStmt InitRecord(IDPtr id, RecordType* rt);
ZAMStmt InitVector(IDPtr id, VectorType* vt);
ZAMStmt InitTable(IDPtr id, TableType* tt, Attributes* attrs);
