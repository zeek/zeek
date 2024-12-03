// See the file "COPYING" in the main distribution directory for copyright.

// Methods for ZAM compilation of statement AST nodes (Stmt's).
//
// This file is included by Compile.h to insert into the ZAMCompiler class.

// Note, we first list the AST nodes and then the helper functions, though
// in the definitions source these are intermingled.
const ZAMStmt CompileStmt(const StmtPtr& body) { return CompileStmt(body.get()); }
const ZAMStmt CompileStmt(const Stmt* body);

const ZAMStmt CompilePrint(const PrintStmt* ps);
const ZAMStmt CompileExpr(const ExprStmt* es);
const ZAMStmt CompileIf(const IfStmt* is);
const ZAMStmt CompileSwitch(const SwitchStmt* sw);
const ZAMStmt CompileWhile(const WhileStmt* ws);
const ZAMStmt CompileFor(const ForStmt* f);
const ZAMStmt CompileReturn(const ReturnStmt* r);
const ZAMStmt CompileCatchReturn(const CatchReturnStmt* cr);
const ZAMStmt CompileStmts(const StmtList* sl);
const ZAMStmt CompileInit(const InitStmt* is);
const ZAMStmt CompileWhen(const WhenStmt* ws);
const ZAMStmt CompileAssert(const AssertStmt* ws);

const ZAMStmt CompileNext() { return GenGoTo(nexts.back()); }
const ZAMStmt CompileBreak() { return GenGoTo(breaks.back()); }
const ZAMStmt CompileFallThrough() { return GenGoTo(fallthroughs.back()); }
const ZAMStmt CompileCatchReturn() { return GenGoTo(catches.back()); }

const ZAMStmt IfElse(const Expr* e, const Stmt* s1, const Stmt* s2);
// Second argument is which instruction slot holds the branch target.
const ZAMStmt GenCond(const Expr* e, int& branch_v);

const ZAMStmt While(const Stmt* cond_stmt, const Expr* cond, const Stmt* body);

const ZAMStmt ValueSwitch(const SwitchStmt* sw, const NameExpr* v, const ConstExpr* c);
const ZAMStmt TypeSwitch(const SwitchStmt* sw, const NameExpr* v, const ConstExpr* c);
const ZAMStmt GenSwitch(const SwitchStmt* sw, int slot, InternalTypeTag it);

const ZAMStmt LoopOverTable(const ForStmt* f, const NameExpr* val);
const ZAMStmt LoopOverVector(const ForStmt* f, const NameExpr* val);
const ZAMStmt LoopOverString(const ForStmt* f, const Expr* e);

const ZAMStmt Loop(const Stmt* body);
const ZAMStmt FinishLoop(const ZAMStmt iter_head, ZInstI& iter_stmt, const Stmt* body, int iter_slot, bool is_table);

const ZAMStmt InitRecord(IDPtr id, RecordType* rt);
const ZAMStmt InitVector(IDPtr id, VectorType* vt);
const ZAMStmt InitTable(IDPtr id, TableType* tt, Attributes* attrs);
