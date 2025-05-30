// See the file "COPYING" in the main distribution directory for copyright.

// Methods for low-level manipulation of ZAM instructions/statements.
//
// This file is included by Compile.h to insert into the ZAMCompiler class.

const ZAMStmt StartingBlock();
const ZAMStmt FinishBlock(const ZAMStmt start);

bool NullStmtOK() const;

const ZAMStmt EmptyStmt();
const ZAMStmt ErrorStmt();
const ZAMStmt LastInst();

// Adds control flow information to an instruction.
void AddCFT(ZInstI* inst, ControlFlowType cft);

// Returns a handle to state associated with building
// up a list of values.
std::unique_ptr<OpaqueVals> BuildVals(const ListExprPtr&);

// "stride" is how many slots each element of l will consume.
ZInstAux* InternalBuildVals(const ListExpr* l, int stride = 1);

// Returns how many values were added.
int InternalAddVal(ZInstAux* zi, int i, Expr* e);

// Adds the given instruction to the ZAM program.  The second
// argument, if true, suppresses generation of any pending
// global/capture store for this instruction.
const ZAMStmt AddInst(const ZInstI& inst, bool suppress_non_local = false);

// Returns the last (interpreter) statement in the body.
const Stmt* LastStmt(const Stmt* s) const;

// Returns the most recent added instruction *other* than those
// added for bookkeeping.
ZInstI* TopMainInst() { return insts1[top_main_inst]; }
