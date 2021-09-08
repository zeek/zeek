// See the file "COPYING" in the main distribution directory for copyright.

// ZAM: Zeek Abstract Machine compiler.

#pragma once

#include "zeek/Event.h"
#include "zeek/script_opt/UseDefs.h"
#include "zeek/script_opt/ZAM/ZBody.h"

namespace zeek {
class EventHandler;
}

namespace zeek::detail {

class NameExpr;
class ConstExpr;
class FieldExpr;
class ListExpr;

class Stmt;
class SwitchStmt;
class CatchReturnStmt;

class ProfileFunc;

using InstLabel = ZInstI*;

// Class representing a single compiled statement.  (This is different from,
// but related to, the ZAM instruction(s) generated for that compilation.)
// Designed to be fully opaque, but also effective without requiring pointer
// management.
class ZAMStmt {
protected:
	friend class ZAMCompiler;

	ZAMStmt()	{ stmt_num = -1; /* flag that it needs to be set */ }
	ZAMStmt(int _stmt_num)	{ stmt_num = _stmt_num; }

	int stmt_num;
};

// Class that holds values that only have meaning to the ZAM compiler,
// but that needs to be held (opaquely, via a pointer) by external
// objects.
class OpaqueVals {
public:
	OpaqueVals(ZInstAux* _aux)	{ aux = _aux; }

	ZInstAux* aux;
};

class ZAMCompiler {
public:
	ZAMCompiler(ScriptFunc* f, std::shared_ptr<ProfileFunc> pf,
	            ScopePtr scope, StmtPtr body, std::shared_ptr<UseDefs> ud,
	            std::shared_ptr<Reducer> rd);

	StmtPtr CompileBody();

	const FrameReMap& FrameDenizens() const
		{ return shared_frame_denizens_final; }

	const std::vector<int>& ManagedSlots() const
		{ return managed_slotsI; }

	const std::vector<GlobalInfo>& Globals() const
		{ return globalsI; }

	bool NonRecursive() const	{ return non_recursive; }

	const TableIterVec& GetTableIters() const	{ return table_iters; }
	int NumStepIters() const	{ return num_step_iters; }

	template <typename T>
	const CaseMaps<T>& GetCases() const
		{
		if constexpr ( std::is_same_v<T, bro_int_t> )
			return int_cases;
		else if constexpr ( std::is_same_v<T, bro_uint_t> )
			return uint_cases;
		else if constexpr ( std::is_same_v<T, double> )
			return double_cases;
		else if constexpr ( std::is_same_v<T, std::string> )
			return str_cases;
		}

	void Dump();

private:
	void Init();
	void InitGlobals();
	void InitArgs();
	void InitLocals();
	void TrackMemoryManagement();

	void ResolveHookBreaks();
	void ComputeLoopLevels();
	void AdjustBranches();
	void RetargetBranches();
	void RemapFrameDenizens(const std::vector<int>& inst1_to_inst2);
	void CreateSharedFrameDenizens();
	void ConcretizeSwitches();

	// The following are used for switch statements, mapping the
	// switch value (which can be any atomic type) to a branch target.
	// We have vectors of them because functions can contain multiple
	// switches.
	// See ZBody.h for their concrete counterparts, which we've
	// already #include'd.
	template<typename T> using CaseMapI = std::map<T, InstLabel>;
	template<typename T> using CaseMapsI = std::vector<CaseMapI<T>>;

	template <typename T>
	void ConcretizeSwitchTables(const CaseMapsI<T>& abstract_cases,
	                            CaseMaps<T>& concrete_cases);

	template <typename T>
	void DumpCases(const T& cases, const char* type_name) const;
	void DumpInsts1(const FrameReMap* remappings);

#include "zeek/ZAM-MethodDecls.h"

	const ZAMStmt CompileStmt(const StmtPtr& body)
		{ return CompileStmt(body.get()); }
	const ZAMStmt CompileStmt(const Stmt* body);

	void SetCurrStmt(const Stmt* stmt)	{ curr_stmt = stmt; }

	const ZAMStmt CompilePrint(const PrintStmt* ps);
	const ZAMStmt CompileExpr(const ExprStmt* es);
	const ZAMStmt CompileIf(const IfStmt* is);
	const ZAMStmt CompileSwitch(const SwitchStmt* sw);
	const ZAMStmt CompileAdd(const AddStmt* as);
	const ZAMStmt CompileDel(const DelStmt* ds);
	const ZAMStmt CompileWhile(const WhileStmt* ws);
	const ZAMStmt CompileFor(const ForStmt* f);
	const ZAMStmt CompileReturn(const ReturnStmt* r);
	const ZAMStmt CompileCatchReturn(const CatchReturnStmt* cr);
	const ZAMStmt CompileStmts(const StmtList* sl);
	const ZAMStmt CompileInit(const InitStmt* is);
	const ZAMStmt CompileWhen(const WhenStmt* ws);

	const ZAMStmt CompileNext()
		{ return GenGoTo(nexts.back()); }
	const ZAMStmt CompileBreak()
		{ return GenGoTo(breaks.back()); }
	const ZAMStmt CompileFallThrough()
		{ return GenGoTo(fallthroughs.back()); }
	const ZAMStmt CompileCatchReturn()
		{ return GenGoTo(catches.back()); }

	const ZAMStmt IfElse(const Expr* e, const Stmt* s1, const Stmt* s2);
	const ZAMStmt While(const Stmt* cond_stmt, const Expr* cond,
	                    const Stmt* body);

	const ZAMStmt InitRecord(IDPtr id, RecordType* rt);
	const ZAMStmt InitVector(IDPtr id, VectorType* vt);
	const ZAMStmt InitTable(IDPtr id, TableType* tt, Attributes* attrs);

	const ZAMStmt ValueSwitch(const SwitchStmt* sw, const NameExpr* v,
	                          const ConstExpr* c);
	const ZAMStmt TypeSwitch(const SwitchStmt* sw, const NameExpr* v,
	                         const ConstExpr* c);

	void PushNexts()		{ PushGoTos(nexts); }
	void PushBreaks()		{ PushGoTos(breaks); }
	void PushFallThroughs()		{ PushGoTos(fallthroughs); }
	void PushCatchReturns()		{ PushGoTos(catches); }

	void ResolveNexts(const InstLabel l)
		{ ResolveGoTos(nexts, l); }
	void ResolveBreaks(const InstLabel l)
		{ ResolveGoTos(breaks, l); }
	void ResolveFallThroughs(const InstLabel l)
		{ ResolveGoTos(fallthroughs, l); }
	void ResolveCatchReturns(const InstLabel l)
		{ ResolveGoTos(catches, l); }


	const ZAMStmt LoopOverTable(const ForStmt* f, const NameExpr* val);
	const ZAMStmt LoopOverVector(const ForStmt* f, const NameExpr* val);
	const ZAMStmt LoopOverString(const ForStmt* f, const Expr* e);

	const ZAMStmt FinishLoop(const ZAMStmt iter_head, ZInstI iter_stmt,
	                         const Stmt* body, int iter_slot,
	                         bool is_table);

	const ZAMStmt Loop(const Stmt* body);


	const ZAMStmt CompileExpr(const ExprPtr& e)
		{ return CompileExpr(e.get()); }
	const ZAMStmt CompileExpr(const Expr* body);

	const ZAMStmt CompileIncrExpr(const IncrExpr* e);
	const ZAMStmt CompileAppendToExpr(const AppendToExpr* e);
	const ZAMStmt CompileAssignExpr(const AssignExpr* e);
	const ZAMStmt CompileAssignToIndex(const NameExpr* lhs,
	                                   const IndexExpr* rhs);
	const ZAMStmt CompileFieldLHSAssignExpr(const FieldLHSAssignExpr* e);
	const ZAMStmt CompileScheduleExpr(const ScheduleExpr* e);
	const ZAMStmt CompileSchedule(const NameExpr* n, const ConstExpr* c,
	                              int is_interval, EventHandler* h,
	                              const ListExpr* l);
	const ZAMStmt CompileEvent(EventHandler* h, const ListExpr* l);

	const ZAMStmt CompileInExpr(const NameExpr* n1, const NameExpr* n2,
	                            const NameExpr* n3)
		{ return CompileInExpr(n1, n2, nullptr, n3, nullptr); }

	const ZAMStmt CompileInExpr(const NameExpr* n1, const NameExpr* n2,
	                            const ConstExpr* c)
		{ return CompileInExpr(n1, n2, nullptr, nullptr, c); }

	const ZAMStmt CompileInExpr(const NameExpr* n1, const ConstExpr* c,
	                            const NameExpr* n3)
		{ return CompileInExpr(n1, nullptr, c, n3, nullptr); }

	// In the following, one of n2 or c2 (likewise, n3/c3) will be nil.
	const ZAMStmt CompileInExpr(const NameExpr* n1, const NameExpr* n2,
	                            const ConstExpr* c2, const NameExpr* n3,
	                            const ConstExpr* c3);

	const ZAMStmt CompileInExpr(const NameExpr* n1, const ListExpr* l,
	                            const NameExpr* n2)
		{ return CompileInExpr(n1, l, n2, nullptr); }

	const ZAMStmt CompileInExpr(const NameExpr* n, const ListExpr* l,
	                            const ConstExpr* c)
		{ return CompileInExpr(n, l, nullptr, c); }

	const ZAMStmt CompileInExpr(const NameExpr* n1, const ListExpr* l,
	                            const NameExpr* n2, const ConstExpr* c);


	const ZAMStmt CompileIndex(const NameExpr* n1, const NameExpr* n2,
	                           const ListExpr* l);
	const ZAMStmt CompileIndex(const NameExpr* n1, const ConstExpr* c,
	                           const ListExpr* l);
	const ZAMStmt CompileIndex(const NameExpr* n1, int n2_slot,
	                           const TypePtr& n2_type, const ListExpr* l);

	// Second argument is which instruction slot holds the branch target.
	const ZAMStmt GenCond(const Expr* e, int& branch_v);

	const ZAMStmt Call(const ExprStmt* e);
	const ZAMStmt AssignToCall(const ExprStmt* e);
	const ZAMStmt DoCall(const CallExpr* c, const NameExpr* n);

	const ZAMStmt AssignVecElems(const Expr* e);
	const ZAMStmt AssignTableElem(const Expr* e);

	const ZAMStmt AppendToField(const NameExpr* n1, const NameExpr* n2,
	                            const ConstExpr* c, int offset);

	const ZAMStmt ConstructTable(const NameExpr* n, const Expr* e);
	const ZAMStmt ConstructSet(const NameExpr* n, const Expr* e);
	const ZAMStmt ConstructRecord(const NameExpr* n, const Expr* e);
	const ZAMStmt ConstructVector(const NameExpr* n, const Expr* e);

	const ZAMStmt ArithCoerce(const NameExpr* n, const Expr* e);
	const ZAMStmt RecordCoerce(const NameExpr* n, const Expr* e);
	const ZAMStmt TableCoerce(const NameExpr* n, const Expr* e);
	const ZAMStmt VectorCoerce(const NameExpr* n, const Expr* e);

	const ZAMStmt Is(const NameExpr* n, const Expr* e);


#include "zeek/script_opt/ZAM/Inst-Gen.h"
#include "zeek/script_opt/ZAM/BuiltIn.h"

	// A bit weird, but handy for switch statements used in built-in
	// operations: returns a bit mask of which of the arguments in the
	// given list correspond to constants, with the high-ordered bit
	// being the first argument (argument "0" in the list) and the
	// low-ordered bit being the last.  Second parameter is the number
	// of arguments that should be present.
	bro_uint_t ConstArgsMask(const ExprPList& args, int nargs) const;

	int ConvertToInt(const Expr* e)
		{
		if ( e->Tag() == EXPR_NAME )
			return FrameSlot(e->AsNameExpr()->Id());
		else
			return e->AsConstExpr()->Value()->AsInt();
		}

	int ConvertToCount(const Expr* e)
		{
		if ( e->Tag() == EXPR_NAME )
			return FrameSlot(e->AsNameExpr()->Id());
		else
			return e->AsConstExpr()->Value()->AsCount();
		}


	using GoToSet = std::vector<ZAMStmt>;
	using GoToSets = std::vector<GoToSet>;

	void PushGoTos(GoToSets& gotos);
	void ResolveGoTos(GoToSets& gotos, const InstLabel l);

	ZAMStmt GenGoTo(GoToSet& v);
	ZAMStmt GoToStub();
	ZAMStmt GoTo(const InstLabel l);
	InstLabel GoToTarget(const ZAMStmt s);
	InstLabel GoToTargetBeyond(const ZAMStmt s);

	void SetTarget(ZInstI* inst, const InstLabel l, int slot);

	// Given a GoTo target, find its live equivalent (first instruction
	// at that location or beyond that's live).
	ZInstI* FindLiveTarget(ZInstI* goto_target);

	// Given an instruction that has a slot associated with the
	// given target, updates the slot to correspond with the current
	// instruction number of the target.
	void ConcretizeBranch(ZInstI* inst, ZInstI* target, int target_slot);

	void SetV(ZAMStmt s, const InstLabel l, int v)
		{
		if ( v == 1 )
			SetV1(s, l);
		else if ( v == 2 )
			SetV2(s, l);
		else if ( v == 3 )
			SetV3(s, l);
		else
			SetV4(s, l);
		}

	void SetV1(ZAMStmt s, const InstLabel l);
	void SetV2(ZAMStmt s, const InstLabel l);
	void SetV3(ZAMStmt s, const InstLabel l);
	void SetV4(ZAMStmt s, const InstLabel l);
	void SetGoTo(ZAMStmt s, const InstLabel targ)
		{ SetV1(s, targ); }


	const ZAMStmt StartingBlock();
	const ZAMStmt FinishBlock(const ZAMStmt start);

	bool NullStmtOK() const;

	const ZAMStmt EmptyStmt();
	const ZAMStmt ErrorStmt();
	const ZAMStmt LastInst();

	// Returns a handle to state associated with building
	// up a list of values.
	OpaqueVals* BuildVals(const ListExprPtr&);

	// "stride" is how many slots each element of l will consume.
	ZInstAux* InternalBuildVals(const ListExpr* l, int stride = 1);

	// Returns how many values were added.
	int InternalAddVal(ZInstAux* zi, int i, Expr* e);

	const ZAMStmt AddInst(const ZInstI& inst);

	// Returns the statement just before the given one.
	ZAMStmt PrevStmt(const ZAMStmt s);

	// Returns the last (interpreter) statement in the body.
	const Stmt* LastStmt(const Stmt* s) const;

	// Returns the most recent added instruction *other* than those
	// added for bookkeeping.
	ZInstI* TopMainInst()	{ return insts1[top_main_inst]; }


	bool IsUnused(const IDPtr& id, const Stmt* where) const;

	void LoadParam(ID* id);
	const ZAMStmt LoadGlobal(ID* id);

	int AddToFrame(ID*);

	int FrameSlot(const IDPtr& id)		{ return FrameSlot(id.get()); }
	int FrameSlot(const ID* id);
	int FrameSlotIfName(const Expr* e)
		{
		auto n = e->Tag() == EXPR_NAME ? e->AsNameExpr() : nullptr;
		return n ? FrameSlot(n->Id()) : 0;
		}

	int FrameSlot(const NameExpr* id)
		{ return FrameSlot(id->AsNameExpr()->Id()); }
	int Frame1Slot(const NameExpr* id, ZOp op)
		{ return Frame1Slot(id->AsNameExpr()->Id(), op); }

	int Frame1Slot(const ID* id, ZOp op)
		{ return Frame1Slot(id, op1_flavor[op]); }
	int Frame1Slot(const NameExpr* n, ZAMOp1Flavor fl)
		{ return Frame1Slot(n->Id(), fl); }
	int Frame1Slot(const ID* id, ZAMOp1Flavor fl);

	// The slot without doing any global-related checking.
	int RawSlot(const NameExpr* n)	{ return RawSlot(n->Id()); }
	int RawSlot(const ID* id);

	bool HasFrameSlot(const ID* id) const;

	int NewSlot(const TypePtr& t)
		{ return NewSlot(ZVal::IsManagedType(t)); }
	int NewSlot(bool is_managed);

	int TempForConst(const ConstExpr* c);

	////////////////////////////////////////////////////////////
	// The following methods relate to optimizing the low-level
	// ZAM function body after it is initially generated.  They're
	// factored out into ZOpt.cc since they're structurally quite
	// different from the methods above that relate to the initial
	// compilation.

	// Optimizing the low-level compiled instructions.
	void OptimizeInsts();

	// Tracks which instructions can be branched to via the given
	// set of switches.
	template<typename T>
	void TallySwitchTargets(const CaseMapsI<T>& switches);

	// Remove code that can't be reached.  True if some removal happened.
	bool RemoveDeadCode();

	// Collapse chains of gotos.  True if some something changed.
	bool CollapseGoTos();

	// Prune statements that are unnecessary.  True if something got
	// pruned.
	bool PruneUnused();

	// For the current state of insts1, compute lifetimes of frame
	// denizens (variable(s) using a given frame slot) in terms of
	// first-instruction-to-last-instruction during which they're
	// relevant, including consideration for loops.
	void ComputeFrameLifetimes();

	// Given final frame lifetime information, remaps frame members
	// with non-overlapping lifetimes to share slots.
	void ReMapFrame();

	// Given final frame lifetime information, remaps slots in the
	// interpreter frame.  (No longer strictly necessary.)
	void ReMapInterpreterFrame();

	// Computes the remapping for a variable currently in the given slot,
	// whose scope begins at the given instruction.
	void ReMapVar(ID* id, int slot, int inst);

	// Look to initialize the beginning of local lifetime based on slot
	// assignment at instruction inst.
	void CheckSlotAssignment(int slot, const ZInstI* inst);

	// Track that a local's lifetime begins at the given statement.
	void SetLifetimeStart(int slot, const ZInstI* inst);

	// Look for extension of local lifetime based on slot usage
	// at instruction inst.
	void CheckSlotUse(int slot, const ZInstI* inst);

	// Extend (or create) the end of a local's lifetime.
	void ExtendLifetime(int slot, const ZInstI* inst);

	// Returns the (live) instruction at the beginning/end of the loop(s)
	// within which the given instruction lies; or that instruction
	// itself if it's not inside a loop.  The second argument specifies
	// the loop depth.  For example, a value of '2' means "extend to
	// the beginning/end of any loop(s) of depth >= 2".
	const ZInstI* BeginningOfLoop(const ZInstI* inst, int depth) const;
	const ZInstI* EndOfLoop(const ZInstI* inst, int depth) const;

	// True if any statement other than a frame sync assigns to the
	// given slot.
	bool VarIsAssigned(int slot) const;

	// True if the given statement assigns to the given slot, and
	// it's not a frame sync.
	bool VarIsAssigned(int slot, const ZInstI* i) const;

	// True if any statement other than a frame sync uses the given slot.
	bool VarIsUsed(int slot) const;

	// Find the first non-dead instruction after i (inclusive).
	// If follow_gotos is true, then if that instruction is
	// an unconditional branch, continues the process until
	// a different instruction is found (and report if there
	// are infinite loops).
	//
	// First form returns nil if there's nothing live after i.
	// Second form returns insts1.size() in that case.
	ZInstI* FirstLiveInst(ZInstI* i, bool follow_gotos = false);
	int FirstLiveInst(int i, bool follow_gotos = false);

	// Same, but not including i.
	ZInstI* NextLiveInst(ZInstI* i, bool follow_gotos = false)
		{
		if ( i->inst_num == insts1.size() - 1 )
			return nullptr;
		return FirstLiveInst(insts1[i->inst_num + 1], follow_gotos);
		}
	int NextLiveInst(int i, bool follow_gotos = false)
		{ return FirstLiveInst(i + 1, follow_gotos); }

	// Mark an instruction as unnecessary and remove its influence on
	// other statements.  The instruction is indicated as an offset
	// into insts1; any labels associated with it are transferred
	// to its next live successor, if any.
	void KillInst(ZInstI* i)	{ KillInst(i->inst_num); }
	void KillInst(int i);

	// The same, but kills any successor instructions until finding
	// one that's labeled.
	void KillInsts(ZInstI* i)	{ KillInsts(i->inst_num); }
	void KillInsts(int i);

	// The first of these is used as we compile down to ZInstI's.
	// The second is the final intermediary code.  They're separate
	// to make it easy to remove dead code.
	std::vector<ZInstI*> insts1;
	std::vector<ZInstI*> insts2;

	// Used as a placeholder when we have to generate a GoTo target
	// beyond the end of what we've compiled so far.
	ZInstI* pending_inst = nullptr;

	// Indices of break/next/fallthrough/catch-return goto's, so they
	// can be patched up post-facto.  These are vectors-of-vectors
	// so that nesting works properly.
	GoToSets breaks;
	GoToSets nexts;
	GoToSets fallthroughs;
	GoToSets catches;

	// The following tracks return variables for catch-returns.
	// Can be nil if the usage doesn't include using the return value
	// (and/or no return value generated).
	std::vector<const NameExpr*> retvars;

	ScriptFunc* func;
	std::shared_ptr<ProfileFunc> pf;
	ScopePtr scope;
	StmtPtr body;
	std::shared_ptr<UseDefs> ud;
	std::shared_ptr<Reducer> reducer;

	// Maps identifiers to their (unique) frame location.
	std::unordered_map<const ID*, int> frame_layout1;

	// Inverse mapping, used for tracking frame usage (and for dumping
	// statements).
	FrameMap frame_denizens;

	// The same, but for remapping identifiers to shared frame slots.
	FrameReMap shared_frame_denizens;

	// The same, but renumbered to take into account removal of
	// dead statements.
	FrameReMap shared_frame_denizens_final;

	// Maps frame1 slots to frame2 slots.  A value < 0 means the
	// variable doesn't exist in frame2 - it's an error to encounter
	// one of these when remapping instructions!
	std::vector<int> frame1_to_frame2;

	// A type for mapping an instruction to a set of locals associated
	// with it.
	using AssociatedLocals =
	      std::unordered_map<const ZInstI*, std::unordered_set<ID*>>;

	// Maps (live) instructions to which frame denizens begin their
	// lifetime via an initialization at that instruction, if any ...
	// (it can be more than one local due to extending lifetimes to
	// span loop bodies)
	AssociatedLocals inst_beginnings;

	// ... and which frame denizens had their last usage at the
	// given instruction.  (These are insts1 instructions, prior to
	// removing dead instructions, compressing the frames, etc.)
	AssociatedLocals inst_endings;

	// A type for inverse mappings.
	using AssociatedInsts = std::unordered_map<int, const ZInstI*>;

	// Inverse mappings: for a given frame denizen's slot, where its
	// lifetime begins and ends.
	AssociatedInsts denizen_beginning;
	AssociatedInsts denizen_ending;

	// In the following, member variables ending in 'I' are intermediary
	// values that get finalized when constructing the corresponding
	// ZBody.
	std::vector<GlobalInfo> globalsI;
	std::unordered_map<const ID*, int> global_id_to_info;	// inverse

	// Intermediary switch tables (branching to ZInst's rather
	// than concrete instruction offsets).
	CaseMapsI<bro_int_t> int_casesI;
	CaseMapsI<bro_uint_t> uint_casesI;
	CaseMapsI<double> double_casesI;

	// Note, we use this not only for strings but for addresses
	// and prefixes.
	CaseMapsI<std::string> str_casesI;

	// Same, but for the concretized versions.
	CaseMaps<bro_int_t> int_cases;
	CaseMaps<bro_uint_t> uint_cases;
	CaseMaps<double> double_cases;
	CaseMaps<std::string> str_cases;

	std::vector<int> managed_slotsI;

	int frame_sizeI;

	TableIterVec table_iters;
	int num_step_iters = 0;

	bool non_recursive = false;

	// Most recent instruction, other than for housekeeping.
	int top_main_inst;

	// Used for communication between Frame1Slot and a subsequent
	// AddInst.  If >= 0, then upon adding the next instruction,
	// it should be followed by Store-Global for the given slot.
	int pending_global_store = -1;
};


// Invokes after compiling all of the function bodies.
class FuncInfo;
extern void finalize_functions(const std::vector<FuncInfo>& funcs);

} // namespace zeek::detail
