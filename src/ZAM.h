// See the file "COPYING" in the main distribution directory for copyright.

// ZAM: Zeek Abstract Machine compiler.

#pragma once

#include "Compile.h"
#include "Event.h"
#include "ReachingDefs.h"
#include "UseDefs.h"
#include "ZOP.h"


struct function_ingredients;
class CallExpr;
class Func;
class Body;
class UseDefs;
class ProfileFunc;
class ZInst;

typedef ZInst* InstLabel;

class ZAM : public Compiler {
public:
	ZAM(const BroFunc* f, Scope* scope, Stmt* body,
		UseDefs* ud, Reducer* rd, ProfileFunc* pf);
	~ZAM() override;

	Stmt* CompileBody();

#include "ZAM-SubDefs.h"

	const CompiledStmt InterpretExpr(const Expr* e) override;
	const CompiledStmt InterpretExpr(const NameExpr* n,
						const Expr* e) override;

	const CompiledStmt ArithCoerce(const NameExpr* n,
					const Expr* e) override;
	const CompiledStmt RecordCoerce(const NameExpr* n,
					const Expr* e) override;
	const CompiledStmt TableCoerce(const NameExpr* n,
					const Expr* e) override;
	const CompiledStmt VectorCoerce(const NameExpr* n,
					const Expr* e) override;

	const CompiledStmt Is(const NameExpr* n, const Expr* e) override;

	const CompiledStmt IfElse(const Expr* e, const Stmt* s1,
					const Stmt* s2) override;

	const CompiledStmt While(const Stmt* cond_stmt, const Expr* cond,
					const Stmt* body) override;
	const CompiledStmt Loop(const Stmt* body) override;

	const CompiledStmt When(Expr* cond, const Stmt* body,
				const Expr* timeout, const Stmt* timeout_body,
				bool is_return) override;

	const CompiledStmt Switch(const SwitchStmt* sw) override;

	const CompiledStmt For(const ForStmt* f) override;

	const CompiledStmt Call(const ExprStmt* e) override;
	const CompiledStmt AssignToCall(const ExprStmt* e) override;

	const CompiledStmt AssignVecElems(const Expr* e) override;

	const CompiledStmt LoopOverTable(const ForStmt* f, const NameExpr* val);
	const CompiledStmt LoopOverVector(const ForStmt* f, const NameExpr* val);
	const CompiledStmt LoopOverString(const ForStmt* f, const NameExpr* val);

	const CompiledStmt FinishLoop(const CompiledStmt iter_head,
					ZInst iter_stmt, const Stmt* body,
					int info_slot);

	const CompiledStmt InitRecord(ID* id, RecordType* rt) override;
	const CompiledStmt InitVector(ID* id, VectorType* vt) override;
	const CompiledStmt InitTable(ID* id, TableType* tt, Attributes* attrs)
		override;

	const CompiledStmt Return(const ReturnStmt* r) override;
	const CompiledStmt CatchReturn(const CatchReturnStmt* cr) override;

	const CompiledStmt Next() override
		{ return GenGoTo(nexts.back()); }
	const CompiledStmt Break() override
		{ return GenGoTo(breaks.back()); }
	const CompiledStmt FallThrough() override
		{ return GenGoTo(fallthroughs.back()); }
	const CompiledStmt CatchReturn()
		{ return GenGoTo(catches.back()); }

	const CompiledStmt StartingBlock() override;
	const CompiledStmt FinishBlock(const CompiledStmt start) override;

	bool NullStmtOK() const override;

	const CompiledStmt EmptyStmt() override;
	const CompiledStmt LastInst();
	const CompiledStmt ErrorStmt() override;

	bool IsUnused(const ID* id, const Stmt* where) const override;

	void SyncGlobals(const BroObj* o) override;
	const CompiledStmt AssignedToGlobal(const ID* global_id) override;

	OpaqueVals* BuildVals(const IntrusivePtr<ListExpr>&) override;

	IntrusivePtr<Val> Exec(Frame* f, stmt_flow_type& flow) const override;

	void StmtDescribe(ODesc* d) const override;

	// Public so that GenInst flavors can get to it.
	int FrameSlot(const NameExpr* id)
		{ return FrameSlot(id->AsNameExpr()->Id()); }
	int Frame1Slot(const NameExpr* id, ZOp op)
		{ return Frame1Slot(id->AsNameExpr()->Id(), op); }

	void ProfileExecution() const override;

	void Dump();

protected:
	void Init();

	// Second argument is which instruction slot holds the branch target.
	const CompiledStmt GenCond(const Expr* e, int& branch_v);

	// Optimizing the low-level compiled instructions.
	void OptimizeInsts();

	// Remove code that can't be reached.  True if some removal happened.
	bool RemoveDeadCode();

	// Collapse chains of gotos.  True if some collapsing happened.
	bool CollapseGoTos();

	// Prune statements that are unnecessary given just global
	// analysis.  True if something got pruned.
	bool PruneGlobally();

	// For the current state of inst1, compute lifetimes of frame
	// denizens in terms of first-instruction-to-last-instruction
	// (including consideration for loops).
	void ComputeFrameLifetimes();

	// Given final frame lifetime information, remaps frame members
	// with non-overlapping lifetimes to share slots.
	void ReMapFrame();

	// Computes the remapping for a variable currently in the given slot,
	// whose scope begins at the given instruction.
	void ReMapVar(const ID* id, int slot, int inst);

	// Look to initialize the beginning of local lifetime based on slot
	// assignment at instruction inst.
	void CheckSlotAssignment(int slot, const ZInst* inst);

	// Track that a local's lifetime begins at the given statement.
	void SetLifetimeStart(int slot, const ZInst* inst);

	// Look for extension of local lifetime based on slot usage
	// at instruction inst.
	void CheckSlotUse(int slot, const ZInst* inst);

	// Extend (or create) the end of a local's lifetime.
	void ExtendLifetime(int slot, const ZInst* inst);

	// Returns the (live) instruction at the beginning/end of the loop(s)
	// within which the given instruction lies; or that instruction
	// itself if it's not inside a loop.  The second argument specifies
	// the loop depth.  For example, a value of '2' means "extend to
	// the beginning/end of any loop(s) of depth >= 2".
	const ZInst* BeginningOfLoop(const ZInst* inst, int depth) const;
	const ZInst* EndOfLoop(const ZInst* inst, int depth) const;

	// True if any statement other than a frame sync assigns to the
	// given slot.
	bool VarIsAssigned(int slot) const;

	// True if the given statement assigns to the given slot, and
	// it's not a frame sync.
	bool VarIsAssigned(int slot, const ZInst* i) const;

	// True if any statement other than a frame sync uses the given slot.
	bool VarIsUsed(int slot) const;

	// Mark a statement as unnecessary and remove its influence on
	// other statements.
	void KillInst(ZInst* i);

	// Given a GoTo target, find its live equivalent (first instruction
	// at that location or beyond that's live).
	ZInst* FindLiveTarget(ZInst* goto_target);

	// Given an instruction that has a slot associated with the
	// given target, updates the slot to correspond with the current
	// (final) location of the target.
	void RetargetBranch(ZInst* inst, ZInst* target, int target_slot);

	friend class ResumptionAM;

	IntrusivePtr<Val> DoExec(Frame* f, int start_pc,
					stmt_flow_type& flow) const;

	int InternalBuildVals(const ListExpr*);


	const CompiledStmt CompileInExpr(const NameExpr* n1, const NameExpr* n2,
						const NameExpr* n3)
		{ return CompileInExpr(n1, n2, nullptr, n3, nullptr); }

	const CompiledStmt CompileInExpr(const NameExpr* n1, const NameExpr* n2,
						const ConstExpr* c)
		{ return CompileInExpr(n1, n2, nullptr, nullptr, c); }

	const CompiledStmt CompileInExpr(const NameExpr* n1, const ConstExpr* c,
						const NameExpr* n3)
		{ return CompileInExpr(n1, nullptr, c, n3, nullptr); }

	// In the following, one of n2 or c2 (likewise, n3/c3) will be nil.
	const CompiledStmt CompileInExpr(const NameExpr* n1,
				const NameExpr* n2, const ConstExpr* c2,
				const NameExpr* n3, const ConstExpr* c3);

	const CompiledStmt CompileInExpr(const NameExpr* n1, const ListExpr* l,
						const NameExpr* n2)
		{ return CompileInExpr(n1, l, n2, nullptr); }

	const CompiledStmt CompileInExpr(const NameExpr* n, const ListExpr* l,
						const ConstExpr* c)
		{ return CompileInExpr(n, l, nullptr, c); }

	const CompiledStmt CompileInExpr(const NameExpr* n1, const ListExpr* l,
					const NameExpr* n2, const ConstExpr* c);


	const CompiledStmt CompileIndex(const NameExpr* n1, const NameExpr* n2,
					const ListExpr* l);

	// If the given expression corresponds to a call to a ZAM built-in,
	// then compiles the call and returns true.  Otherwise, returns false.
	bool IsZAM_BuiltIn(const Expr* e);

	// Built-ins returns true if they were able to compile the
	// call, false if not.
	bool BuiltIn_to_lower(const NameExpr* n, const expr_list& args);
	bool BuiltIn_sub_bytes(const NameExpr* n, const expr_list& args);
	bool BuiltIn_Log__write(const NameExpr* n, const expr_list& args);
	bool BuiltIn_Broker__flush_logs(const NameExpr* n,
					const expr_list& args);
	bool BuiltIn_get_port_etc(const NameExpr* n, const expr_list& args);
	bool BuiltIn_reading_live_traffic(const NameExpr* n, const expr_list& args);
	bool BuiltIn_reading_traces(const NameExpr* n, const expr_list& args);

	// A bit weird, but handy for switch statements: returns a
	// bit mask of which of the arguments in the given list correspond
	// to constants, with the high-ordered bit being the first argument
	// (argument "0" in the list) and the low-ordered bit being the
	// last.  Second parameter is the number of arguments that should
	// be present.
	bro_uint_t ConstArgsMask(const expr_list& args, int nargs) const;

	const CompiledStmt DoCall(const CallExpr* c, const NameExpr* n, UDs uds);

	const CompiledStmt CompileSchedule(const NameExpr* n,
					const ConstExpr* c, int is_interval,
					EventHandler* h, const ListExpr* l);

	const CompiledStmt CompileEvent(EventHandler* h, const ListExpr* l);

	const CompiledStmt ValueSwitch(const SwitchStmt* sw, const NameExpr* v,
					const ConstExpr* c);
	const CompiledStmt TypeSwitch(const SwitchStmt* sw, const NameExpr* v,
					const ConstExpr* c);

	ListVal* ValVecToListVal(val_vec* v, int n) const;

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

	typedef vector<CompiledStmt> GoToSet;
	typedef vector<GoToSet> GoToSets;

	void PushGoTos(GoToSets& gotos);
	void ResolveGoTos(GoToSets& gotos, const InstLabel l);

	CompiledStmt GenGoTo(GoToSet& v);
	CompiledStmt GoToStub();
	CompiledStmt GoTo(const InstLabel l);
	InstLabel GoToTarget(const CompiledStmt s);
	InstLabel GoToTargetBeyond(const CompiledStmt s);
	CompiledStmt PrevStmt(const CompiledStmt s);
	void SetV(CompiledStmt s, const InstLabel l, int v)
		{
		if ( v == 1 )
			SetV1(s, l);
		else if ( v == 2 )
			SetV2(s, l);
		else
			SetV3(s, l);
		}

	void SetTarget(ZInst* inst, const InstLabel l, int slot);
	void SetV1(CompiledStmt s, const InstLabel l);
	void SetV2(CompiledStmt s, const InstLabel l);
	void SetV3(CompiledStmt s, const InstLabel l);
	void SetGoTo(CompiledStmt s, const InstLabel targ)
		{ SetV1(s, targ); }

	const CompiledStmt AddInst(const ZInst& inst);

	// Returns the most recent added instruction *other* than those
	// added for bookkeeping (like dirtying globals);
	ZInst* TopMainInst()	{ return insts1[top_main_inst]; }

	// Returns the last (interpreter) statement in the body.
	const Stmt* LastStmt() const;

	void FlushVars(const Expr* e);

	void LoadParam(ID* id)		{ LoadOrStoreLocal(id, true, true); }
	void StoreLocal(ID* id)		{ LoadOrStoreLocal(id, false, false); }
	const CompiledStmt LoadOrStoreLocal(ID* id, bool is_load, bool add);

	const CompiledStmt LoadGlobal(ID* id);

	int AddToFrame(ID*);

	int FrameSlot(const ID* id);
	int FrameSlotIfName(const Expr* e)
		{
		auto n = e->Tag() == EXPR_NAME ? e->AsNameExpr() : nullptr;
		return n ? FrameSlot(n->Id()) : 0;
		}

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

	int Frame1Slot(const ID* id, ZOp op)
		{ return Frame1Slot(id, op1_flavor[op]); }
	int Frame1Slot(const NameExpr* n, ZAMOp1Flavor fl)
		{ return Frame1Slot(n->Id(), fl); }
	int Frame1Slot(const ID* id, ZAMOp1Flavor fl);

	// The slot without doing any global-related checking.
	int RawSlot(const NameExpr* n)	{ return RawSlot(n->Id()); }
	int RawSlot(const ID* id);

	bool HasFrameSlot(const ID* id) const;

	int NewSlot();
	int RegisterSlot();

	void SyncGlobals(std::unordered_set<ID*>& g, const BroObj* o);

	// Run-time checking for "any" type being consistent with
	// expected typed.  Returns true if the type match is okay.
	bool CheckAnyType(const BroType* any_type, const BroType* expected_type,
				const Stmt* associated_stmt) const;

	// The first of these is used as we compile down to ZInst's.
	// The second is the final code used during execution.  They're
	// separate to make it easy to remove dead code.
	vector<ZInst*> insts1;
	vector<ZInst*> insts2;

	// Used as a placeholder when we have to generate a GoTo target
	// beyond the end of what we've compiled so far.
	ZInst* pending_inst = nullptr;

	// These need to be pointers so we can manipulate them in a
	// const method.
	vector<int>* inst_count;	// for profiling
	double* CPU_time = nullptr;	// cumulative CPU time for the program
	vector<double>* inst_CPU;	// per-instruction CPU time.

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
	vector<const NameExpr*> retvars;

	const BroFunc* func;
	Scope* scope;
	Stmt* body;
	UseDefs* ud;
	Reducer* reducer;
	ProfileFunc* pf;

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
	typedef std::unordered_map<const ZInst*, std::unordered_set<const ID*>>
		AssociatedLocals;

	// Maps (live) instructions to which frame denizens begin their
	// lifetime via an initialization at that instruction, if any ...
	// (it can be more than one local due to extending lifetimes to
	// span loop bodies)
	AssociatedLocals inst_beginnings;

	// ... and which frame denizens had their last usage at the
	// given instruction.  (These are inst1 instructions, prior to
	// removing dead instructions, compressing the frames, etc.)
	AssociatedLocals inst_endings;

	// A type for inverse mappings.
	typedef std::unordered_map<int, const ZInst*> AssociatedInsts;

	// Inverse mappings: for a given frame denizen's slot, where its
	// lifetime begins and ends.
	AssociatedInsts denizen_beginning;
	AssociatedInsts denizen_ending;

	// Which frame slots need clearing/deleting on entry/exit,
	// and their corresponding type tags.
	std::vector<int> managed_slots;
	std::vector<const BroType*> managed_slot_types;

	// Static information about globals used in the function.  There's
	// a parallel array "global_state" that's constructed
	// per-function-invocation that dynamically tracks whether a
	// global is loaded, clean, or dirty.
	class GlobalInfo {
	public:
		ID* id;
		int slot;
	};
	std::vector<GlobalInfo> globals;
	std::unordered_map<const ID*, int> global_id_to_info;	// inverse

	// Which globals are potentially ever modified.
	std::unordered_set<const ID*> modified_globals;

	// The following are used for switch statements, mapping the
	// switch value (which can be any atomic type) to a branch target.
	// We have vectors of them because functions can contain multiple
	// switches.
	template<class T> using CaseMap = std::map<T, InstLabel>;
	template<class T> using CaseMaps = std::vector<CaseMap<T>>;

	CaseMaps<bro_int_t> int_cases;
	CaseMaps<bro_uint_t> uint_cases;
	CaseMaps<double> double_cases;

	// Note, we use this not only for strings but for addresses
	// and prefixes.
	CaseMaps<std::string> str_cases;

	void DumpIntCases(int i) const;
	void DumpUIntCases(int i) const;
	void DumpDoubleCases(int i) const;
	void DumpStrCases(int i) const;

	int frame_size;
	int register_slot;
	int num_globals;
	bool error_seen = false;

	// Most recent instruction, other than for housekeeping.
	int top_main_inst;

	// Used for communication between Frame1Slot and a subsequent
	// AddInst.  If >= 0, then upon adding the next instruction,
	// it should be followed by Dirty-Global for the given slot.
	int mark_dirty = -1;
};

// This is a statement that resumes execution into a code block in an
// ZAM.  Used for deferred execution for "when" statements.
class ResumptionAM : public Stmt {
public:
	ResumptionAM(const ZAM* _am, int _xfer_pc)
		{
		am = _am;
		xfer_pc = _xfer_pc;
		}

	IntrusivePtr<Val> Exec(Frame* f, stmt_flow_type& flow) const override;

	void StmtDescribe(ODesc* d) const override;

protected:
	TraversalCode Traverse(TraversalCallback* cb) const override;

	const ZAM* am;
	int xfer_pc = 0;
};

extern void report_ZOP_profile();

extern void ZAM_run_time_error(const Stmt* stmt, const char* msg);
extern void ZAM_run_time_error(const char* msg, const BroObj* o);
