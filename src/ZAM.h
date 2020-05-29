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

	const CompiledStmt GenCond(const Expr* e);

	// Optimizing the low-level compiled instructions.
	void OptimizeInsts();

	// Remove code that can't be reached.  True if some removal happened.
	bool RemoveDeadCode();

	// Collapse chains of gotos.  True if some collapsing happened.
	bool CollapseGoTos();

	// Prune statements that are unnecessary given just global
	// analysis.  True if something got pruned.
	bool PruneGlobally();

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

	void SpillVectors(ZAM_tracker_type* tracker) const;
	void LoadVectors(ZAM_tracker_type* tracker) const;

	// The first of these is used as we compile down to ZInst's.
	// The second is the final code used during execution.  They're
	// separate to make it easy to remove dead code.
	vector<ZInst*> insts1;
	vector<ZInst*> insts2;

	// Used as a placeholder when we have to generate a GoTo target
	// beyond the end of what we've compiled so far.
	ZInst* pending_inst = nullptr;

	bool profile = false;
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

	// Maps identifiers to their frame location.
	std::unordered_map<const ID*, int> frame_layout;

	// Inverse mapping, used for dumping statements.
	frame_map frame_denizens;

	// Which frame slots need clearing/deleting on entry/exit,
	// and their corresponding type tags.
	std::vector<int> managed_slots;
	std::vector<const BroType*> managed_slot_types;

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

extern void ZAM_run_time_error(bool& error_flag, const Stmt* stmt,
				const char* msg);
extern void ZAM_run_time_error(const char* msg, const BroObj* o,
				bool& error_flag);
