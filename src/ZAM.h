// See the file "COPYING" in the main distribution directory for copyright.

// ZAM: Zeek Abstract Machine compiler.

#pragma once

#include "Compile.h"
#include "Event.h"
#include "ReachingDefs.h"
#include "UseDefs.h"
#include "ZBody.h"


struct function_ingredients;
class CallExpr;
class Func;
class Body;
class UseDefs;
class ProfileFunc;
class ZInstI;

typedef ZInstI* InstLabel;

class ZAM : public Compiler {
public:
	ZAM(BroFunc* f, Scope* scope, Stmt* body,
		UseDefs* ud, Reducer* rd, ProfileFunc* pf);
	~ZAM();

	Stmt* CompileBody();

#include "ZAM-SubDefs.h"

	const CompiledStmt ConstructTable(const NameExpr* n,
						const Expr* e) override;
	const CompiledStmt ConstructSet(const NameExpr* n,
						const Expr* e) override;
	const CompiledStmt ConstructRecord(const NameExpr* n,
						const Expr* e) override;
	const CompiledStmt ConstructVector(const NameExpr* n,
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
	const CompiledStmt AssignTableElem(const Expr* e) override;

	const CompiledStmt LoopOverTable(const ForStmt* f, const NameExpr* val);
	const CompiledStmt LoopOverVector(const ForStmt* f, const NameExpr* val);
	const CompiledStmt LoopOverString(const ForStmt* f, const NameExpr* val);

	const CompiledStmt FinishLoop(const CompiledStmt iter_head,
					ZInstI iter_stmt, const Stmt* body,
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

	// Public so that GenInst flavors can get to it.
	int FrameSlot(const NameExpr* id)
		{ return FrameSlot(id->AsNameExpr()->Id()); }
	int Frame1Slot(const NameExpr* id, ZOp op)
		{ return Frame1Slot(id->AsNameExpr()->Id(), op); }

	void Dump();

protected:
	void Init();

	// Second argument is which instruction slot holds the branch target.
	const CompiledStmt GenCond(const Expr* e, int& branch_v);

	// "stride" is how many slots each element of l will consume.
	ZInstAux* InternalBuildVals(const ListExpr* l, int stride = 1);

	// Returns how many values were added.
	int InternalAddVal(ZInstAux* zi, int i, Expr* e);


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

#include "ZBuiltIn.h"

	// A bit weird, but handy for switch statements: returns a
	// bit mask of which of the arguments in the given list correspond
	// to constants, with the high-ordered bit being the first argument
	// (argument "0" in the list) and the low-ordered bit being the
	// last.  Second parameter is the number of arguments that should
	// be present.
	bro_uint_t ConstArgsMask(const expr_list& args, int nargs) const;

	const CompiledStmt DoCall(const CallExpr* c, const NameExpr* n);

	const CompiledStmt CompileSchedule(const NameExpr* n,
					const ConstExpr* c, int is_interval,
					EventHandler* h, const ListExpr* l);

	const CompiledStmt CompileEvent(EventHandler* h, const ListExpr* l);

	const CompiledStmt ValueSwitch(const SwitchStmt* sw, const NameExpr* v,
					const ConstExpr* c);
	const CompiledStmt TypeSwitch(const SwitchStmt* sw, const NameExpr* v,
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
		else if ( v == 3 )
			SetV3(s, l);
		else
			SetV4(s, l);
		}

	void SetTarget(ZInstI* inst, const InstLabel l, int slot);
	void SetV1(CompiledStmt s, const InstLabel l);
	void SetV2(CompiledStmt s, const InstLabel l);
	void SetV3(CompiledStmt s, const InstLabel l);
	void SetV4(CompiledStmt s, const InstLabel l);
	void SetGoTo(CompiledStmt s, const InstLabel targ)
		{ SetV1(s, targ); }

	const CompiledStmt AddInst(const ZInstI& inst);

	// Returns the most recent added instruction *other* than those
	// added for bookkeeping (like dirtying globals);
	ZInstI* TopMainInst()	{ return insts1[top_main_inst]; }

	// Returns the last (interpreter) statement in the body.
	const Stmt* LastStmt(const Stmt* s) const;

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

	int NewSlot(const IntrusivePtr<BroType>& t)
		{ return NewSlot(IsManagedType(t)); }
	int NewSlot(bool is_managed);

	void SyncGlobals(std::unordered_set<ID*>& g, const BroObj* o);

#include "ZOpt.h"

	// The first of these is used as we compile down to ZInstI's.
	// The second is the final intermediary code.  They're separate
	// to make it easy to remove dead code.
	vector<ZInstI*> insts1;
	vector<ZInstI*> insts2;

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
	vector<const NameExpr*> retvars;

	BroFunc* func;
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
	typedef std::unordered_map<const ZInstI*, std::unordered_set<ID*>>
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
	typedef std::unordered_map<int, const ZInstI*> AssociatedInsts;

	// Inverse mappings: for a given frame denizen's slot, where its
	// lifetime begins and ends.
	AssociatedInsts denizen_beginning;
	AssociatedInsts denizen_ending;

	// Which locals appear in interpreted expressions.
	std::unordered_set<const ID*> interpreter_locals;

	// In the following, member variables ending in 'I' are intermediary
	// values that get finalized when constructing the corresponding
	// ZBody.
	std::vector<GlobalInfo> globalsI;
	std::unordered_map<const ID*, int> global_id_to_info;	// inverse

	// Which globals are potentially ever modified.
	std::unordered_set<const ID*> modified_globals;

	// The following are used for switch statements, mapping the
	// switch value (which can be any atomic type) to a branch target.
	// We have vectors of them because functions can contain multiple
	// switches.
	template<class T> using CaseMapI = std::map<T, InstLabel>;
	template<class T> using CaseMapsI = std::vector<CaseMapI<T>>;

	CaseMapsI<bro_int_t> int_casesI;
	CaseMapsI<bro_uint_t> uint_casesI;
	CaseMapsI<double> double_casesI;

	// Note, we use this not only for strings but for addresses
	// and prefixes.
	CaseMapsI<std::string> str_casesI;

	void DumpIntCases(int i) const;
	void DumpUIntCases(int i) const;
	void DumpDoubleCases(int i) const;
	void DumpStrCases(int i) const;

	std::vector<int> managed_slotsI;

	int frame_sizeI;

	bool non_recursive = false;

	// Most recent instruction, other than for housekeeping.
	int top_main_inst;

	// Used for communication between Frame1Slot and a subsequent
	// AddInst.  If >= 0, then upon adding the next instruction,
	// it should be followed by Dirty-Global for the given slot.
	int mark_dirty = -1;
};

// Invokes after compiling all of the function bodies.
class FuncInfo;
extern void finalize_functions(const std::vector<FuncInfo*>& funcs);
