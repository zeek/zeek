// See the file "COPYING" in the main distribution directory for copyright.

// Methods for low-level optimization of the ZAM abstract machine.
//
// This file is included by Compile.h to insert into the ZAMCompiler class.

// Optimizing the low-level compiled instructions.
void OptimizeInsts();

// Tracks which instructions can be branched to via the given
// set of switches.
template<typename T>
void TallySwitchTargets(const CaseMapsI<T>& switches);

// Remove code that can't be reached.  True if some removal happened.
bool RemoveDeadCode();

// Invert conditionals that branch around unconditional branches.
bool InvertConditionalsAroundGotos();

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
void ReMapVar(const IDPtr& id, int slot, zeek_uint_t inst);

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
zeek_uint_t FirstLiveInst(zeek_uint_t i, bool follow_gotos = false);

// Same, but not including i.
ZInstI* NextLiveInst(ZInstI* i, bool follow_gotos = false) {
    if ( i->inst_num == static_cast<int>(insts1.size()) - 1 )
        return nullptr;
    return FirstLiveInst(insts1[i->inst_num + 1], follow_gotos);
}
zeek_uint_t NextLiveInst(int i, bool follow_gotos = false) { return FirstLiveInst(i + 1, follow_gotos); }

// Mark an instruction as unnecessary and remove its influence on
// other statements.  The instruction is indicated as an offset
// into insts1; any labels associated with it are transferred
// to its next live successor, if any.
void KillInst(ZInstI* i) { KillInst(i->inst_num); }
void KillInst(zeek_uint_t i);

// Helper function for propagating control flow (of a given type)
// backwards, when the instruction at the given offset has been killed.
void BackPropagateCFT(int inst_num, ControlFlowType cf_type);

// The same, but kills any successor instructions until finding
// one that's labeled.
void KillInsts(ZInstI* i) { KillInsts(i->inst_num); }
void KillInsts(zeek_uint_t i);
