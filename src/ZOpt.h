// See the file "COPYING" in the main distribution directory for copyright.

// ZAM compiler declarations for optimization components.
//
// This file is only included by ZAM.h, in the context of the ZAM class
// declaration.


////////////////////////////////////////////////////////////
// The following methods relate to optimizing the low-level
// ZAM function body after it is initially generated.  They're
// factored out into ZOpt.cc since they're structurally quite
// different from the methods above that relate to the initial
// compilation.

// Optimizing the low-level compiled instructions.
void OptimizeInsts();

// Remove code that can't be reached.  True if some removal happened.
bool RemoveDeadCode();

// Collapse chains of gotos.  True if some collapsing happened.
bool CollapseGoTos();

// Prune statements that are unnecessary.  True if something got
// pruned.
bool PruneUnused();

// For the current state of inst1, compute lifetimes of frame
// denizens in terms of first-instruction-to-last-instruction
// (including consideration for loops).
void ComputeFrameLifetimes();

// Given final frame lifetime information, remaps frame members
// with non-overlapping lifetimes to share slots.
void ReMapFrame();

// Given final frame lifetime information, remaps slots in
// the interpreter frame.
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

// Mark a statement as unnecessary and remove its influence on
// other statements.
void KillInst(ZInstI* i);

// Given a GoTo target, find its live equivalent (first instruction
// at that location or beyond that's live).
ZInstI* FindLiveTarget(ZInstI* goto_target);

// Given an instruction that has a slot associated with the
// given target, updates the slot to correspond with the current
// (final) location of the target.
void RetargetBranch(ZInstI* inst, ZInstI* target, int target_slot);
