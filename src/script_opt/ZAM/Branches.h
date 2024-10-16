// See the file "COPYING" in the main distribution directory for copyright.

// Methods for managing low-level ZAM control flow, which is implemented
// using go-to branches.
//
// This file is included by Compile.h to insert into the ZAMCompiler class.

void PushNexts() { PushGoTos(nexts); }
void PushBreaks() { PushGoTos(breaks); }
void PushFallThroughs() { PushGoTos(fallthroughs); }
void PushCatchReturns() { PushGoTos(catches); }

void ResolveNexts(const InstLabel l) { ResolveGoTos(nexts, l, CFT_NEXT); }
void ResolveBreaks(const InstLabel l) { ResolveGoTos(breaks, l, CFT_BREAK); }
void ResolveFallThroughs(const InstLabel l) { ResolveGoTos(fallthroughs, l); }
void ResolveCatchReturns(const InstLabel l) { ResolveGoTos(catches, l, CFT_INLINED_RETURN); }

using GoToSet = std::vector<ZAMStmt>;
using GoToSets = std::vector<GoToSet>;

void PushGoTos(GoToSets& gotos);
void ResolveGoTos(GoToSets& gotos, const InstLabel l, ControlFlowType cft = CFT_NONE);

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

void SetV(ZAMStmt s, const InstLabel l, int v) {
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
void SetGoTo(ZAMStmt s, const InstLabel targ) { SetV1(s, targ); }
