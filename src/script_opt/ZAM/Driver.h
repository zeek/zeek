// See the file "COPYING" in the main distribution directory for copyright.

// Methods for driving the overall ZAM compilation process.
//
// This file is included by Compile.h to insert into the ZAMCompiler class.

void Init();
void InitGlobals();
void InitArgs();
void InitCaptures();
void InitLocals();
void TrackMemoryManagement();

template<typename T>
void AdjustSwitchTables(CaseMapsI<T>& abstract_cases);

template<typename T>
void ConcretizeSwitchTables(const CaseMapsI<T>& abstract_cases, CaseMaps<T>& concrete_cases);
void ConcretizeSwitches();

void RetargetBranches();
void RemapFrameDenizens(const std::vector<int>& inst1_to_inst2);
void CreateSharedFrameDenizens();

void ResolveHookBreaks();
void ComputeLoopLevels();
void AdjustBranches();

template<typename T>
void DumpCases(const CaseMaps<T>& cases, const char* type_name) const;
void DumpInsts1(const FrameReMap* remappings);
