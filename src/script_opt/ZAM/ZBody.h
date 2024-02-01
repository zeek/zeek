// See the file "COPYING" in the main distribution directory for copyright.

// ZBody: ZAM function body that replaces a function's original AST body.

#pragma once

#include "zeek/script_opt/ZAM/IterInfo.h"
#include "zeek/script_opt/ZAM/Profile.h"
#include "zeek/script_opt/ZAM/Support.h"

namespace zeek::detail {

// Static information about globals used in a function.
class GlobalInfo {
public:
    IDPtr id;
    int slot;
};

// These are the counterparts to CaseMapI and CaseMapsI in ZAM.h,
// but concretized to use instruction numbers rather than pointers
// to instructions.
template<typename T>
using CaseMap = std::map<T, int>;
template<typename T>
using CaseMaps = std::vector<CaseMap<T>>;

using TableIterVec = std::vector<TableIterInfo>;
using ProfVec = std::vector<std::pair<zeek_uint_t, double>>;
using ProfMap = std::unordered_map<std::string, std::pair<zeek_uint_t, double>>;
using CallStack = std::vector<std::shared_ptr<ZAMLocInfo>>;

class ZBody : public Stmt {
public:
    ZBody(std::string _func_name, const ZAMCompiler* zc);

    ~ZBody() override;

    // These are split out from the constructor to allow construction
    // of a ZBody from either save-file full instructions (first method,
    // not currently supported) or intermediary instructions (second method).
    void SetInsts(std::vector<ZInst*>& insts);
    void SetInsts(std::vector<ZInstI*>& instsI);

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;

    // Older code exists for save files, but let's see if we can
    // avoid having to support them, as they're a fairly elaborate
    // production.
    //
    // void SaveTo(FILE* f, int interp_frame_size) const;

    void Dump() const;

    void ProfileExecution(ProfMap& pm);

    const std::string& FuncName() const { return func_name; }
    double CPUTime() const { return adj_CPU_time; }
    int NInst() const { return ninst; }

private:
    // Initializes profiling information, if needed.
    void InitProfile();
    std::shared_ptr<ProfVec> BuildProfVec() const;

    void ReportProfile(ProfMap& pm, const ProfVec& pv, const std::string& prefix,
                       std::set<std::string> caller_modules) const;

    ValPtr DoExec(Frame* f, StmtFlowType& flow);

    // Run-time checking for "any" type being consistent with
    // expected typed.  Returns true if the type match is okay.
    bool CheckAnyType(const TypePtr& any_type, const TypePtr& expected_type,
                      const std::shared_ptr<ZAMLocInfo>& loc) const;

    StmtPtr Duplicate() override { return {NewRef{}, this}; }

    void StmtDescribe(ODesc* d) const override;
    TraversalCode Traverse(TraversalCallback* cb) const override;

    std::string func_name;

    const ZInst* insts = nullptr;
    unsigned int end_pc = 0;

    FrameReMap frame_denizens;
    int frame_size;

    // A list of frame slots that correspond to managed values.
    std::vector<int> managed_slots;

    // This is non-nil if the function is (asserted to be) non-recursive,
    // in which case we pre-allocate this.
    ZVal* fixed_frame = nullptr;

    // Pre-allocated table iteration values.  For recursive invocations,
    // these are copied into a local stack variable, but for non-recursive
    // functions they can be used directly.
    TableIterVec table_iters;

    // Points to the TableIterVec used to manage iteration over tables.
    // For non-recursive functions, we just use the static one, but
    // for recursive ones this points to the local stack variable.
    TableIterVec* tiv_ptr = &table_iters;

    // Number of StepIterInfo's required by the function.  These we
    // always create using a local stack variable, since they don't
    // require any overhead or cleanup.
    int num_step_iters;

    std::vector<GlobalInfo> globals;
    int num_globals;

    CaseMaps<zeek_int_t> int_cases;
    CaseMaps<zeek_uint_t> uint_cases;
    CaseMaps<double> double_cases;
    CaseMaps<std::string> str_cases;

    // The following are only maintained if we're doing profiling.
    double CPU_time = 0.0;     // cumulative CPU time for the program
    double adj_CPU_time = 0.0; // adjusted for profiling overhead
    int ninst = 0;

    std::map<CallStack, std::shared_ptr<ProfVec>> prof_vecs;
    std::shared_ptr<ProfVec> default_prof_vec;
    std::shared_ptr<ProfVec> curr_prof_vec;
};

} // namespace zeek::detail
