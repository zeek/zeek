// See the file "COPYING" in the main distribution directory for copyright.

// ZBody: ZAM function body that replaces a function's original AST body.

#pragma once

#include <vector>

#include "zeek/script_opt/ZAM/IterInfo.h"

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

struct ProfVal {
    zeek_uint_t num_samples = 0;
    double CPU_time = 0.0;
};

using ProfVec = std::vector<ProfVal>;
using ProfMap = std::unordered_map<std::string, ProfVal>;
using CallStack = std::vector<const ZAMLocInfo*>;

class ZBody : public Stmt {
public:
    ZBody(std::string _func_name, const ZAMCompiler* zc);

    ~ZBody() override;

    // This is split out from the constructor to allow construction of
    // a ZBody from save-file instructions (not currently supported).
    void SetInsts(std::vector<ZInstI*>& instsI);

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;

    // Older code exists for save files, but let's see if we can
    // avoid having to support them, as they're a fairly elaborate
    // production.
    //
    // void SaveTo(FILE* f, int interp_frame_size) const;

    void Dump() const;

    // Specify whether to measure CPU & memory for calls to the given body.
    void SetProfilingCalls(bool active) {
        profile_calls = active;
        profiling_set_call = ncall;
    }
    bool IsProfilingCalls() const { return profile_calls; }

    uint64_t NumBodyCalls() const { return ncall; }
    uint64_t NumBodyInsts() const;
    uint64_t NumModuleInsts(const std::string& mod) const;

    double CPUTimeEst() const { return tot_CPU_time; }
    uint64_t MemoryEst() const { return tot_mem; }

    void ReportExecutionProfile(ProfMap& pm);

    const std::string& FuncName() const { return func_name; }
    const std::set<std::string>& Modules() const { return modules; }

    // Helper run-time function for looking up a field in a record, checking
    // that it exists and complaining if it does not. A member here rather than
    // a standalone run-time function because ZBody is a "friend" of RecordVal
    // and can use its low-level record field accessors.
    static ZVal CheckAndLookupField(RecordVal* r, int f, const std::shared_ptr<ZAMLocInfo>& loc) {
        auto opt_zv = r->RawOptField(f);
        if ( ! opt_zv ) {
            auto fn = r->GetType<RecordType>()->FieldName(f);
            ZAM_run_time_error(loc, util::fmt("field value missing ($%s)", fn));
        }

        return *opt_zv;
    }

private:
    friend class CPPCompile;

    auto Instructions() const { return insts; }
    auto NumInsts() const { return end_pc; }

    std::shared_ptr<ProfVec> BuildProfVec() const;

    void ReportProfile(ProfMap& pm, const ProfVec& pv, const std::string& prefix,
                       const std::set<std::string>& caller_modules) const;

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

    // Variables controlling the depth of profiling.
    bool profile_calls = false;  // CPU and memory for calls
    bool sample_CPU_mem = false; // sample per instruction

    // We remember whenever profile_calls has been adjusted. This is to
    // avoid a miscomputation of CPU time when set_module_profiling() is called
    // from within the module being measured. See ZBody::DoExec() for more.
    uint64_t profiling_set_call = 0;

    // Indexed by program counter. Holds number of times the given instruction
    // has executed. Always maintained.
    uint64_t* inst_cnt = nullptr;

    uint64_t ncall = 0; // number of calls to the ZBody; always maintained

    int prof_sampling_rate = 0; // sample CPU/memory every N'th instruction
    uint64_t num_sampled_inst = 0;
    double tot_CPU_time = 0.0;
    uint64_t tot_mem = 0;

    // Profiling information associated with different call stacks.
    std::map<CallStack, std::shared_ptr<ProfVec>> prof_vecs;

    // Profiling information for the common case of no nested ZAM calls.
    std::shared_ptr<ProfVec> default_prof_vec;

    // Profiling information for the current call.
    ProfVec* curr_prof_vec;

    // Modules associated with this body. Used to selectively activate
    // profiling.
    std::set<std::string> modules;
};

extern bool copy_vec_elem(VectorVal* vv, zeek_uint_t ind, ZVal zv, const TypePtr& t);

extern VectorVal* vec_coerce_DI(VectorVal* vec, const std::shared_ptr<ZAMLocInfo>& z_loc);
extern VectorVal* vec_coerce_DU(VectorVal* vec, const std::shared_ptr<ZAMLocInfo>& z_loc);
extern VectorVal* vec_coerce_ID(VectorVal* vec, const std::shared_ptr<ZAMLocInfo>& z_loc);
extern VectorVal* vec_coerce_IU(VectorVal* vec, const std::shared_ptr<ZAMLocInfo>& z_loc);
extern VectorVal* vec_coerce_UD(VectorVal* vec, const std::shared_ptr<ZAMLocInfo>& z_loc);
extern VectorVal* vec_coerce_UI(VectorVal* vec, const std::shared_ptr<ZAMLocInfo>& z_loc);

// Estimated overhead (in seconds) of a single CPU or memory measurement
// when profiling.
extern double CPU_prof_overhead;
extern double mem_prof_overhead;

} // namespace zeek::detail
