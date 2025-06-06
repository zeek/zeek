// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/ZAM/ZBody.h"

#include "zeek/Conn.h"
#include "zeek/Desc.h"
#include "zeek/Event.h"
#include "zeek/File.h"
#include "zeek/Frame.h"
#include "zeek/OpaqueVal.h"
#include "zeek/Overflow.h"
#include "zeek/RE.h"
#include "zeek/Reporter.h"
#include "zeek/Traverse.h"
#include "zeek/Trigger.h"
#include "zeek/script_opt/ScriptOpt.h"
#include "zeek/script_opt/ZAM/Compile.h"
#include "zeek/script_opt/ZAM/Support.h"

// Forward declarations from RunState.cc
namespace zeek::run_state {
extern double network_time;
extern bool reading_traces;
extern bool reading_live;
extern bool terminating;
} // namespace zeek::run_state

namespace zeek::detail {

static double CPU_prof_overhead = 0.0;
static double mem_prof_overhead = 0.0;

// Estimates the minimum overhead for calling function "f", in seconds.
// "n" specifies how many total calls to measure, and "navg" the number
// of calls to average over. "f" should be a somewhat heavyweight function
// such that a call to it amounts to at least 100s of nsecs.
//
// We use minimum overhead rather than average as the latter can be
// significantly skewed by scheduling spikes and the like, whereas the
// minimum has proven robust in practice.
//
// Note that the measurement itself has some overhead from calling
// util::curr_CPU_time(), though this becomes quite minor as long as "navg"
// isn't too small / "f" is sufficiently heavyweight.

static double est_min_overhead(void (*f)(), int n, int navg) {
    double last_t = util::curr_CPU_time();
    double min_dt = -1.0;
    int ncall = 0;

    for ( int i = 0; i < n; ++i ) {
        (*f)();
        if ( ++ncall % navg == 0 ) {
            double new_t = util::curr_CPU_time();
            double dt = new_t - last_t;
            if ( min_dt >= 0.0 )
                min_dt = std::min(min_dt, dt);
            else
                min_dt = dt;
            last_t = new_t;
        }
    }

    return min_dt / navg;
}

static void get_CPU_time() { (void)util::curr_CPU_time(); }

static void get_mem_time() {
    uint64_t m2;
    util::get_memory_usage(&m2, nullptr);
}

void estimate_ZAM_profiling_overhead() {
    CPU_prof_overhead = est_min_overhead(get_CPU_time, 1000000, 100);
    mem_prof_overhead = est_min_overhead(get_mem_time, 250000, 100);
}

#ifdef ENABLE_ZAM_PROFILE

static std::vector<const ZAMLocInfo*> caller_locs;
static bool profile_all = getenv("ZAM_PROFILE_ALL") != nullptr;

#define DO_ZAM_PROFILE                                                                                                 \
    if ( do_profile ) {                                                                                                \
        double dt = util::curr_CPU_time() - profile_CPU;                                                               \
        auto& prof_info = (*curr_prof_vec)[profile_pc];                                                                \
        ++prof_info.num_samples;                                                                                       \
        prof_info.CPU_time += dt;                                                                                      \
        ZOP_CPU[z.op] += dt;                                                                                           \
    }

// These next two macros appear in code generated by gen-zam.
#define ZAM_PROFILE_PRE_CALL                                                                                           \
    if ( do_profile ) {                                                                                                \
        caller_locs.push_back(z.loc.get());                                                                            \
        if ( ! z.aux->is_BiF_call ) { /* For non-BiFs we don't include the callee's execution time as part of our own  \
                                       */                                                                              \
            DO_ZAM_PROFILE                                                                                             \
        }                                                                                                              \
    }

#define ZAM_PROFILE_POST_CALL                                                                                          \
    if ( do_profile ) {                                                                                                \
        caller_locs.pop_back();                                                                                        \
        if ( ! z.aux->is_BiF_call ) { /* We already did the profiling, move on to next instruction */                  \
            ++pc;                                                                                                      \
            continue;                                                                                                  \
        }                                                                                                              \
    }

#else

#define DO_ZAM_PROFILE
#define ZAM_PROFILE_PRE_CALL
#define ZAM_PROFILE_POST_CALL

static bool profile_all = false;

#endif

using std::vector;

// Thrown when a call inside a "when" delays.
class ZAMDelayedCallException : public InterpreterException {};

static bool did_init = false;

// Count of how often each type of ZOP executed, and how much CPU it
// cumulatively took.
int ZOP_count[OP_NOP + 1];
double ZOP_CPU[OP_NOP + 1];

void report_ZOP_profile() {
    static bool did_overhead_report = false;

    if ( ! did_overhead_report ) {
        fprintf(analysis_options.profile_file, "Profile sampled every %d instructions; all calls profiled\n",
                analysis_options.profile_sampling_rate);
        fprintf(analysis_options.profile_file,
                "Profiling overhead = %.0f nsec/instruction, memory profiling overhead = %.0f nsec/call\n",
                CPU_prof_overhead * 1e9, mem_prof_overhead * 1e9);
        did_overhead_report = true;
    }

    for ( int i = 1; i <= OP_NOP; ++i )
        if ( ZOP_count[i] > 0 || profile_all ) {
            auto CPU = std::max(ZOP_CPU[i] - ZOP_count[i] * CPU_prof_overhead, 0.0);
            fprintf(analysis_options.profile_file, "%s\t%d\t%.06f\n", ZOP_name(ZOp(i)), ZOP_count[i], CPU);
        }
}

// Sets the given element to a copy of an existing (not newly constructed)
// ZVal, including underlying memory management.  Returns false if the
// assigned value was missing (which we can only tell for managed types),
// true otherwise.

bool copy_vec_elem(VectorVal* vv, zeek_uint_t ind, ZVal zv, const TypePtr& t) {
    if ( vv->Size() <= ind )
        vv->Resize(ind + 1);

    auto& elem = vv->RawVec()[ind];

    if ( ! ZVal::IsManagedType(t) ) {
        elem = zv;
        return true;
    }

    if ( elem )
        ZVal::DeleteManagedType(*elem);

    elem = zv;
    auto managed_elem = elem->ManagedVal();

    if ( ! managed_elem ) {
        elem = std::nullopt;
        return false;
    }

    zeek::Ref(managed_elem);
    return true;
}

// Unary and binary element-by-element vector operations, yielding a new
// VectorVal with a yield type of 't'.  'z' is passed in only for localizing
// errors.
static void vec_exec(ZOp op, TypePtr t, VectorVal*& v1, const VectorVal* v2, const ZInst& z);

static void vec_exec(ZOp op, TypePtr t, VectorVal*& v1, const VectorVal* v2, const VectorVal* v3, const ZInst& z);

auto false_func = [](double x) { return false; };

// Vector coercion.
#define VEC_COERCE(tag, lhs_type, cast, rhs_accessor, ov_check, ov_err)                                                \
    VectorVal* vec_coerce_##tag(VectorVal* vec, std::shared_ptr<ZAMLocInfo> z_loc) {                                   \
        auto& v = vec->RawVec();                                                                                       \
        auto yt = make_intrusive<VectorType>(base_type(lhs_type));                                                     \
        auto res_zv = new VectorVal(yt);                                                                               \
        auto n = v.size();                                                                                             \
        res_zv->Resize(n);                                                                                             \
        auto& res = res_zv->RawVec();                                                                                  \
        for ( auto i = 0U; i < n; ++i )                                                                                \
            if ( v[i] ) {                                                                                              \
                auto vi = (*v[i]).rhs_accessor;                                                                        \
                if ( ov_check(vi) ) {                                                                                  \
                    std::string err = "overflow promoting from ";                                                      \
                    err += (ov_err);                                                                                   \
                    err += " arithmetic value";                                                                        \
                    /* The run-time error will throw an exception, so recover intermediary memory. */                  \
                    delete res_zv;                                                                                     \
                    ZAM_run_time_error(z_loc, err.c_str());                                                            \
                }                                                                                                      \
                else                                                                                                   \
                    res[i] = ZVal(cast(vi));                                                                           \
            }                                                                                                          \
            else                                                                                                       \
                res[i] = std::nullopt;                                                                                 \
        return res_zv;                                                                                                 \
    }

VEC_COERCE(DI, TYPE_DOUBLE, double, AsInt(), false_func, "")
VEC_COERCE(DU, TYPE_DOUBLE, double, AsCount(), false_func, "")
VEC_COERCE(ID, TYPE_INT, zeek_int_t, AsDouble(), double_to_int_would_overflow, "double to signed")
VEC_COERCE(IU, TYPE_INT, zeek_int_t, AsCount(), count_to_int_would_overflow, "unsigned to signed")
VEC_COERCE(UD, TYPE_COUNT, zeek_uint_t, AsDouble(), double_to_count_would_overflow, "double to unsigned")
VEC_COERCE(UI, TYPE_COUNT, zeek_int_t, AsInt(), int_to_count_would_overflow, "signed to unsigned")

ZBody::ZBody(std::string _func_name, const ZAMCompiler* zc) : Stmt(STMT_ZAM) {
    func_name = std::move(_func_name);

    frame_denizens = zc->FrameDenizens();
    frame_size = frame_denizens.size();

    // Concretize the names of the frame denizens.
    for ( auto& f : frame_denizens )
        for ( auto& id : f.ids )
            f.names.push_back(id->Name());

    managed_slots = zc->ManagedSlots();

    globals = zc->Globals();
    num_globals = globals.size();

    int_cases = zc->GetCases<zeek_int_t>();
    uint_cases = zc->GetCases<zeek_uint_t>();
    double_cases = zc->GetCases<double>();
    str_cases = zc->GetCases<std::string>();

    if ( zc->NonRecursive() ) {
        fixed_frame = new ZVal[frame_size];

        for ( auto& ms : managed_slots )
            fixed_frame[ms].ClearManagedVal();
    }

    table_iters = zc->GetTableIters();
    num_step_iters = zc->NumStepIters();

    // It's a little weird doing this in the constructor, but unless
    // we add a general "initialize for ZAM" function, this is as good
    // a place as any.
    if ( ! did_init ) {
        auto log_ID_type = lookup_ID("ID", "Log");
        ASSERT(log_ID_type);
        ZAM::log_ID_enum_type = log_ID_type->GetType<EnumType>();
        ZVal::SetZValNilStatusAddr(&ZAM_error);
        did_init = false;
    }
}

ZBody::~ZBody() {
    delete[] fixed_frame;
    delete[] insts;
}

void ZBody::SetInsts(vector<ZInst*>& _insts) {
    end_pc = _insts.size();
    auto insts_copy = new ZInst[end_pc];

    for ( auto i = 0U; i < end_pc; ++i )
        insts_copy[i] = *_insts[i];

    insts = insts_copy;

    InitProfile();
}

void ZBody::SetInsts(vector<ZInstI*>& instsI) {
    end_pc = instsI.size();
    auto insts_copy = new ZInst[end_pc];

    for ( auto i = 0U; i < end_pc; ++i ) {
        auto& iI = *instsI[i];
        insts_copy[i] = iI;
    }

    insts = insts_copy;

    InitProfile();
}

void ZBody::InitProfile() {
    if ( analysis_options.profile_ZAM ) {
        default_prof_vec = BuildProfVec();
        curr_prof_vec = default_prof_vec.get();
    }
}

std::shared_ptr<ProfVec> ZBody::BuildProfVec() const {
    auto pv = std::make_shared<ProfVec>();
    pv->resize(end_pc);

    for ( auto i = 0U; i < end_pc; ++i )
        (*pv)[i] = {0, 0.0};

    return pv;
}

// Helper class for managing ZBody state to ensure that memory is recovered
// if a ZBody is exited via an exception.
class ZBodyStateManager {
public:
    // If fixed_frame is nil then creates a dynamic frame.
    ZBodyStateManager(ZVal* _fixed_frame, int frame_size, const std::vector<int>& _managed_slots,
                      TableIterVec* _tiv_ptr)
        : fixed_frame(_fixed_frame), managed_slots(_managed_slots), tiv_ptr(_tiv_ptr) {
        if ( fixed_frame )
            frame = fixed_frame;
        else {
            frame = new ZVal[frame_size];
            for ( auto s : managed_slots )
                frame[s].ClearManagedVal();
        }
    }

    void SetTableIters(TableIterVec* _tiv_ptr) { tiv_ptr = _tiv_ptr; }

    ~ZBodyStateManager() {
        if ( tiv_ptr )
            for ( auto& ti : *tiv_ptr )
                ti.Clear();

        if ( fixed_frame ) {
            // Recover memory and reset for use in next call.
            for ( auto s : managed_slots ) {
                ZVal::DeleteManagedType(frame[s]);
                frame[s].ClearManagedVal();
            }
        }

        else {
            // Recover memory, no need to reset.
            for ( auto s : managed_slots )
                ZVal::DeleteManagedType(frame[s]);
            delete[] frame;
        }
    }

    auto Frame() { return frame; }

private:
    ZVal* fixed_frame;
    ZVal* frame;
    const std::vector<int>& managed_slots;
    TableIterVec* tiv_ptr;
};

ValPtr ZBody::Exec(Frame* f, StmtFlowType& flow) {
    unsigned int pc = 0;

    // Return value, or nil if none.
    const ZVal* ret_u = nullptr;

    // Type of the return value.  If nil, then we don't have a value.
    TypePtr ret_type;

    // ListVal corresponding to INDEX_LIST.
    static auto zam_index_val_list = make_intrusive<ListVal>(TYPE_ANY);

#ifdef ENABLE_ZAM_PROFILE
    static bool profiling_active = analysis_options.profile_ZAM;
    static int sampling_rate = analysis_options.profile_sampling_rate;

    double start_CPU_time = 0.0;
    uint64_t start_mem = 0;

    if ( profiling_active ) {
        ++ncall;
        start_CPU_time = util::curr_CPU_time();
        util::get_memory_usage(&start_mem, nullptr);

        if ( caller_locs.empty() )
            curr_prof_vec = default_prof_vec.get();
        else {
            auto pv = prof_vecs.find(caller_locs);
            if ( pv == prof_vecs.end() )
                pv = prof_vecs.insert({caller_locs, BuildProfVec()}).first;
            curr_prof_vec = pv->second.get();
        }
    }
#endif

    ZBodyStateManager state_mgr(fixed_frame, frame_size, managed_slots, &table_iters);
    std::unique_ptr<TableIterVec> local_table_iters;
    std::vector<StepIterInfo> step_iters(num_step_iters);

    ZVal* frame;

    if ( fixed_frame )
        frame = fixed_frame;
    else {
        frame = state_mgr.Frame();

        if ( ! table_iters.empty() ) {
            local_table_iters = std::make_unique<TableIterVec>(table_iters.size());
            *local_table_iters = table_iters;
            tiv_ptr = &(*local_table_iters);
            state_mgr.SetTableIters(nullptr); // unique_ptr will clean it up directly
        }
    }

    flow = FLOW_RETURN; // can be over-written by a Hook-Break

    // Clear any leftover error state.
    ZAM_error = false;

    while ( pc < end_pc && ! ZAM_error ) {
        auto& z = insts[pc];

#ifdef ENABLE_ZAM_PROFILE
        bool do_profile = false;
        int profile_pc = 0;
        double profile_CPU = 0.0;

        if ( profiling_active ) {
            static auto seed = util::detail::random_number();
            seed = util::detail::prng(seed);
            do_profile = seed % sampling_rate == 0;

            if ( do_profile ) {
                ++ZOP_count[z.op];
                ++ninst;

                profile_pc = pc;
                profile_CPU = util::curr_CPU_time();
            }
        }
#endif

        switch ( z.op ) {
            case OP_NOP:
                break;

                // These must stay in this order or the build fails.
                // clang-format off
#include "ZAM-EvalMacros.h"
#include "ZAM-EvalDefs.h"
                // clang-format on

            default: reporter->InternalError("bad ZAM opcode");
        }

        DO_ZAM_PROFILE

        ++pc;
    }

#ifdef ENABLE_ZAM_PROFILE
    if ( profiling_active ) {
        tot_CPU_time += util::curr_CPU_time() - start_CPU_time;
        uint64_t final_mem;
        util::get_memory_usage(&final_mem, nullptr);
        if ( final_mem > start_mem )
            tot_mem += final_mem - start_mem;
    }
#endif

    return ret_type ? ret_u->ToVal(ret_type) : nullptr;
}

void ZBody::ReportExecutionProfile(ProfMap& pm) {
    static bool did_overhead_report = false;

    if ( end_pc == 0 ) {
        fprintf(analysis_options.profile_file, "%s has an empty body\n", func_name.c_str());
        return;
    }

    auto& dpv = *default_prof_vec;

    if ( dpv[0].num_samples == 0 && prof_vecs.empty() ) {
        fprintf(analysis_options.profile_file, "%s did not execute\n", func_name.c_str());
        if ( ! profile_all )
            return;
    }

    int total_samples = ncall + ninst;
    double adj_CPU_time = tot_CPU_time;
    adj_CPU_time -= ncall * (mem_prof_overhead + CPU_prof_overhead);
    adj_CPU_time -= ninst * CPU_prof_overhead;
    adj_CPU_time = std::max(adj_CPU_time, 0.0);

    fprintf(analysis_options.profile_file, "%s CPU time %.06f, %" PRIu64 " memory, %d calls, %d sampled instructions\n",
            func_name.c_str(), adj_CPU_time, tot_mem, ncall, ninst);

    if ( dpv[0].num_samples != 0 || profile_all )
        ReportProfile(pm, dpv, "", {});

    for ( auto& pv : prof_vecs ) {
        std::string prefix;
        std::set<std::string> modules;
        for ( auto& caller : pv.first ) {
            prefix += caller->Describe(true) + ";";
            auto& m = caller->GetModules();
            modules.insert(m.begin(), m.end());
        }

        ReportProfile(pm, *pv.second, prefix, std::move(modules));
    }
}

void ZBody::ReportProfile(ProfMap& pm, const ProfVec& pv, const std::string& prefix,
                          std::set<std::string> caller_modules) const {
    for ( auto i = 0U; i < pv.size(); ++i ) {
        auto ninst = pv[i].num_samples;
        auto CPU = pv[i].CPU_time;
        CPU = std::max(CPU - ninst * CPU_prof_overhead, 0.0);
        fprintf(analysis_options.profile_file, "%s %d %" PRId64 " %.06f ", func_name.c_str(), i, ninst, CPU);
        insts[i].Dump(analysis_options.profile_file, i, &frame_denizens, prefix);

        auto modules = caller_modules;
        auto& m = insts[i].loc->GetModules();
        modules.insert(m.begin(), m.end());

        for ( auto& m : modules ) {
            auto mod_prof = pm.find(m);
            if ( mod_prof == pm.end() )
                pm[m] = {ninst, CPU};
            else {
                mod_prof->second.num_samples += ninst;
                mod_prof->second.CPU_time += CPU;
            }
        }
    }
}

void ZBody::Dump() const {
    printf("Frame:\n");

    for ( unsigned i = 0; i < frame_denizens.size(); ++i ) {
        auto& d = frame_denizens[i];

        printf("frame[%d] =", i);

        if ( d.names.empty() )
            for ( auto& id : d.ids )
                printf(" %s", id->Name());
        else
            for ( auto& n : d.names )
                printf(" %s", n);
        printf("\n");
    }

    printf("Final code:\n");

    for ( unsigned i = 0; i < end_pc; ++i ) {
        auto& inst = insts[i];
        printf("%d: ", i);
        inst.Dump(stdout, i, &frame_denizens, "");
    }
}

void ZBody::StmtDescribe(ODesc* d) const {
    d->AddSP("ZAM-code");
    d->Add(func_name.c_str());
}

TraversalCode ZBody::Traverse(TraversalCallback* cb) const {
    TraversalCode tc = cb->PreStmt(this);
    HANDLE_TC_STMT_PRE(tc);

    for ( auto& gi : globals ) {
        tc = gi.id->Traverse(cb);
        HANDLE_TC_STMT_PRE(tc);
    }

    for ( size_t i = 0; i < NumInsts(); ++i ) {
        tc = insts[i].Traverse(cb);
        HANDLE_TC_STMT_PRE(tc);
    }

    tc = cb->PostStmt(this);
    HANDLE_TC_STMT_POST(tc);
}

// Unary vector operation of v1 <vec-op> v2.
static void vec_exec(ZOp op, TypePtr t, VectorVal*& v1, const VectorVal* v2, const ZInst& /* z */) {
    // We could speed this up further still by gen'ing up an instance
    // of the loop inside each switch case (in which case we might as
    // well move the whole kit-and-caboodle into the Exec method).  But
    // that seems like a lot of code bloat for only a very modest gain.

    auto& vec2 = v2->RawVec();
    auto n = vec2.size();
    vector<std::optional<ZVal>> vec1(n);

    for ( auto i = 0U; i < n; ++i ) {
        if ( vec2[i] )
            switch ( op ) {
#include "ZAM-Vec1EvalDefs.h"

                default: reporter->InternalError("bad invocation of VecExec");
            }
        else
            vec1[i] = std::nullopt;
    }

    auto vt = cast_intrusive<VectorType>(std::move(t));
    auto old_v1 = v1;
    v1 = new VectorVal(std::move(vt), &vec1);
    Unref(old_v1);
}

// Binary vector operation of v1 = v2 <vec-op> v3.
static void vec_exec(ZOp op, TypePtr t, VectorVal*& v1, const VectorVal* v2, const VectorVal* v3, const ZInst& z) {
    // See comment above re further speed-up.

    auto& vec2 = v2->RawVec();
    auto& vec3 = v3->RawVec();
    auto n = vec2.size();

    if ( vec3.size() != n ) {
        ZAM_run_time_error(z.loc, util::fmt("vector operands are of different sizes (%zu vs. %zu)", n, vec3.size()));
        return;
    }

    vector<std::optional<ZVal>> vec1(n);

    for ( auto i = 0U; i < vec2.size(); ++i ) {
        if ( vec2[i] && vec3[i] )
            switch ( op ) {
#include "ZAM-Vec2EvalDefs.h"

                default: reporter->InternalError("bad invocation of VecExec");
            }
        else
            vec1[i] = std::nullopt;
    }

    auto vt = cast_intrusive<VectorType>(std::move(t));
    auto old_v1 = v1;
    v1 = new VectorVal(std::move(vt), &vec1);
    Unref(old_v1);
}

} // namespace zeek::detail
