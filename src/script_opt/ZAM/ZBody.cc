// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/ZAM/ZBody.h"

#include "zeek/Desc.h"
#include "zeek/EventHandler.h"
#include "zeek/Frame.h"
#include "zeek/Overflow.h"
#include "zeek/RE.h"
#include "zeek/Reporter.h"
#include "zeek/Traverse.h"
#include "zeek/Trigger.h"
#include "zeek/script_opt/ScriptOpt.h"
#include "zeek/script_opt/ZAM/Compile.h"

// Needed for managing the corresponding values.
#include "zeek/File.h"
#include "zeek/Func.h"
#include "zeek/OpaqueVal.h"

// Just needed for BiFs.
#include "zeek/analyzer/Manager.h"
#include "zeek/broker/Manager.h"
#include "zeek/file_analysis/Manager.h"
#include "zeek/logging/Manager.h"
#include "zeek/packet_analysis/Manager.h"

// For reading_live and reading_traces
#include "zeek/RunState.h"

namespace zeek::detail {

#ifdef ENABLE_ZAM_PROFILE

static std::vector<std::shared_ptr<ZAMLocInfo>> caller_locs;
static std::vector<bool> caller_prof;

static double compute_prof_overhead() {
    double start = util::curr_CPU_time();
    double CPU = 0.0;
    const int n = 100000;
    for ( int i = 0; i < n; ++i )
        CPU = std::max(CPU, util::curr_CPU_time());

    return (CPU - start) / n;
}

static double prof_overhead = compute_prof_overhead();

#define DO_ZAM_PROFILE                                                                                                 \
    if ( do_profile ) {                                                                                                \
        double dt = util::curr_CPU_time() - profile_CPU;                                                               \
        auto& prof_info = (*curr_prof_vec)[profile_pc];                                                                \
        ++prof_info.first;                                                                                             \
        prof_info.second += dt;                                                                                        \
        ZOP_CPU[z.op] += dt;                                                                                           \
    }
#define ZAM_PROFILE_PRE_CALL                                                                                           \
    if ( analysis_options.profile_ZAM ) {                                                                              \
        caller_locs.push_back(z.loc);                                                                                  \
        caller_prof.push_back(do_profile);                                                                             \
    }                                                                                                                  \
    if ( ! z.aux->is_BiF_call ) { /* For non-BiFs we don't include the callee's execution time as part of our own */   \
        DO_ZAM_PROFILE                                                                                                 \
    }

#define ZAM_PROFILE_POST_CALL                                                                                          \
    if ( analysis_options.profile_ZAM ) {                                                                              \
        caller_locs.pop_back();                                                                                        \
        caller_prof.pop_back();                                                                                        \
    }                                                                                                                  \
    if ( ! z.aux->is_BiF_call ) { /* We already did the profiling, move on to next instruction */                      \
        ++pc;                                                                                                          \
        continue;                                                                                                      \
    }

#else

#define DO_ZAM_PROFILE
#define ZAM_PROFILE_PRE_CALL
#define ZAM_PROFILE_POST_CALL
static double prof_overhead = 0.0;

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
        fprintf(analysis_options.profile_file, "Profile sampled every %d calls\n",
                analysis_options.profile_sampling_rate);
        fprintf(analysis_options.profile_file, "Profiling overhead = %.0f nsec/instruction\n", prof_overhead * 1e9);
        did_overhead_report = true;
    }

    for ( int i = 1; i <= OP_NOP; ++i )
        if ( ZOP_count[i] > 0 ) {
            auto CPU = std::max(ZOP_CPU[i] - ZOP_count[i] * prof_overhead, 0.0);
            fprintf(analysis_options.profile_file, "%s\t%d\t%.06f\n", ZOP_name(ZOp(i)), ZOP_count[i], CPU);
        }
}

// Sets the given element to a copy of an existing (not newly constructed)
// ZVal, including underlying memory management.  Returns false if the
// assigned value was missing (which we can only tell for managed types),
// true otherwise.

static bool copy_vec_elem(VectorVal* vv, zeek_uint_t ind, ZVal zv, const TypePtr& t) {
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

// Vector coercion.
#define VEC_COERCE(tag, lhs_type, cast, rhs_accessor, ov_check, ov_err)                                                \
    static VectorVal* vec_coerce_##tag(VectorVal* vec, const ZInst& z) {                                               \
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
                    err += ov_err;                                                                                     \
                    err += " arithmetic value";                                                                        \
                    ZAM_run_time_error(z.loc, err.c_str());                                                            \
                    res[i] = std::nullopt;                                                                             \
                }                                                                                                      \
                else                                                                                                   \
                    res[i] = ZVal(cast(vi));                                                                           \
            }                                                                                                          \
            else                                                                                                       \
                res[i] = std::nullopt;                                                                                 \
        return res_zv;                                                                                                 \
    }

#define false_func(x) false

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
        log_ID_enum_type = log_ID_type->GetType<EnumType>();

        any_base_type = base_type(TYPE_ANY);

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
    if ( analysis_options.profile_ZAM )
        curr_prof_vec = default_prof_vec = BuildProfVec();
}

std::shared_ptr<ProfVec> ZBody::BuildProfVec() const {
    auto pv = std::make_shared<ProfVec>();
    pv->resize(end_pc);

    for ( auto i = 0U; i < end_pc; ++i )
        (*pv)[i] = std::pair<zeek_uint_t, double>{0, 0.0};

    return pv;
}

ValPtr ZBody::Exec(Frame* f, StmtFlowType& flow) {
    unsigned int pc = 0;

    // Return value, or nil if none.
    const ZVal* ret_u = nullptr;

    // Type of the return value.  If nil, then we don't have a value.
    TypePtr ret_type;

#ifdef ENABLE_ZAM_PROFILE
    bool do_profile;
    double start_CPU_time;

    if ( analysis_options.profile_ZAM ) {
        if ( caller_prof.empty() ) {
            static auto seed = util::detail::random_number();
            seed = util::detail::prng(seed);
            do_profile = seed % analysis_options.profile_sampling_rate == 0;
        }
        else
            do_profile = caller_prof.back();

        if ( do_profile ) {
            start_CPU_time = util::curr_CPU_time();

            if ( caller_locs.empty() )
                curr_prof_vec = default_prof_vec;
            else {
                auto pv = prof_vecs.find(caller_locs);
                if ( pv == prof_vecs.end() )
                    pv = prof_vecs.insert({caller_locs, BuildProfVec()}).first;
                curr_prof_vec = pv->second;
            }
        }
    }
    else
        do_profile = false;
#endif

    ZVal* frame;
    std::unique_ptr<TableIterVec> local_table_iters;
    std::vector<StepIterInfo> step_iters(num_step_iters);

    if ( fixed_frame )
        frame = fixed_frame;
    else {
        frame = new ZVal[frame_size];
        // Clear slots for which we do explicit memory management.
        for ( auto s : managed_slots )
            frame[s].ClearManagedVal();

        if ( ! table_iters.empty() ) {
            local_table_iters = std::make_unique<TableIterVec>(table_iters.size());
            *local_table_iters = table_iters;
            tiv_ptr = &(*local_table_iters);
        }
    }

    flow = FLOW_RETURN; // can be over-written by a Hook-Break

    // Clear any leftover error state.
    ZAM_error = false;

    while ( pc < end_pc && ! ZAM_error ) {
        auto& z = insts[pc];

#ifdef ENABLE_ZAM_PROFILE
        int profile_pc = 0;
        double profile_CPU = 0.0;

        if ( do_profile ) {
            ++ZOP_count[z.op];
            ++ninst;

            profile_pc = pc;
            profile_CPU = util::curr_CPU_time();
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

    auto result = ret_type ? ret_u->ToVal(ret_type) : nullptr;

    if ( fixed_frame ) {
        // Make sure we don't have any dangling iterators.
        for ( auto& ti : table_iters )
            ti.Clear();

        // Free slots for which we do explicit memory management,
        // preparing them for reuse.
        for ( auto& ms : managed_slots ) {
            auto& v = frame[ms];
            ZVal::DeleteManagedType(v);
            v.ClearManagedVal();
        }
    }
    else {
        // Free those slots for which we do explicit memory management.
        // No need to then clear them, as we're about to throw away
        // the entire frame.
        for ( auto& ms : managed_slots ) {
            auto& v = frame[ms];
            ZVal::DeleteManagedType(v);
        }

        delete[] frame;
    }

#ifdef ENABLE_ZAM_PROFILE
    if ( do_profile )
        tot_CPU_time += util::curr_CPU_time() - start_CPU_time;
#endif

    return result;
}

void ZBody::ProfileExecution(ProfMap& pm) {
    static bool did_overhead_report = false;

    if ( end_pc == 0 ) {
        fprintf(analysis_options.profile_file, "%s has an empty body\n", func_name.c_str());
        return;
    }

    auto& dpv = *default_prof_vec;

    if ( dpv[0].first == 0 && prof_vecs.empty() ) {
        fprintf(analysis_options.profile_file, "%s did not execute\n", func_name.c_str());
        return;
    }

    int ncall = dpv[0].first;
    double CPU = dpv[0].second;
    for ( auto [_, pv] : prof_vecs )
        ncall += (*pv)[0].first;

    double adj_CPU_time = std::max(tot_CPU_time - ncall * prof_overhead, 0.0);

    fprintf(analysis_options.profile_file, "%s CPU time %.06f, %d calls, %d instructions\n", func_name.c_str(),
            adj_CPU_time, ncall, ninst);

    if ( dpv[0].first != 0 )
        ReportProfile(pm, dpv, "", {});

    for ( auto& pv : prof_vecs ) {
        std::string prefix;
        std::set<std::string> modules;
        for ( auto& caller : pv.first ) {
            prefix += caller->Describe(true) + ";";
            caller->AddInModules(modules);
        }

        ReportProfile(pm, *pv.second, prefix, std::move(modules));
    }
}

void ZBody::ReportProfile(ProfMap& pm, const ProfVec& pv, const std::string& prefix,
                          std::set<std::string> caller_modules) const {
    for ( auto i = 0U; i < pv.size(); ++i ) {
        auto ninst = pv[i].first;
        auto CPU = pv[i].second;
        CPU = std::max(CPU - ninst * prof_overhead, 0.0);
        fprintf(analysis_options.profile_file, "%s %d %" PRId64 " %.06f ", func_name.c_str(), i, ninst, CPU);
        insts[i].Dump(analysis_options.profile_file, i, &frame_denizens, prefix);

        auto modules = caller_modules;
        insts[i].loc->AddInModules(modules);

        for ( auto& m : modules ) {
            auto mod_prof = pm.find(m);
            if ( mod_prof == pm.end() )
                pm[m] = std::pair<zeek_uint_t, double>{ninst, CPU};
            else {
                mod_prof->second.first += ninst;
                mod_prof->second.second += CPU;
            }
        }
    }
}

bool ZBody::CheckAnyType(const TypePtr& any_type, const TypePtr& expected_type,
                         const std::shared_ptr<ZAMLocInfo>& loc) const {
    if ( IsAny(expected_type) )
        return true;

    if ( ! same_type(any_type, expected_type, false, false) ) {
        auto at = any_type->Tag();
        auto et = expected_type->Tag();

        if ( at == TYPE_RECORD && et == TYPE_RECORD ) {
            auto at_r = any_type->AsRecordType();
            auto et_r = expected_type->AsRecordType();

            if ( record_promotion_compatible(et_r, at_r) )
                return true;
        }

        char buf[8192];
        snprintf(buf, sizeof buf, "run-time type clash (%s/%s)", type_name(at), type_name(et));

        reporter->RuntimeError(loc->Loc(), "%s", buf);
        return false;
    }

    return true;
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

    tc = cb->PostStmt(this);
    HANDLE_TC_STMT_POST(tc);
}

// Unary vector operation of v1 <vec-op> v2.
static void vec_exec(ZOp op, TypePtr t, VectorVal*& v1, const VectorVal* v2, const ZInst& z) {
    // We could speed this up further still by gen'ing up an instance
    // of the loop inside each switch case (in which case we might as
    // well move the whole kit-and-caboodle into the Exec method).  But
    // that seems like a lot of code bloat for only a very modest gain.

    auto& vec2 = v2->RawVec();
    auto n = vec2.size();
    auto vec1_ptr = new vector<std::optional<ZVal>>(n);
    auto& vec1 = *vec1_ptr;

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
    v1 = new VectorVal(std::move(vt), vec1_ptr);
    Unref(old_v1);
}

// Binary vector operation of v1 = v2 <vec-op> v3.
static void vec_exec(ZOp op, TypePtr t, VectorVal*& v1, const VectorVal* v2, const VectorVal* v3, const ZInst& z) {
    // See comment above re further speed-up.

    auto& vec2 = v2->RawVec();
    auto& vec3 = v3->RawVec();
    auto n = vec2.size();
    auto vec1_ptr = new vector<std::optional<ZVal>>(n);
    auto& vec1 = *vec1_ptr;

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
    v1 = new VectorVal(std::move(vt), vec1_ptr);
    Unref(old_v1);
}

} // namespace zeek::detail
