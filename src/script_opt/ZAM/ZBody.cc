// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Desc.h"
#include "zeek/RE.h"
#include "zeek/Frame.h"
#include "zeek/EventHandler.h"
#include "zeek/Trigger.h"
#include "zeek/Traverse.h"
#include "zeek/Overflow.h"
#include "zeek/Reporter.h"
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


namespace zeek::detail {

using std::vector;

static bool did_init = false;

// Count of how often each type of ZOP executed, and how much CPU it
// cumulatively took.
int ZOP_count[OP_NOP+1];
double ZOP_CPU[OP_NOP+1];


void report_ZOP_profile()
	{
	for ( int i = 1; i <= OP_NOP; ++i )
		if ( ZOP_count[i] > 0 )
			printf("%s\t%d\t%.06f\n", ZOP_name(ZOp(i)),
			       ZOP_count[i], ZOP_CPU[i]);
	}


// Sets the given element to a copy of an existing (not newly constructed)
// ZVal, including underlying memory management.  Returns false if the
// assigned value was missing (which we can only tell for managed types),
// true otherwise.

static bool copy_vec_elem(VectorVal* vv, int ind, ZVal zv, const TypePtr& t)
	{
	if ( vv->Size() <= ind )
		vv->Resize(ind + 1);

	auto& elem = (*vv->RawVec())[ind];

	if ( ! ZVal::IsManagedType(t) )
		{
		elem = zv;
		return true;
		}

	if ( elem )
		ZVal::DeleteManagedType(*elem);

	elem = zv;
	auto managed_elem = elem->ManagedVal();

	if ( ! managed_elem )
		{
		elem = std::nullopt;
		return false;
		}

	zeek::Ref(managed_elem);
	return true;
	}

// Unary and binary element-by-element vector operations, yielding a new
// VectorVal with a yield type of 't'.  'z' is passed in only for localizing
// errors.
static void vec_exec(ZOp op, TypePtr t, VectorVal*& v1, const VectorVal* v2,
                     const ZInst& z);

static void vec_exec(ZOp op, TypePtr t, VectorVal*& v1, const VectorVal* v2,
                     const VectorVal* v3, const ZInst& z);

// Vector coercion.
#define VEC_COERCE(tag, lhs_type, cast, rhs_accessor, ov_check, ov_err) \
	static VectorVal* vec_coerce_##tag(VectorVal* vec, const ZInst& z) \
		{ \
		auto& v = *vec->RawVec(); \
		auto yt = make_intrusive<VectorType>(base_type(lhs_type)); \
		auto res_zv = new VectorVal(yt); \
		auto n = v.size(); \
		res_zv->Resize(n); \
		auto& res = *res_zv->RawVec(); \
		for ( auto i = 0U; i < n; ++i ) \
			if ( v[i] ) \
				{ \
				auto vi = (*v[i]).rhs_accessor; \
				if ( ov_check(vi) ) \
					{ \
					std::string err = "overflow promoting from "; \
					err += ov_err; \
					err += " arithmetic value"; \
					ZAM_run_time_error(z.loc, err.c_str()); \
					res[i] = std::nullopt; \
					} \
				else \
					res[i] = ZVal(cast(vi)); \
				} \
			else \
				res[i] = std::nullopt; \
		return res_zv; \
		}

#define false_func(x) false

VEC_COERCE(DI, TYPE_DOUBLE, double, AsInt(), false_func, "")
VEC_COERCE(DU, TYPE_DOUBLE, double, AsCount(), false_func, "")
VEC_COERCE(ID, TYPE_INT, bro_int_t, AsDouble(), double_to_int_would_overflow, "double to signed")
VEC_COERCE(IU, TYPE_INT, bro_int_t, AsCount(), count_to_int_would_overflow, "unsigned to signed")
VEC_COERCE(UD, TYPE_COUNT, bro_uint_t, AsDouble(), double_to_count_would_overflow, "double to unsigned")
VEC_COERCE(UI, TYPE_COUNT, bro_int_t, AsInt(), int_to_count_would_overflow, "signed to unsigned")

double curr_CPU_time()
	{
	struct timespec ts;
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
	return double(ts.tv_sec) + double(ts.tv_nsec) / 1e9;
	}


ZBody::ZBody(const char* _func_name, const ZAMCompiler* zc)
: Stmt(STMT_ZAM)
	{
	func_name = _func_name;

	frame_denizens = zc->FrameDenizens();
	frame_size = frame_denizens.size();

	// Concretize the names of the frame denizens.
	for ( auto& f : frame_denizens )
		for ( auto& id : f.ids )
			f.names.push_back(id->Name());

	managed_slots = zc->ManagedSlots();

	globals = zc->Globals();
	num_globals = globals.size();

	int_cases = zc->GetCases<bro_int_t>();
	uint_cases = zc->GetCases<bro_uint_t>();
	double_cases = zc->GetCases<double>();
	str_cases = zc->GetCases<std::string>();

	if ( zc->NonRecursive() )
		{
		fixed_frame = new ZVal[frame_size];

		for ( auto& ms : managed_slots )
			fixed_frame[ms].ClearManagedVal();
		}

	table_iters = zc->GetTableIters();
	num_step_iters = zc->NumStepIters();

	// It's a little weird doing this in the constructor, but unless
	// we add a general "initialize for ZAM" function, this is as good
	// a place as any.
	if ( ! did_init )
		{
		auto log_ID_type = lookup_ID("ID", "Log");
		ASSERT(log_ID_type);
		log_ID_enum_type = log_ID_type->GetType<EnumType>();

		any_base_type = base_type(TYPE_ANY);

		ZVal::SetZValNilStatusAddr(&ZAM_error);

		did_init = false;
		}
	}

ZBody::~ZBody()
	{
	delete[] fixed_frame;
	delete[] insts;
	delete inst_count;
	delete CPU_time;
	}

void ZBody::SetInsts(vector<ZInst*>& _insts)
	{
	ninst = _insts.size();
	auto insts_copy = new ZInst[ninst];

	for ( auto i = 0U; i < ninst; ++i )
		insts_copy[i] = *_insts[i];

	insts = insts_copy;

	InitProfile();
	}

void ZBody::SetInsts(vector<ZInstI*>& instsI)
	{
	ninst = instsI.size();
	auto insts_copy = new ZInst[ninst];

	for ( auto i = 0U; i < ninst; ++i )
		{
		auto& iI = *instsI[i];
		insts_copy[i] = iI;
		if ( iI.stmt )
			insts_copy[i].loc = iI.stmt->Original()->GetLocationInfo();
		}

	insts = insts_copy;

	InitProfile();
	}

void ZBody::InitProfile()
	{
	if ( analysis_options.profile_ZAM )
		{
		inst_count = new vector<int>;
		inst_CPU = new vector<double>;
		for ( auto i = 0U; i < ninst; ++i )
			{
			inst_count->push_back(0);
			inst_CPU->push_back(0.0);
			}

		CPU_time = new double;
		*CPU_time = 0.0;
		}
	}

ValPtr ZBody::Exec(Frame* f, StmtFlowType& flow)
	{
#ifdef DEBUG
	double t = analysis_options.profile_ZAM ? curr_CPU_time() : 0.0;
#endif

	auto val = DoExec(f, 0, flow);

#ifdef DEBUG
	if ( analysis_options.profile_ZAM )
		*CPU_time += curr_CPU_time() - t;
#endif

	return val;
	}

ValPtr ZBody::DoExec(Frame* f, int start_pc, StmtFlowType& flow)
	{
	int pc = start_pc;
	const int end_pc = ninst;

	// Return value, or nil if none.
	const ZVal* ret_u;

	// Type of the return value.  If nil, then we don't have a value.
	TypePtr ret_type;

#ifdef DEBUG
	bool do_profile = analysis_options.profile_ZAM;
#endif

	ZVal* frame;
	std::unique_ptr<TableIterVec> local_table_iters;
	std::vector<StepIterInfo> step_iters(num_step_iters);

	if ( fixed_frame )
		frame = fixed_frame;
	else
		{
		frame = new ZVal[frame_size];
		// Clear slots for which we do explicit memory management.
		for ( auto s : managed_slots )
			frame[s].ClearManagedVal();

		if ( ! table_iters.empty() )
			{
			local_table_iters =
			    std::make_unique<TableIterVec>(table_iters.size());
			*local_table_iters = table_iters;
			tiv_ptr = &(*local_table_iters);
			}
		}

	flow = FLOW_RETURN;	// can be over-written by a Hook-Break

	while ( pc < end_pc && ! ZAM_error )
		{
		auto& z = insts[pc];

#ifdef DEBUG
		int profile_pc;
		double profile_CPU;

		if ( do_profile )
			{
			++ZOP_count[z.op];
			++(*inst_count)[pc];

			profile_pc = pc;
			profile_CPU = curr_CPU_time();
			}
#endif

		switch ( z.op ) {
		case OP_NOP:
			break;

#include "ZAM-EvalMacros.h"
#include "ZAM-EvalDefs.h"

		default:
			reporter->InternalError("bad ZAM opcode");
		}

#ifdef DEBUG
		if ( do_profile )
			{
			double dt = curr_CPU_time() - profile_CPU;
			inst_CPU->at(profile_pc) += dt;
			ZOP_CPU[z.op] += dt;
			}
#endif

		++pc;
		}

	auto result = ret_type ? ret_u->ToVal(ret_type) : nullptr;

	if ( fixed_frame )
		{
		// Make sure we don't have any dangling iterators.
		for ( auto& ti : table_iters )
			ti.Clear();

		// Free slots for which we do explicit memory management,
		// preparing them for reuse.
		for ( auto& ms : managed_slots )
			{
			auto& v = frame[ms];
			ZVal::DeleteManagedType(v);
			v.ClearManagedVal();
			}
		}
	else
		{
		// Free those slots for which we do explicit memory management.
		// No need to then clear them, as we're about to throw away
		// the entire frame.
		for ( auto& ms : managed_slots )
			{
			auto& v = frame[ms];
			ZVal::DeleteManagedType(v);
			}

		delete [] frame;
		}

	// Clear any error state.
	ZAM_error = false;

	return result;
	}

void ZBody::ProfileExecution() const
	{
	if ( inst_count->empty() )
		{
		printf("%s has an empty body\n", func_name);
		return;
		}

	if ( (*inst_count)[0] == 0 )
		{
		printf("%s did not execute\n", func_name);
		return;
		}

	printf("%s CPU time: %.06f\n", func_name, *CPU_time);

	for ( auto i = 0U; i < inst_count->size(); ++i )
		{
		printf("%s %d %d %.06f ", func_name, i,
		       (*inst_count)[i], (*inst_CPU)[i]);
		insts[i].Dump(i, &frame_denizens);
		}
	}

bool ZBody::CheckAnyType(const TypePtr& any_type, const TypePtr& expected_type,
                         const Location* loc) const
	{
	if ( IsAny(expected_type) )
		return true;

	if ( ! same_type(any_type, expected_type, false, false) )
		{
		auto at = any_type->Tag();
		auto et = expected_type->Tag();

		if ( at == TYPE_RECORD && et == TYPE_RECORD )
			{
			auto at_r = any_type->AsRecordType();
			auto et_r = expected_type->AsRecordType();

			if ( record_promotion_compatible(et_r, at_r) )
				return true;
			}

		char buf[8192];
		snprintf(buf, sizeof buf, "run-time type clash (%s/%s)",
		         type_name(at), type_name(et));

		reporter->RuntimeError(loc, "%s", buf);
		return false;
		}

	return true;
	}

void ZBody::Dump() const
	{
	printf("Frame:\n");

	for ( unsigned i = 0; i < frame_denizens.size(); ++i )
		{
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

	for ( unsigned i = 0; i < ninst; ++i )
		{
		auto& inst = insts[i];
		printf("%d: ", i);
		inst.Dump(i, &frame_denizens);
		}
	}

void ZBody::StmtDescribe(ODesc* d) const
	{
	d->AddSP("ZAM-code");
	d->AddSP(func_name);
	}

TraversalCode ZBody::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}


ValPtr ZAMResumption::Exec(Frame* f, StmtFlowType& flow)
	{
	return am->DoExec(f, xfer_pc, flow);
	}

void ZAMResumption::StmtDescribe(ODesc* d) const
	{
	d->Add("<resumption of compiled code>");
	}

TraversalCode ZAMResumption::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}


// Unary vector operation of v1 <vec-op> v2.
static void vec_exec(ZOp op, TypePtr t, VectorVal*& v1, const VectorVal* v2,
                     const ZInst& z)
	{
	// We could speed this up further still by gen'ing up an instance
	// of the loop inside each switch case (in which case we might as
	// well move the whole kit-and-caboodle into the Exec method).  But
	// that seems like a lot of code bloat for only a very modest gain.

	auto& vec2 = *v2->RawVec();
	auto n = vec2.size();
	auto vec1_ptr = new vector<std::optional<ZVal>>(n);
	auto& vec1 = *vec1_ptr;

	for ( auto i = 0U; i < n; ++i )
		{
		if ( vec2[i] )
			switch ( op ) {

#include "ZAM-Vec1EvalDefs.h"

			default:
				reporter->InternalError("bad invocation of VecExec");
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
static void vec_exec(ZOp op, TypePtr t, VectorVal*& v1,
                     const VectorVal* v2, const VectorVal* v3, const ZInst& z)
	{
	// See comment above re further speed-up.

	auto& vec2 = *v2->RawVec();
	auto& vec3 = *v3->RawVec();
	auto n = vec2.size();
	auto vec1_ptr = new vector<std::optional<ZVal>>(n);
	auto& vec1 = *vec1_ptr;

	for ( auto i = 0U; i < vec2.size(); ++i )
		{
		if ( vec2[i] && vec3[i] )
			switch ( op ) {

#include "ZAM-Vec2EvalDefs.h"

			default:
				reporter->InternalError("bad invocation of VecExec");
			}
		else
			vec1[i] = std::nullopt;
		}

	auto vt = cast_intrusive<VectorType>(std::move(t));
	auto old_v1 = v1;
	v1 = new VectorVal(std::move(vt), vec1_ptr);
	Unref(old_v1);
	}

} // zeek::detail
