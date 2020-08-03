// See the file "COPYING" in the main distribution directory for copyright.

#include "ZBody.h"
#include "ScriptAnaly.h"
#include "Desc.h"
#include "RE.h"
#include "Frame.h"
#include "Trigger.h"
#include "Traverse.h"
#include "Reporter.h"

// Needed for managing the corresponding values.
#include "File.h"
#include "Func.h"
#include "OpaqueVal.h"

// Just needed for BiFs.
#include "Net.h"
#include "logging/Manager.h"
#include "broker/Manager.h"


BroType* log_ID_enum_type;


// Count of how often each top of ZOP executed, and how much CPU it
// cumulatively took.
int ZOP_count[OP_NOP+1];
double ZOP_CPU[OP_NOP+1];

// Per-interpreted-expression.
std::unordered_map<const Expr*, double> expr_CPU;


// The dynamic state of a global.  Used to construct an array indexed in
// parallel with the globals[] array, which tracks the associated static
// information.
typedef enum {
	GS_UNLOADED,	// global hasn't been loaded
	GS_CLEAN,	// global has been loaded but not modified
	GS_DIRTY,	// loaded-and-modified
} GlobalState;


void report_ZOP_profile()
	{
	for ( int i = 1; i <= OP_NOP; ++i )
		if ( ZOP_count[i] > 0 )
			printf("%s\t%d\t%.06f\n", ZOP_name(ZOp(i)),
				ZOP_count[i], ZOP_CPU[i]);

	for ( auto& e : expr_CPU )
		printf("expr CPU %.06f %s\n", e.second, obj_desc(e.first));
	}


void ZAM_run_time_error(const Location* loc, const char* msg)
	{
	reporter->RuntimeError(loc, "%s", msg);
	ZAM_error = true;
	}

void ZAM_run_time_error(const char* msg, const BroObj* o)
	{
	fprintf(stderr, "%s: %s\n", msg, obj_desc(o));
	ZAM_error = true;
	}


// Unary vector operations never work on managed types, so no need
// to pass in the type ...  However, the RHS, which normally would
// be const, needs to be non-const so we can use its Type() method
// to get at a shareable VectorType.
static void vec_exec(ZOp op, VectorVal*& v1, VectorVal* v2);

// Binary ones *can* have managed types (strings).
static void vec_exec(ZOp op, BroType* t, VectorVal*& v1, VectorVal* v2,
			const VectorVal* v3);

// Vector coercion.
//
// ### Should check for underflow/overflow.
#define VEC_COERCE(tag, lhs_type, lhs_accessor, cast, rhs_accessor) \
	static VectorVal* vec_coerce_##tag(VectorVal* vec) \
		{ \
		auto& v = vec->RawVector()->ConstVec(); \
		auto yt = new VectorType(base_type(lhs_type)); \
		auto res_zv = new VectorVal(yt); \
		auto n = v.size(); \
		auto& res = res_zv->RawVector()->InitVec(n); \
		for ( unsigned int i = 0; i < n; ++i ) \
			res[i].lhs_accessor = cast(v[i].rhs_accessor); \
		return res_zv; \
		}

VEC_COERCE(IU, TYPE_INT, int_val, bro_int_t, uint_val)
VEC_COERCE(ID, TYPE_INT, int_val, bro_int_t, double_val)
VEC_COERCE(UI, TYPE_COUNT, uint_val, bro_int_t, int_val)
VEC_COERCE(UD, TYPE_COUNT, uint_val, bro_uint_t, double_val)
VEC_COERCE(DI, TYPE_DOUBLE, double_val, double, int_val)
VEC_COERCE(DU, TYPE_DOUBLE, double_val, double, uint_val)

double curr_CPU_time()
	{
	struct timespec ts;
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
	return double(ts.tv_sec) + double(ts.tv_nsec) / 1e9;
	}

StringVal* ZAM_to_lower(const StringVal* sv)
	{
	auto bs = sv->AsString();
	const u_char* s = bs->Bytes();
	int n = bs->Len();
	u_char* lower_s = new u_char[n + 1];
	u_char* ls = lower_s;

	for ( int i = 0; i < n; ++i )
		{
		if ( isascii(s[i]) && isupper(s[i]) )
			*ls++ = tolower(s[i]);
		else
			*ls++ = s[i];
		}

	*ls++ = '\0';
		
	return new StringVal(new BroString(1, lower_s, n));
	}

StringVal* ZAM_sub_bytes(const StringVal* s, bro_uint_t start, bro_int_t n)
	{
        if ( start > 0 )
                --start;        // make it 0-based

        BroString* ss = s->AsString()->GetSubstring(start, n);

	return new StringVal(ss ? ss : new BroString(""));
	}


ZBody::ZBody(const char* _func_name, vector<ZInstI*>& instsI,
		FrameReMap& _frame_denizens, std::vector<int>& _managed_slots,
		std::vector<GlobalInfo>& _globals, bool non_recursive,
		CaseMaps<bro_int_t>& _int_cases, 
		CaseMaps<bro_uint_t>& _uint_cases,
		CaseMaps<double>& _double_cases, 
		CaseMaps<std::string>& _str_cases)
: Stmt(STMT_COMPILED)
	{
	func_name = _func_name;

	for ( auto i : instsI )
		{
		insts.push_back(i);
		if ( i->stmt )
			insts.back()->loc =
				i->stmt->Original()->GetLocationInfo();
		}

	frame_denizens = _frame_denizens;
	frame_size = frame_denizens.size();

	managed_slots = _managed_slots;

	globals = _globals;
	num_globals = globals.size();

	int_cases = _int_cases;
	uint_cases = _uint_cases;
	double_cases = _double_cases;
	str_cases = _str_cases;

	if ( non_recursive )
		{
		fixed_frame = new ZAMValUnion[frame_size];

		for ( auto i = 0; i < managed_slots.size(); ++i )
			fixed_frame[managed_slots[i]].managed_val = nullptr;
		}

	if ( analysis_options.report_profile )
		{
		inst_count = new vector<int>;
		inst_CPU = new vector<double>;
		for ( auto i : insts )
			{
			inst_count->push_back(0);
			inst_CPU->push_back(0.0);
			}

		CPU_time = new double;
		*CPU_time = 0.0;
		}
	}

ZBody::~ZBody()
	{
	if ( fixed_frame )
		{
		// Free slots with explicit memory management.
		for ( auto i = 0; i < managed_slots.size(); ++i )
			{
			auto& v = fixed_frame[managed_slots[i]];
			DeleteManagedType(v, nullptr);
			}

		delete[] fixed_frame;
		}

	delete inst_count;
	delete CPU_time;
	}

IntrusivePtr<Val> ZBody::Exec(Frame* f, stmt_flow_type& flow) const
	{
	auto nv = num_Vals;
	auto ndv = num_del_Vals;

	double t = analysis_options.report_profile ? curr_CPU_time() : 0.0;

	auto val = DoExec(f, 0, flow);

	if ( analysis_options.report_profile )
		*CPU_time += curr_CPU_time() - t;

	auto dnv = num_Vals - nv;
	auto dndv = num_del_Vals - ndv;

	if ( /* dnv || dndv */ 0 )
		printf("%s vals: +%d -%d\n", func_name, dnv, dndv);

	return val;
	}

IntrusivePtr<Val> ZBody::DoExec(Frame* f, int start_pc,
						stmt_flow_type& flow) const
	{
	auto global_state = num_globals > 0 ? new GlobalState[num_globals] :
						nullptr;
	int pc = start_pc;
	int end_pc = insts.size();

#define BuildVal(v, t) ZAMValUnion(v, t)
#define CopyVal(v) (IsManagedType(z.t) ? BuildVal(v.ToVal(z.t), z.t) : v)

// Managed assignments to frame[s.v1].
#define AssignV1T(v, t) { \
	if ( z.is_managed ) \
		{ \
		/* It's important to hold a reference to v here prior \
		   to the deletion in case frame[z.v1] points to v. */ \
		auto v2 = v; \
		DeleteManagedType(frame[z.v1], t); \
		frame[z.v1] = v2; \
		} \
	else \
		frame[z.v1] = v; \
	}

#define AssignV1(v) AssignV1T(v, z.t)

	// Return value, or nil if none.
	const ZAMValUnion* ret_u;

	// Type of the return value.  If nil, then we don't have a value.
	BroType* ret_type = nullptr;

	bool do_profile = analysis_options.report_profile;

	// All globals start out unloaded.
	for ( auto i = 0; i < num_globals; ++i )
		global_state[i] = GS_UNLOADED;

	ZAMValUnion* frame;

	if ( fixed_frame )
		frame = fixed_frame;
	else
		{
		frame = new ZAMValUnion[frame_size];
		// Clear slots for which we do explicit memory management.
		for ( auto s : managed_slots )
			frame[s].managed_val = nullptr;
		}

	flow = FLOW_RETURN;	// can be over-written by a Hook-Break

	while ( pc < end_pc && ! ZAM_error ) {
		auto& z = *insts[pc];

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

#include "ZAM-OpsEvalDefs.h"
		}

#ifdef DEBUG
		if ( do_profile )
			{
			double dt = curr_CPU_time() - profile_CPU;
			(*inst_CPU)[profile_pc] += dt;
			ZOP_CPU[z.op] += dt;
			}
#endif

		++pc;
		}

	auto result = ret_type ? ret_u->ToVal(ret_type) : nullptr;

	if ( ! fixed_frame )
		{
		// Free those slots for which we do explicit memory management.
		for ( auto i = 0; i < managed_slots.size(); ++i )
			{
			auto& v = frame[managed_slots[i]];
			DeleteManagedType(v, nullptr);
			}

		delete [] frame;
		}

	delete [] global_state;

	// Clear any error state.
	ZAM_error = false;

	return result;
	}

void ZBody::SaveTo(FILE* f) const
	{
	// Collect all of the types that will be required.

	std::vector<const BroType*> types;
	std::unordered_map<const BroType*, int> type_map;	// inverse

	for ( auto i : insts )
		{
		if ( i->t && type_map.count(i->t) == 0 )
			{
			types.push_back(i->t);
			type_map[i->t] = types.size();
			}

		if ( i->t2 && type_map.count(i->t2) == 0 )
			{
			types.push_back(i->t2);
			type_map[i->t2] = types.size();
			}
		}

	fprintf(f, "<ZAM-file>\n");

	if ( types.size() > 0 )
		{
		fprintf(f, "types {\n");
		for ( auto t : types )
			{
			ODesc d;
			DescribeType(t, &d);
			fprintf(f, "%s,\n", d.Description());
			}

		fprintf(f, "}");
		}
	}

void ZBody::ProfileExecution() const
	{
	if ( inst_count->size() == 0 )
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

	for ( int i = 0; i < inst_count->size(); ++i )
		{
		printf("%s %d %d %.06f ", func_name, i,
			(*inst_count)[i], (*inst_CPU)[i]);
		insts[i]->Dump(i, &frame_denizens);
		}
	}

void ZBody::DescribeType(const BroType* t, ODesc* d) const
	{
	auto t_name = t->GetName();

	if ( t_name.length() > 0 )
		{
		// Always prefer to use a type name.
		d->Add(t_name.c_str());
		return;
		}

	switch ( t->Tag() ) {
	case TYPE_VOID:
	case TYPE_BOOL:
	case TYPE_INT:
	case TYPE_COUNT:
	case TYPE_COUNTER:
	case TYPE_DOUBLE:
	case TYPE_TIME:
	case TYPE_INTERVAL:
	case TYPE_STRING:
	case TYPE_PATTERN:
	case TYPE_TIMER:
	case TYPE_PORT:
	case TYPE_ADDR:
	case TYPE_SUBNET:
	case TYPE_ANY:
	case TYPE_ERROR:
		t->Describe(d);
		break;

	case TYPE_ENUM:
		reporter->InternalError("enum type without a name");
		break;

	case TYPE_TYPE:
		// d->AddSP("type");
		DescribeType(t->AsTypeType()->Type(), d);
		break;

	case TYPE_TABLE:
		{
		auto tbl = t->AsTableType();
		auto yt = tbl->YieldType();

		if ( yt )
			d->Add("table[");
		else
			d->Add("set[");

		DescribeType(tbl->Indices(), d);

		d->Add("]");

		if ( yt )
			{
			d->Add(" of ");
			DescribeType(yt, d);
			}
		break;
		}

	case TYPE_FUNC:
		{
		auto f = t->AsFuncType();

		d->Add(f->FlavorString());
		d->Add("(");

		auto args = f->Args();
		int n = args->NumFields();

		for ( auto i = 0; i < n; ++i )
			{
			d->Add(args->FieldName(i));
			d->AddSP(":");

			DescribeType(args->FieldType(i), d);

			if ( i < n - 1 )
				d->AddSP(",");
			}

		d->Add(")");
		auto yt = f->YieldType();

		if ( f->Flavor() == FUNC_FLAVOR_FUNCTION &&
		     yt && yt->Tag() != TYPE_VOID )
			{
			d->AddSP(":");
			DescribeType(yt, d);
			}

		break;
		}

	case TYPE_RECORD:
		{
		auto rt = t->AsRecordType();
		int n = rt->NumFields();

		d->Add("record { ");

		for ( auto i = 0; i < n; ++i )
			{
			d->Add(rt->FieldName(i));
			d->AddSP(":");

			DescribeType(rt->FieldType(i), d);
			d->AddSP(";");
			}

		d->Add("}");
		break;
		}

	case TYPE_LIST:
		{
		auto l = t->AsTypeList()->Types();
		int n = l->length();

		for ( auto i = 0; i < n; ++i )
			{
			DescribeType((*l)[i], d);
			if ( i < n - 1 )
				d->AddSP(",");
			}

		break;
		}

	case TYPE_VECTOR:
	case TYPE_FILE:
		d->Add(type_name(t->Tag()));
		d->Add(" of ");
		DescribeType(t->YieldType(), d);
		break;

	case TYPE_OPAQUE:
		d->Add("opaque of ");
		d->Add(t->AsOpaqueType()->Name());
		break;

	case TYPE_UNION:
		reporter->InternalError("union type in ZBody::DescribeType()");
	}
	}

bool ZBody::CheckAnyType(const BroType* any_type, const BroType* expected_type,
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

void ZBody::Dump()
	{
	printf("Frame:\n");

	for ( auto i = 0; i < frame_denizens.size(); ++i )
		{
		printf("frame[%d] =", i);
		for ( auto& id : frame_denizens[i].ids )
			printf(" %s", id->Name());
		printf("\n");
		}

	printf("Final code:\n");

	for ( int i = 0; i < insts.size(); ++i )
		{
		auto& inst = insts[i];
		printf("%d: ", i);
		inst->Dump(i, &frame_denizens);
		}

#if 0
	for ( int i = 0; i < int_casesI.size(); ++i )
		DumpIntCases(i);
	for ( int i = 0; i < uint_casesI.size(); ++i )
		DumpUIntCases(i);
	for ( int i = 0; i < double_casesI.size(); ++i )
		DumpDoubleCases(i);
	for ( int i = 0; i < str_casesI.size(); ++i )
		DumpStrCases(i);
#endif
	}

void ZBody::StmtDescribe(ODesc* d) const
	{
	d->AddSP("compiled");
	d->AddSP(func_name);
	}

TraversalCode ZBody::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}


IntrusivePtr<Val> ResumptionAM::Exec(Frame* f, stmt_flow_type& flow) const
	{
	return am->DoExec(f, xfer_pc, flow);
	}

void ResumptionAM::StmtDescribe(ODesc* d) const
	{
	d->Add("resumption of compiled code");
	}

TraversalCode ResumptionAM::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}


// Unary vector operation of v1 <vec-op> v2.
static void vec_exec(ZOp op, VectorVal*& v1, VectorVal* v2)
	{
	// We could speed this up further still by gen'ing up an
	// instance of the loop inside each switch case (in which
	// case we might as well move the whole kit-and-caboodle
	// into the Exec method).  But that seems like a lot of
	// code bloat for only a very modest gain.

	auto old_v1 = v1;
	auto& vec2 = v2->RawVector()->ConstVec();
	auto vt = v2->Type()->AsVectorType();

	::Ref(vt);
	v1 = new VectorVal(vt);

	v1->RawVector()->Resize(vec2.size());

	auto& vec1 = v1->RawVector()->ModVec();

	for ( unsigned int i = 0; i < vec2.size(); ++i )
		switch ( op ) {

#include "ZAM-Vec1EvalDefs.h"

		default:
			reporter->InternalError("bad invocation of VecExec");
		}

	Unref(old_v1);
	}

// Binary vector operation of v1 = v2 <vec-op> v3.
static void vec_exec(ZOp op, BroType* yt, VectorVal*& v1,
			VectorVal* v2, const VectorVal* v3)
	{
	// See comment above re further speed-up.

	auto old_v1 = v1;
	auto& vec2 = v2->RawVector()->ConstVec();
	auto& vec3 = v3->RawVector()->ConstVec();

	IntrusivePtr<BroType> yt_ptr = {NewRef{}, yt};
	auto vt = new VectorType(yt_ptr);
	v1 = new VectorVal(vt);

	v1->RawVector()->Resize(vec2.size());

	auto& vec1 = v1->RawVector()->ModVec();

	for ( unsigned int i = 0; i < vec2.size(); ++i )
		switch ( op ) {

#include "ZAM-Vec2EvalDefs.h"

		default:
			reporter->InternalError("bad invocation of VecExec");
		}

	Unref(old_v1);
	}
