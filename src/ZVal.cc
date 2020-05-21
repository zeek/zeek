// See the file "COPYING" in the main distribution directory for copyright.

// Include ZAM.h, not ZVal.h, so we get ZAM_run_time_error.
#include "ZAM.h"

#include "OpaqueVal.h"
#include "BroString.h"
#include "File.h"
#include "Func.h"
#include "Reporter.h"


ZAM_tracker_type* curr_ZAM_VM_Tracker;


bool IsAny(const BroType* t)
	{
	return t->Tag() == TYPE_ANY;
	}

bool IsAnyVec(const BroType* t)
	{
	if ( t->Tag() != TYPE_VECTOR )
		return false;

	auto vt = t->AsVectorType();
	auto yt = vt->YieldType();

	return yt->Tag() == TYPE_ANY;
	}

bool IsManagedType(const BroType* t)
	{
	switch ( t->Tag() ) {
	case TYPE_ADDR:
	case TYPE_SUBNET:
	case TYPE_STRING:
		return true;

	case TYPE_VECTOR:
		return ! IsAny(t);

	default:
		return false;
	}
	}

void DeleteManagedType(ZAMValUnion& v, const BroType* t)
	{
	switch ( t->Tag() ) {
	case TYPE_ADDR:		delete v.addr_val; break;
	case TYPE_SUBNET:	delete v.subnet_val; break;
	case TYPE_STRING:	delete v.string_val; break;
	case TYPE_VECTOR:	delete v.vector_val; break;

	default:
		reporter->InternalError("type inconsistency in DeleteManagedType");
	}
	}


ZAMValUnion::ZAMValUnion(Val* v, BroType* t, ZAM_tracker_type* tracker,
				const BroObj* o, bool& error)
	{
	if ( ! v )
		{
		ZAM_run_time_error("uninitialized value in compiled code",
					o, error);
		int_val = 0;
		return;
		}

	auto vu = v->val;
	auto vt = v->Type();

	if ( vt->Tag() != t->Tag() && t->Tag() != TYPE_ANY )
		{
		if ( t->InternalType() == TYPE_INTERNAL_OTHER ||
		     t->InternalType() != vt->InternalType() )
			reporter->InternalError("type inconsistency in ZAMValUnion constructor");
		}

	switch ( t->Tag() ) {
	case TYPE_BOOL:
	case TYPE_INT:
	case TYPE_ENUM:
		int_val = vu.int_val;
		break;

	case TYPE_COUNT:
	case TYPE_COUNTER:
	case TYPE_PORT:
		uint_val = vu.uint_val;
		break;

	case TYPE_DOUBLE:
	case TYPE_INTERVAL:
	case TYPE_TIME:
		double_val = vu.double_val;
		break;

	case TYPE_FUNC:		func_val = vu.func_val; break;
	case TYPE_FILE:		file_val = vu.file_val; break;

	case TYPE_LIST:		list_val = v->AsListVal(); break;
	case TYPE_OPAQUE:	opaque_val = v->AsOpaqueVal(); break;
	case TYPE_PATTERN:	re_val = v->AsPatternVal(); break;
	case TYPE_RECORD:	record_val = v->AsRecordVal(); break;
	case TYPE_TABLE:	table_val = v->AsTableVal(); break;

	case TYPE_VECTOR:
		{
		auto my_ytag = t->AsVectorType()->YieldType()->Tag();
		auto v_ytag = vt->AsVectorType()->YieldType()->Tag();

		if ( my_ytag != v_ytag && my_ytag != TYPE_ANY &&
		     v_ytag != TYPE_ANY )
			{
			// Despite the above checks, this clash can still
			// happen thanks to the intercession of vector-of-any,
			// which for example can allow a function to return
			// a concrete vector-of-X that's assigned to a local
			// with a concrete vector-of-Y type.
			char msg[8192];
			snprintf(msg, sizeof msg, "vector type clash: %s vs. %s",
					type_name(my_ytag), type_name(v_ytag));
			ZAM_run_time_error(msg, o, error);
			vector_val = nullptr;
			}
		else
			vector_val = to_ZAM_vector(v, tracker, true);

		break;
		}

	case TYPE_STRING:
		string_val = new BroString(*v->AsString());
		break;

	case TYPE_ADDR:
		addr_val = new IPAddr(*vu.addr_val);
		break;

	case TYPE_SUBNET:
		subnet_val = new IPPrefix(*vu.subnet_val);
		break;

	case TYPE_ANY:		any_val = v; break;
	case TYPE_TYPE:		type_val = t; break;

	case TYPE_ERROR:
	case TYPE_TIMER:
	case TYPE_UNION:
	case TYPE_VOID:
		reporter->InternalError("bad type in ZAMValUnion constructor");
	}
	}

bool ZAMValUnion::IsNil(const BroType* t) const
	{
	switch ( t->Tag() ) {
	case TYPE_ADDR:		return ! addr_val;
	case TYPE_ANY:		return ! any_val;
	case TYPE_FILE:		return ! file_val;
	case TYPE_FUNC:		return ! func_val;
	case TYPE_LIST:		return ! list_val;
	case TYPE_OPAQUE:	return ! opaque_val;
	case TYPE_PATTERN:	return ! re_val;
	case TYPE_RECORD:	return ! record_val;
	case TYPE_STRING:	return ! string_val;
	case TYPE_SUBNET:	return ! subnet_val;
	case TYPE_TABLE:	return ! table_val;
	case TYPE_TYPE:		return ! type_val;

	default:	return false;
	}
	}

IntrusivePtr<Val> ZAMValUnion::ToVal(BroType* t) const
	{
	Val* v;

	switch ( t->Tag() ) {
	case TYPE_INT:		v = new Val(int_val, TYPE_INT); break;
	case TYPE_BOOL:		v = Val::MakeBool(int_val); break;
	case TYPE_COUNT:	v = new Val(uint_val, TYPE_COUNT); break;
	case TYPE_COUNTER:	v = new Val(uint_val, TYPE_COUNTER); break;
	case TYPE_DOUBLE:	v = new Val(double_val, TYPE_DOUBLE); break;
	case TYPE_INTERVAL:	v = new IntervalVal(double_val, 1.0); break;
	case TYPE_TIME:		v = new Val(double_val, TYPE_TIME); break;
	case TYPE_FUNC:		Ref(func_val); v = new Val(func_val); break;
	case TYPE_FILE:		Ref(file_val); v = new Val(file_val); break;
	case TYPE_ADDR:		v = new AddrVal(*addr_val); break;
	case TYPE_SUBNET:	v = new SubNetVal(*subnet_val); break;
	case TYPE_STRING:
		v = new StringVal(new BroString(*string_val));
		break;

	case TYPE_ENUM:		return t->AsEnumType()->GetVal(int_val);

	case TYPE_PORT:		v = val_mgr->GetPort(uint_val); break;

	case TYPE_VECTOR:	return ToVector(t);

	case TYPE_ANY:		return {NewRef{}, any_val};

	case TYPE_TYPE:		v = new Val(type_val, true); break;

	case TYPE_LIST:		v = list_val; v->Ref(); break;
	case TYPE_OPAQUE:	v = opaque_val; v->Ref(); break;
	case TYPE_RECORD:	v = record_val; v->Ref(); break;
	case TYPE_TABLE:	v = table_val; v->Ref(); break;
	case TYPE_PATTERN:	v = re_val; v->Ref(); break;

	case TYPE_ERROR:
	case TYPE_TIMER:
	case TYPE_UNION:
	case TYPE_VOID:
		reporter->InternalError("bad ret type return tag");
	}

	return {AdoptRef{}, v};
	}

IntrusivePtr<VectorVal> ZAMValUnion::ToVector(BroType* t) const
	{
	vector_val->Spill();

	auto v = vector_val->VecVal();

	if ( v )
		return v;

	// Need to create the vector.
	auto vt = t->AsVectorType();
	auto yt = vt->YieldType();

	auto& vec = *vector_val->ConstVec();
	int n = vec.size();

	auto actual_yt = vector_val->YieldType();
	if ( ! actual_yt )
		actual_yt = yt;

	auto is_any = actual_yt->Tag() == TYPE_ANY;

	v = make_intrusive<VectorVal>(vt);
	for ( int i = 0; i < n; ++i )
		{
		auto& vr = vec[i];

		if ( vr.IsNil(actual_yt) )
			continue;

		IntrusivePtr<Val> v_i;
		if ( is_any )
			v_i = {NewRef{}, vr.any_val};
		else
			v_i = vr.ToVal(actual_yt);

		v->Assign(i, v_i);
		}

	vector_val->SetVecVal(v.get());

	return v;
	}


ZAMVectorMgr::ZAMVectorMgr(std::shared_ptr<ZAM_vector> _vec, VectorVal* _v,
				ZAM_tracker_type* _tracker)
	{
	vec = _vec;
	v = _v;
	is_clean = true;

	if ( ! v )
		{
		yield_type = nullptr;
		tracker = nullptr;
		return;
		}

	Ref(v);

	tracker = _tracker;
	if ( tracker )
		tracker->insert(this);

	auto vt = v->Type()->AsVectorType();
	auto yt = vt->YieldType();

	if ( yt->Tag() == TYPE_ANY )
		{
		if ( v->Size() > 0 )
			{
			// If we use a bare 0 in the call to Lookup, effin'
			// C++ selects the Val* version of Lookup.  Geez.
			unsigned int zee_row = 0;
			auto elem0 = v->Lookup(zee_row);
			yt = elem0->Type();
			}
		else
			yt = nullptr;
		}

	yield_type = yt;
	}

ZAMVectorMgr::~ZAMVectorMgr()
	{
	if ( v )
		{
		if ( v->RefCnt() > 1 )
			// Don't bother spilling for a value we're about
			// to delete.
			Spill();

		if ( tracker )
			tracker->erase(this);
		}

	if ( v )
		Unref(v);
	}

void ZAMVectorMgr::Spill()
	{
	if ( ! v || is_clean )
		return;

	auto vt = v->Type()->AsVectorType();
	auto yt = vt->YieldType();
	auto val_vec = new vector<Val*>();

	for ( auto elem : *vec )
		{
		if ( elem.IsNil(yt) )
			val_vec->push_back(nullptr);
		else
			val_vec->push_back(elem.ToVal(yt).release());
		}

	delete v->val.vector_val;
	v->val.vector_val = val_vec;

	is_clean = true;
	}

void ZAMVectorMgr::Freshen()
	{
	ASSERT(is_clean);
	vec = to_raw_ZAM_vector(v, tracker);
	}


ZAMVectorMgr* to_ZAM_vector(Val* vec, ZAM_tracker_type* tracker, bool track_val)
	{
	auto raw = to_raw_ZAM_vector(vec, tracker);
	auto v = track_val ? vec->AsVectorVal() : nullptr;
	return new ZAMVectorMgr(raw, v, tracker);
	}

std::shared_ptr<ZAM_vector> to_raw_ZAM_vector(Val* vec, ZAM_tracker_type* trk)
	{
	auto v = vec->AsVector();
	auto t = vec->Type()->AsVectorType();
	auto yt = t->YieldType();

	auto raw = make_shared<ZAM_vector>();
	bool error;

	for ( auto elem : *v )
		if ( ! elem )
			// Zeek vectors can have holes.
			raw.get()->push_back(ZAMValUnion());
		else
			raw.get()->push_back(ZAMValUnion(elem, yt, trk, vec,
								error));

	return raw;
	}

void grow_vector(ZAM_vector& vec, int new_size)
	{
	int old_size = vec.size();
	vec.resize(new_size);

	for ( int i = old_size; i < new_size; ++i )
		// Strictly speaking, we should know the particular type of
		// vector and zero it accordingly.  We could get that
		// from the original vector_val's Val but geez.
		vec[i].void_val = nullptr;
	}
