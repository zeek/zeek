// See the file "COPYING" in the main distribution directory for copyright.

// Include ZAM.h, not ZVal.h, so we get ZAM_run_time_error.
#include "ZAM.h"

#include "OpaqueVal.h"
#include "BroString.h"
#include "File.h"
#include "Func.h"
#include "Reporter.h"


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
	case TYPE_ADDR:	
		delete v.addr_val; v.addr_val = nullptr; break;
	case TYPE_SUBNET:
		delete v.subnet_val; v.subnet_val = nullptr; break;
	case TYPE_STRING:
		delete v.string_val; v.string_val = nullptr; break;
	case TYPE_VECTOR:
		delete v.vector_val; v.vector_val = nullptr; break;

	default:
		reporter->InternalError("type inconsistency in DeleteManagedType");
	}
	}


ZAMValUnion::ZAMValUnion(Val* v, BroType* t, ZAMAggrBindings* bindings,
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
			vector_val = to_ZAM_vector(v, bindings, true);

		break;
		}

	case TYPE_RECORD:
		record_val = to_ZAM_record(v, bindings, true);
		break;

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
	case TYPE_RECORD:	return record_val->ToRecordVal();

	case TYPE_ANY:		return {NewRef{}, any_val};

	case TYPE_TYPE:		v = new Val(type_val, true); break;

	case TYPE_LIST:		v = list_val; v->Ref(); break;
	case TYPE_OPAQUE:	v = opaque_val; v->Ref(); break;
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

	auto& vec = vector_val->ConstVec();
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


void ZAM_vector::SetManagedElement(int n, ZAMValUnion& v)
	{
	auto& zn = zvec[n];

	DeleteManagedType(zn, managed_yt);

	switch ( managed_yt->Tag() ) {
	case TYPE_STRING:
		zn.string_val = new BroString(*v.string_val);
		break;

	case TYPE_ADDR:
		zn.addr_val = new IPAddr(*v.addr_val);
		break;

	case TYPE_SUBNET:
		zn.subnet_val = new IPPrefix(*v.subnet_val);
		break;

	case TYPE_VECTOR:
		zn.vector_val = v.vector_val->ShallowCopy();

	default:
		reporter->InternalError("bad type tag in ZAM_vector::SetManagedElement");
	}
	}

void ZAM_vector::GrowVector(int new_size)
	{
	int old_size = zvec.size();
	zvec.resize(new_size);

	for ( int i = old_size; i < new_size; ++i )
		// Strictly speaking, we should know the particular type of
		// vector and zero it accordingly.
		zvec[i].void_val = nullptr;
	}

void ZAM_vector::DeleteMembers()
	{
	for ( auto& z : zvec )
		DeleteManagedType(z, managed_yt);
	}

void ZAM_vector::Spill()
	{
	}

void ZAM_vector::Freshen()
	{
	ASSERT(! is_dirty);
	ASSERT(vv);

	if ( vv->AsVector() == this )
		// Association stands.
		return;

	vv = nullptr;

	EndAssociation();
	}


ZAM_record::ZAM_record(RecordVal* _v, RecordType* _rt,
			ZAMAggrBindings* _bindings)
	: ZAMAggrInstantiation(_v, _bindings, _rt->NumFields())
	{
	is_in_record = is_loaded = 0;

	rv = _v;
	rt = _rt;

	if ( rv )
		{
		Ref(rv);
		is_managed = rt->ManagedFields();
		}
	else
		is_managed = 0;
	}

IntrusivePtr<RecordVal> ZAM_record::ToRecordVal()
	{
	if ( ! rv )
		{
		aggr_val = rv = new RecordVal(rt);
		if ( bindings )
			bindings->insert(this);
		}

	Spill();

	return {NewRef{}, rv};
	}

void ZAM_record::Spill()
	{
	if ( ! rv || ! is_dirty )
		return;

	for ( auto i = 0; i < zvec.size(); ++i )
		{
		auto rti = rt->FieldType(i);
		auto& zvi = zvec[i];

		if ( IsDirty(i) )
			{
			if ( IsInRecord(i) )
				{
				rv->Assign(i, zvi.ToVal(rti));
				if ( IsManaged(i) )
					DeleteManagedType(zvi, rti);
				}
			else
				rv->Assign(i, nullptr);
			}
		}

	// Our strategy for spilling is that we start from scratch,
	// with nothing loaded.
	is_in_record = is_loaded = is_dirty = 0;
	}

void ZAM_record::Freshen()
	{
	ASSERT(! is_loaded && ! is_dirty);
	ASSERT(rv);
	// The following is for when we've converted over RecordVal's.
	//
	// if ( rv->val.record_val == this )
	// 	// Association stands.
	// 	return;
	//
	// rv = nullptr;
	//
	// EndAssociation();
	}

void ZAM_record::Load(int field)
	{
	if ( ! rv )
		reporter->InternalError("field missing in record load");

	auto f = rv->LookupWithDefault(field);
	auto mask = 1 << field;

	if ( f )
		{
		bool error;
		// ### The following will leak until we regularize
		// memory management in ZAMValUnion's constructor.
		zvec[field] = ZAMValUnion(f.release(), rt->FieldType(field), bindings, rv, error);
		is_in_record |= mask;
		}

	// Mark it as loaded even if it wasn't in the record, since we
	// did try to sync it.
	is_loaded |= mask;
	}

void ZAM_record::Delete(int field)
	{
	}

void ZAM_record::DeleteManagedMembers()
	{
	for ( auto i = 0; i < zvec.size(); ++i )
		{
		auto& zvi = zvec[i];
		if ( IsLoaded(i) && IsManaged(i) )
			{
			auto rti = rt->FieldType(i);
			DeleteManagedType(zvi, rti);
			}
		}
	}


ZAMVector::ZAMVector(IntrusivePtr<ZAM_vector> _vec)
	: vec(std::move(_vec))
	{
	auto vv = vec->VecVal();

	if ( ! vv )
		{
		yield_type = nullptr;
		return;
		}

	auto vt = vv->Type()->AsVectorType();
	auto yt = vt->YieldType();

	if ( yt->Tag() == TYPE_ANY )
		{
		if ( vec->Size() > 0 )
			{
			// If we use a bare 0 in the call to Lookup, effin'
			// C++ selects the Val* version of Lookup.  Geez.
			unsigned int zee_row = 0;
			auto elem0 = vv->Lookup(zee_row);
			yt = elem0->Type();
			}
		else
			yt = nullptr;
		}

	if ( yt && IsManagedType(yt) )
		vec->SetManagedYieldType(yt);

	yield_type = yt;
	}


ZAMRecord::ZAMRecord(IntrusivePtr<ZAM_record> _zr)
	{
	zr = _zr;
	}


ZAMVector* to_ZAM_vector(Val* vec, ZAMAggrBindings* bindings, bool track_val)
	{
	if ( ! track_val )
		// Set the bindings to nil so that the ZAM_vector knows
		// not to bother sync'ing the aggregate.
		bindings = nullptr;

	auto raw = to_raw_ZAM_vector(vec, bindings);
	return new ZAMVector(raw);
	}

IntrusivePtr<ZAM_vector> to_raw_ZAM_vector(Val* vec, ZAMAggrBindings* bindings)
	{
	auto vv = vec->AsVector();

	return {NewRef{}, vv};
#if 0
	auto t = vec->Type()->AsVectorType();
	auto yt = t->YieldType();

	auto myt = IsManagedType(yt) ? yt : nullptr;
	auto zv = make_intrusive<ZAM_vector>(vec->AsVectorVal(), bindings, myt);
	auto& raw = zv->ModVecNoDirty();

	bool error;

	for ( auto elem : *vv )
		if ( ! elem )
			// Zeek vectors can have holes.
			raw.push_back(ZAMValUnion());
		else
			raw.push_back(ZAMValUnion(elem, yt, bindings,
							vec, error));

	return zv;
#endif
	}


ZAMRecord* to_ZAM_record(Val* r, ZAMAggrBindings* bindings, bool track_val)
	{
	auto rv = track_val ? r->AsRecordVal() : nullptr;
	auto zr = make_intrusive<ZAM_record>(rv, r->Type()->AsRecordType(),
						bindings);
	return new ZAMRecord(zr);
	}
