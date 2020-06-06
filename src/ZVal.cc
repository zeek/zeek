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
	case TYPE_ANY:
	case TYPE_FILE:
	case TYPE_FUNC:
	case TYPE_LIST:
	case TYPE_OPAQUE:
	case TYPE_PATTERN:
	case TYPE_RECORD:
	case TYPE_STRING:
	case TYPE_SUBNET:
	case TYPE_TABLE:
	case TYPE_TYPE:
	case TYPE_VECTOR:
		return true;

	default:
		return false;

	}
	}

void DeleteManagedType(ZAMValUnion& v, const BroType* t)
	{
	switch ( t->Tag() ) {
	case TYPE_ADDR:	Unref(v.addr_val); v.addr_val = nullptr; break;
	case TYPE_ANY:	Unref(v.any_val); v.any_val = nullptr; break;
	case TYPE_FILE:	Unref(v.file_val); v.file_val = nullptr; break;
	case TYPE_FUNC:	Unref(v.func_val); v.func_val = nullptr; break;
	case TYPE_LIST:	Unref(v.list_val); v.list_val = nullptr; break;
	case TYPE_OPAQUE:
			Unref(v.opaque_val); v.opaque_val = nullptr; break;
	case TYPE_PATTERN:
			Unref(v.re_val); v.re_val = nullptr; break;
	case TYPE_RECORD:
			Unref(v.record_val); v.record_val = nullptr; break;
	case TYPE_STRING:
			Unref(v.string_val); v.string_val = nullptr; break;
	case TYPE_SUBNET:
			Unref(v.subnet_val); v.subnet_val = nullptr; break;
	case TYPE_TABLE:
			Unref(v.table_val); v.table_val = nullptr; break;
	case TYPE_TYPE:	Unref(v.type_val); v.type_val = nullptr; break;
	case TYPE_VECTOR: Unref(v.vector_val); v.vector_val = nullptr; break;

	default:
		reporter->InternalError("type inconsistency in DeleteManagedType");
	}
	}


ZAMValUnion::ZAMValUnion(IntrusivePtr<Val> v, BroType* t)
	{
	ASSERT(v);

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

	case TYPE_FUNC:
		func_val = vu.func_val;
		Ref(func_val);
		break;

	case TYPE_FILE:
		file_val = vu.file_val;
		Ref(file_val);
		break;

	case TYPE_LIST:
		list_val = v.release()->AsListVal();
		break;

	case TYPE_OPAQUE:
		opaque_val = v.release()->AsOpaqueVal();
		break;

	case TYPE_PATTERN:
		re_val = v.release()->AsPatternVal();
		break;

	case TYPE_TABLE:
		table_val = v.release()->AsTableVal();
		break;

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
			ZAM_run_time_error(msg, v.get());
			vector_val = nullptr;
			}
		else
			vector_val = to_ZAM_vector(v);

		break;
		}

	case TYPE_RECORD:
		record_val = to_ZAM_record(v);
		break;

	case TYPE_STRING:
		string_val = v.release()->AsStringVal();
		break;

	case TYPE_ADDR:
		addr_val = v.release()->AsAddrVal();
		break;

	case TYPE_SUBNET:
		subnet_val = v.release()->AsSubNetVal();
		break;

	case TYPE_ANY:
		any_val = v.release();
		break;

	case TYPE_TYPE:
		type_val = t->Ref();
		break;

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

	case TYPE_ENUM:		return t->AsEnumType()->GetVal(int_val);

	case TYPE_PORT:		v = val_mgr->GetPort(uint_val); break;

	case TYPE_VECTOR:	return vector_val->ToVectorVal(t);
	case TYPE_RECORD:	return record_val->ToRecordVal();

	case TYPE_ANY:		return {NewRef{}, any_val};

	case TYPE_TYPE:		v = new Val(type_val); break;

	case TYPE_ADDR:		v = addr_val; v->Ref(); break;
	// Damned if I know why Clang won't allow this one particular
	// v->Ref():
	case TYPE_SUBNET:	v = subnet_val; ::Ref(v); break;
	case TYPE_STRING:	v = string_val; v->Ref(); break;
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


IntrusivePtr<VectorVal> ZAM_vector::ToVectorVal(BroType* t)
	{
	if ( ! aggr_val )
		{
		// Need to create the vector.
		auto vt = t->AsVectorType();
		auto yt = vt->YieldType();
		int n = zvec.size();

		if ( ! general_yt )
			SetGeneralYieldType(yt);

		auto is_any = IsAny(general_yt);

		auto vv = new VectorVal(this, vt);

		for ( int i = 0; i < n; ++i )
			{
			auto& vr = zvec[i];

			if ( vr.IsNil(general_yt) )
				continue;

			IntrusivePtr<Val> v_i;
			if ( is_any )
				v_i = {NewRef{}, vr.any_val};
			else
				v_i = vr.ToVal(general_yt);

			vv->Assign(i, v_i);
			}

		aggr_val = vv;
		}

	return {NewRef{}, aggr_val->AsVectorVal()};
	}

void ZAM_vector::SetManagedElement(int n, ZAMValUnion& v)
	{
	auto& zn = zvec[n];

	switch ( managed_yt->Tag() ) {

#define MANAGE_VIA_REF(accessor) \
	Unref(zn.accessor); zn = v; Ref(zn.accessor);

	case TYPE_ADDR: 	MANAGE_VIA_REF(addr_val); break;
	case TYPE_ANY:		MANAGE_VIA_REF(any_val); break;
	case TYPE_FILE:		MANAGE_VIA_REF(file_val); break;
	case TYPE_FUNC:		MANAGE_VIA_REF(func_val); break;
	case TYPE_LIST:		MANAGE_VIA_REF(list_val); break;
	case TYPE_OPAQUE:	MANAGE_VIA_REF(opaque_val); break;
	case TYPE_PATTERN:	MANAGE_VIA_REF(re_val); break;
	case TYPE_RECORD:	MANAGE_VIA_REF(record_val); break;
	case TYPE_STRING:	MANAGE_VIA_REF(string_val); break;
	case TYPE_SUBNET: 	MANAGE_VIA_REF(subnet_val); break;
	case TYPE_TABLE: 	MANAGE_VIA_REF(table_val); break;
	case TYPE_TYPE:		MANAGE_VIA_REF(type_val); break;
	case TYPE_VECTOR:	MANAGE_VIA_REF(vector_val); break;

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


ZAM_record::ZAM_record(RecordVal* rv, RecordType* _rt)
	: ZAMAggrInstantiation(rv, _rt->NumFields())
	{
	is_in_record = 0;

	rt = _rt;

	if ( aggr_val )
		is_managed = rt->ManagedFields();
	else
		is_managed = 0;
	}

IntrusivePtr<RecordVal> ZAM_record::ToRecordVal()
	{
	if ( ! aggr_val )
		aggr_val = new RecordVal(this, rt);

	return {NewRef{}, aggr_val->AsRecordVal()};
	}

bool ZAM_record::SetToDefault(unsigned int field)
	{
	auto v = rt->FieldDefault(field);
	auto td = rt->FieldDecl(field);
	auto t = td->type;

	if ( ! v )
		{
		// If it's an aggregate, initialize it to an empty value.
		if ( t->Tag() == TYPE_TABLE )
			{
			IntrusivePtr<TableType> tt =
				{NewRef{}, t->AsTableType()};
			v = make_intrusive<TableVal>(tt, td->attrs);
			}
		else if ( t->Tag() == TYPE_VECTOR )
			v = make_intrusive<VectorVal>(t->AsVectorType());
		else if ( t->Tag() == TYPE_RECORD )
			v = make_intrusive<RecordVal>(t->AsRecordType(),
							false);
		else
			return false;
		}

	bool error_flag;
	ZAMValUnion zvu(v, t.get());
	Assign(field, zvu);
	return true;
	}

void ZAM_record::DeleteManagedMembers()
	{
	for ( auto i = 0; i < zvec.size(); ++i )
		{
		if ( IsInRecord(i) && IsManaged(i) )
			{
			auto& zvi = zvec[i];
			auto rti = FieldType(i);
			DeleteManagedType(zvi, rti);
			}
		}
	}


#if 0
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

	if ( yt )
		vec->SetGeneralYieldType(yt);

	yield_type = yt;
	}


ZAMRecord::ZAMRecord(IntrusivePtr<ZAM_record> _zr)
	{
	zr = _zr;
	ASSERT(zr.get());
	}
#endif


ZAM_vector* to_ZAM_vector(const IntrusivePtr<Val>& vec)
	{
	auto zv = vec->AsNonConstVector();
	Ref(zv);
	return zv;
	}

ZAM_record* to_ZAM_record(const IntrusivePtr<Val>& r)
	{
	auto zr = r->AsNonConstRecord();
	Ref(zr);
	return zr;
	}
