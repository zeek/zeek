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

#if 0
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
#endif


ZAMValUnion::ZAMValUnion(IntrusivePtr<Val> v, BroType* t)
	{
	if ( ! v )
		{
		ASSERT(IsManagedType(t));
		managed_val = nullptr;
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
		vector_val = v.release()->AsVectorVal();

		// Some run-time type-checking, sigh.
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
			}

		break;
		}

	case TYPE_RECORD:
		record_val = v.release()->AsRecordVal();
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
	case TYPE_RECORD:	v = record_val; v->Ref(); break;
	case TYPE_VECTOR:	v = vector_val; v->Ref(); break;
	case TYPE_PATTERN:	v = re_val; v->Ref(); break;

	case TYPE_ERROR:
	case TYPE_TIMER:
	case TYPE_UNION:
	case TYPE_VOID:
		reporter->InternalError("bad ret type return tag");
	}

	return {AdoptRef{}, v};
	}


void ZAM_vector::SetManagedElement(int n, ZAMValUnion& v)
	{
	// ### Shouldn't be called.
	ASSERT(0);
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
		zvec[i].managed_val = nullptr;
	}

void ZAM_vector::DeleteMembers()
	{
	for ( auto& z : zvec )
		DeleteManagedType(z, managed_yt);
	}


ZAM_record::ZAM_record(RecordVal* _rv, RecordType* _rt)
	: zvec(_rt->NumFields())
	{
	rv = _rv;
	rt = _rt;

	is_in_record = 0;
	is_managed = rt->ManagedFields();
	}

bool ZAM_record::SetToDefault(unsigned int field)
	{
	auto v = rt->FieldDefault(field);
	auto td = rt->FieldDecl(field);
	auto t = td->type;

	if ( ! v )
		return false;

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
			DeleteManagedType(zvi, nullptr);
			// auto rti = FieldType(i);
			// DeleteManagedType(zvi, rti);
			}
		}
	}
