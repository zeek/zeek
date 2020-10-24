// See the file "COPYING" in the main distribution directory for copyright.

#include "Val.h"

#include "OpaqueVal.h"
#include "ZeekString.h"
#include "File.h"
#include "Func.h"
#include "Reporter.h"
#include "Desc.h"

using namespace zeek;


bool zeek::IsManagedType(const TypePtr& t)
	{
	switch ( t->Tag() ) {
	case zeek::TYPE_ADDR:
	case zeek::TYPE_ANY:
	case zeek::TYPE_FILE:
	case zeek::TYPE_FUNC:
	case zeek::TYPE_LIST:
	case zeek::TYPE_OPAQUE:
	case zeek::TYPE_PATTERN:
	case zeek::TYPE_RECORD:
	case zeek::TYPE_STRING:
	case zeek::TYPE_SUBNET:
	case zeek::TYPE_TABLE:
	case zeek::TYPE_TYPE:
	case zeek::TYPE_VECTOR:
		return true;

	default:
		return false;

	}
	}


ZAMValUnion::ZAMValUnion(ValPtr v, const TypePtr& t)
	{
	if ( ! v )
		{
		ASSERT(IsManagedType(t));
		managed_val = nullptr;
		return;
		}

	auto vu = v->val;
	auto vt = v->GetType();

	if ( vt->Tag() != t->Tag() && t->Tag() != zeek::TYPE_ANY )
		{
		if ( t->InternalType() == zeek::TYPE_INTERNAL_OTHER ||
		     t->InternalType() != vt->InternalType() )
			reporter->InternalError("type inconsistency in ZAMValUnion constructor");
		}

	switch ( t->Tag() ) {
	case zeek::TYPE_BOOL:
	case zeek::TYPE_INT:
	case zeek::TYPE_ENUM:
		int_val = vu.int_val;
		break;

	case zeek::TYPE_COUNT:
	case zeek::TYPE_PORT:
		uint_val = vu.uint_val;
		break;

	case zeek::TYPE_DOUBLE:
	case zeek::TYPE_INTERVAL:
	case zeek::TYPE_TIME:
		double_val = vu.double_val;
		break;

	case zeek::TYPE_FUNC:
		func_val = vu.func_val;
		Ref(func_val);
		break;

	case zeek::TYPE_FILE:
		file_val = vu.file_val;
		Ref(file_val);
		break;

	case zeek::TYPE_LIST:
		list_val = v.release()->AsListVal();
		break;

	case zeek::TYPE_OPAQUE:
		opaque_val = v.release()->AsOpaqueVal();
		break;

	case zeek::TYPE_PATTERN:
		re_val = v.release()->AsPatternVal();
		break;

	case zeek::TYPE_TABLE:
		table_val = v.release()->AsTableVal();
		break;

	case zeek::TYPE_VECTOR:
		{
		vector_val = v.release()->AsVectorVal();

		// Some run-time type-checking, sigh.
		auto my_ytag = t->AsVectorType()->Yield()->Tag();
		auto v_ytag = vt->AsVectorType()->Yield()->Tag();

		if ( my_ytag != v_ytag && my_ytag != zeek::TYPE_ANY &&
		     v_ytag != zeek::TYPE_ANY )
			{
			// Despite the above checks, this clash can still
			// happen thanks to the intercession of vector-of-any,
			// which for example can allow a function to return
			// a concrete vector-of-X that's assigned to a local
			// with a concrete vector-of-Y type.
			reporter->Error("vector type clash: %s vs. %s (%s)",
					type_name(my_ytag), type_name(v_ytag),
					obj_desc(v));
			if ( zval_error_addr )
				*zval_error_addr = true;
			}

		break;
		}

	case zeek::TYPE_RECORD:
		record_val = v.release()->AsRecordVal();
		break;

	case zeek::TYPE_STRING:
		string_val = v.release()->AsStringVal();
		break;

	case zeek::TYPE_ADDR:
		addr_val = v.release()->AsAddrVal();
		break;

	case zeek::TYPE_SUBNET:
		subnet_val = v.release()->AsSubNetVal();
		break;

	case zeek::TYPE_ANY:
		any_val = v.release();
		break;

	case zeek::TYPE_TYPE:
		type_val = t->Ref();
		break;

	case zeek::TYPE_ERROR:
	case zeek::TYPE_TIMER:
	case zeek::TYPE_UNION:
	case zeek::TYPE_VOID:
		reporter->InternalError("bad type in ZAMValUnion constructor");
	}
	}

bool ZAMValUnion::IsNil(const TypePtr& t) const
	{
	switch ( t->Tag() ) {
	case zeek::TYPE_ADDR:		return ! addr_val;
	case zeek::TYPE_ANY:		return ! any_val;
	case zeek::TYPE_FILE:		return ! file_val;
	case zeek::TYPE_FUNC:		return ! func_val;
	case zeek::TYPE_LIST:		return ! list_val;
	case zeek::TYPE_OPAQUE:	return ! opaque_val;
	case zeek::TYPE_PATTERN:	return ! re_val;
	case zeek::TYPE_RECORD:	return ! record_val;
	case zeek::TYPE_STRING:	return ! string_val;
	case zeek::TYPE_SUBNET:	return ! subnet_val;
	case zeek::TYPE_TABLE:	return ! table_val;
	case zeek::TYPE_TYPE:		return ! type_val;

	default:	return false;
	}
	}

ValPtr ZAMValUnion::ToVal(const TypePtr& t) const
	{
	Val* v;

	switch ( t->Tag() ) {
	case zeek::TYPE_INT:
		return val_mgr->Int(int_val);

	case zeek::TYPE_BOOL:	
		return val_mgr->Bool(int_val);

	case zeek::TYPE_PORT:
		return val_mgr->Port(uint_val);

	case zeek::TYPE_COUNT:
		return val_mgr->Count(uint_val);

	case zeek::TYPE_DOUBLE:
		return make_intrusive<zeek::DoubleVal>(double_val);

	case zeek::TYPE_INTERVAL:
		return make_intrusive<IntervalVal>(double_val, 1.0);

	case zeek::TYPE_TIME:
		return make_intrusive<zeek::TimeVal>(double_val);

	case zeek::TYPE_ENUM:
		return t->AsEnumType()->GetEnumVal(int_val);

	case zeek::TYPE_ANY:
		return {NewRef{}, any_val};

	case zeek::TYPE_TYPE:
		v =  new Val({NewRef{}, type_val});
		return {AdoptRef{}, v};

	case zeek::TYPE_FUNC:
		if ( func_val )
			{
			FuncPtr fv_ptr = {NewRef{}, func_val};
			return make_intrusive<zeek::Val>(fv_ptr);
			}

		v = nullptr;
		break;

	case zeek::TYPE_FILE:
		if ( file_val )
			{
			FilePtr fv_ptr = {NewRef{}, file_val};
			return make_intrusive<zeek::Val>(fv_ptr);
			}

		v = nullptr;
		break;

	case zeek::TYPE_ADDR:		v = addr_val; break;
	case zeek::TYPE_SUBNET:	v = subnet_val; break;
	case zeek::TYPE_STRING:	v = string_val; break;
	case zeek::TYPE_LIST:		v = list_val; break;
	case zeek::TYPE_OPAQUE:	v = opaque_val; break;
	case zeek::TYPE_TABLE:	v = table_val; break;
	case zeek::TYPE_RECORD:	v = record_val; break;
	case zeek::TYPE_VECTOR:	v = vector_val; break;
	case zeek::TYPE_PATTERN:	v = re_val; break;

	case zeek::TYPE_ERROR:
	case zeek::TYPE_TIMER:
	case zeek::TYPE_UNION:
	case zeek::TYPE_VOID:
		reporter->InternalError("bad ret type return tag");
	}

	if ( v )
		return {NewRef{}, v};

	reporter->Error("value used but not set");
	if ( zval_error_addr )
		*zval_error_addr = true;

	return nullptr;
	}


bool ZAM_vector::SetManagedElement(int n, const ZAMValUnion& v)
	{
	auto& zn = zvec[n];

	switch ( managed_yt->Tag() ) {

#define MANAGE_VIA_REF(accessor) \
	Unref(zn.accessor); \
	zn = v; \
	if ( ! zn.accessor ) \
		return false; \
	Ref(zn.accessor);

	case zeek::TYPE_ADDR: 	MANAGE_VIA_REF(addr_val); break;
	case zeek::TYPE_ANY:		MANAGE_VIA_REF(any_val); break;
	case zeek::TYPE_FILE:		MANAGE_VIA_REF(file_val); break;
	case zeek::TYPE_FUNC:		MANAGE_VIA_REF(func_val); break;
	case zeek::TYPE_LIST:		MANAGE_VIA_REF(list_val); break;
	case zeek::TYPE_OPAQUE:	MANAGE_VIA_REF(opaque_val); break;
	case zeek::TYPE_PATTERN:	MANAGE_VIA_REF(re_val); break;
	case zeek::TYPE_RECORD:	MANAGE_VIA_REF(record_val); break;
	case zeek::TYPE_STRING:	MANAGE_VIA_REF(string_val); break;
	case zeek::TYPE_SUBNET: 	MANAGE_VIA_REF(subnet_val); break;
	case zeek::TYPE_TABLE: 	MANAGE_VIA_REF(table_val); break;
	case zeek::TYPE_TYPE:		MANAGE_VIA_REF(type_val); break;
	case zeek::TYPE_VECTOR:	MANAGE_VIA_REF(vector_val); break;

	default:
		reporter->InternalError("bad type tag in ZAM_vector::SetManagedElement");
	}

	return true;
	}

void ZAM_vector::GrowVector(int new_size)
	{
	int old_size = zvec.size();
	zvec.resize(new_size);

	if ( any_types )
		any_types->resize(new_size);

	for ( int i = old_size; i < new_size; ++i )
		// Strictly speaking, we should know the particular type of
		// vector and zero it accordingly.
		zvec[i].managed_val = nullptr;
	}

void ZAM_vector::DeleteMembers()
	{
	for ( auto& z : zvec )
		DeleteManagedType(z);
	}

void ZAM_vector::DeleteAnyMembers()
	{
	for ( unsigned int i = 0; i < zvec.size(); ++i )
		if ( IsManagedYieldType(i) )
			DeleteManagedType(zvec[i]);
	}


ZAM_record::ZAM_record(RecordVal* _rv, RecordTypePtr _rt)
	: zvec(_rt->NumFields()), is_in_record(_rt->NumFields(), false),
	is_managed(_rt->ManagedFields())
	{
	rv = _rv;
	rt = std::move(_rt);
	}

bool ZAM_record::SetToDefault(unsigned int field)
	{
	auto v = rt->FieldDefault(field);
	if ( ! v )
		return false;

	auto td = rt->FieldDecl(field);
	auto t = td->type;

	ZAMValUnion zvu(v, t);
	Assign(field, zvu);

	return true;
	}

void ZAM_record::DeleteManagedMembers()
	{
	for ( unsigned int i = 0; i < zvec.size(); ++i )
		{
		if ( IsInRecord(i) && IsManaged(i) )
			{
			auto& zvi = zvec[i];
			DeleteManagedType(zvi);
			}
		}
	}
