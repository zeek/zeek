// See the file "COPYING" in the main distribution directory for copyright.

#include "ZVal.h"

#include "OpaqueVal.h"
#include "BroString.h"
#include "File.h"
#include "Func.h"
#include "Reporter.h"
#include "Desc.h"


bool* zval_error_addr = nullptr;


bool IsManagedType(const IntrusivePtr<BroType>& t)
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


ZAMValUnion::ZAMValUnion(IntrusivePtr<Val> v, const IntrusivePtr<BroType>& t)
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
			reporter->Error("vector type clash: %s vs. %s (%s)",
					type_name(my_ytag), type_name(v_ytag),
					obj_desc(v));
			if ( zval_error_addr )
				*zval_error_addr = true;
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

bool ZAMValUnion::IsNil(const IntrusivePtr<BroType>& t) const
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

IntrusivePtr<Val> ZAMValUnion::ToVal(const IntrusivePtr<BroType>& t) const
	{
	Val* v;

	switch ( t->Tag() ) {
	case TYPE_INT:
		// We can't use make_intrusive directly because this
		// constructor is protected, sigh.
		v = new Val(int_val, TYPE_INT);
		return {AdoptRef{}, v};

	case TYPE_BOOL:	
		return {AdoptRef{}, Val::MakeBool(int_val)};

	case TYPE_PORT:
		return {AdoptRef{}, val_mgr->GetPort(uint_val)};

	case TYPE_COUNT:
		v = new Val(uint_val, TYPE_COUNT);
		return {AdoptRef{}, v};

	case TYPE_COUNTER:
		v = new Val(uint_val, TYPE_COUNTER);
		return {AdoptRef{}, v};

	case TYPE_DOUBLE:
		return make_intrusive<Val>(double_val, TYPE_DOUBLE);

	case TYPE_INTERVAL:
		return make_intrusive<IntervalVal>(double_val, 1.0);

	case TYPE_TIME:
		return make_intrusive<Val>(double_val, TYPE_TIME);

	case TYPE_ENUM:
		return t->AsEnumType()->GetVal(int_val);

	case TYPE_ANY:
		return {NewRef{}, any_val};

	case TYPE_TYPE:
		v =  new Val(type_val);
		return {AdoptRef{}, v};

	case TYPE_FUNC:
		if ( func_val )
			{
			Ref(func_val);
			return make_intrusive<Val>(func_val);
			}

		v = nullptr;
		break;

	case TYPE_FILE:
		if ( file_val )
			{
			Ref(file_val);
			return make_intrusive<Val>(file_val);
			}

		v = nullptr;
		break;

	case TYPE_ADDR:		v = addr_val; break;
	case TYPE_SUBNET:	v = subnet_val; break;
	case TYPE_STRING:	v = string_val; break;
	case TYPE_LIST:		v = list_val; break;
	case TYPE_OPAQUE:	v = opaque_val; break;
	case TYPE_TABLE:	v = table_val; break;
	case TYPE_RECORD:	v = record_val; break;
	case TYPE_VECTOR:	v = vector_val; break;
	case TYPE_PATTERN:	v = re_val; break;

	case TYPE_ERROR:
	case TYPE_TIMER:
	case TYPE_UNION:
	case TYPE_VOID:
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

	return true;
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
		DeleteManagedType(z);
	}


ZAM_record::ZAM_record(RecordVal* _rv, IntrusivePtr<RecordType> _rt)
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
