// See the file "COPYING" in the main distribution directory for copyright.


#include "SerialTypes.h"
#include "Reporter.h"

using namespace threading;

string Field::TypeName() const
	{
	string n;

	// We do not support tables, if the internal Bro type is table it
	// always is a set.
	if ( type == TYPE_TABLE )
		n = "set";
	else
		n = type_name(type);

	if ( (type == TYPE_TABLE) || (type == TYPE_VECTOR) )
		{
		n += "[";
		n += type_name(subtype);
		n += "]";
		}

	return n;
	}

Value::~Value()
	{
	if ( ! present )
		return;

	if ( type == TYPE_ENUM || type == TYPE_STRING || type == TYPE_FILE || type == TYPE_FUNC )
		delete [] val.string_val.data;

	else if ( type == TYPE_PATTERN )
		delete [] val.pattern_text_val;

	else if ( type == TYPE_TABLE )
		{
		for ( int i = 0; i < val.set_val.size; i++ )
			delete val.set_val.vals[i];

		delete [] val.set_val.vals;
		}

	else if ( type == TYPE_VECTOR )
		{
		for ( int i = 0; i < val.vector_val.size; i++ )
			delete val.vector_val.vals[i];

		delete [] val.vector_val.vals;
		}
	}

bool Value::IsCompatibleType(BroType* t, bool atomic_only)
	{
	if ( ! t )
		return false;

	switch ( t->Tag() )	{
	case TYPE_BOOL:
	case TYPE_INT:
	case TYPE_COUNT:
	case TYPE_COUNTER:
	case TYPE_PORT:
	case TYPE_SUBNET:
	case TYPE_ADDR:
	case TYPE_DOUBLE:
	case TYPE_TIME:
	case TYPE_INTERVAL:
	case TYPE_ENUM:
	case TYPE_STRING:
	case TYPE_FILE:
	case TYPE_FUNC:
		return true;

	case TYPE_RECORD:
		return ! atomic_only;

	case TYPE_TABLE:
		{
		if ( atomic_only )
			return false;

		if ( ! t->IsSet() )
			return false;

		return IsCompatibleType(t->AsSetType()->Indices()->PureType(), true);
		}

	case TYPE_VECTOR:
		{
		if ( atomic_only )
			return false;

		return IsCompatibleType(t->AsVectorType()->YieldType(), true);
		}

	default:
		return false;
	}

	return false;
	}
