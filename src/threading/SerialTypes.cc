// See the file "COPYING" in the main distribution directory for copyright.


#include "SerialTypes.h"
#include "../RemoteSerializer.h"


using namespace threading;

bool Field::Read(SerializationFormat* fmt)
	{
	int t;
	int st;
	string tmp_name;
	bool have_2nd;

	if ( ! fmt->Read(&have_2nd, "have_2nd") )
		return false;

	if ( have_2nd )
		{
		string tmp_secondary_name;
		if ( ! fmt->Read(&tmp_secondary_name, "secondary_name") )
			return false;

		secondary_name = copy_string(tmp_secondary_name.c_str());
		}
	else
		secondary_name = 0;

	bool success = (fmt->Read(&tmp_name, "name")
			&& fmt->Read(&t, "type")
			&& fmt->Read(&st, "subtype")
			&& fmt->Read(&optional, "optional"));

	if ( ! success )
		return false;

	name = copy_string(tmp_name.c_str());

	type = (TypeTag) t;
	subtype = (TypeTag) st;

	return true;
	}

bool Field::Write(SerializationFormat* fmt) const
	{
	assert(name);

	if ( secondary_name )
		{
		if ( ! (fmt->Write(true, "have_2nd")
			&& fmt->Write(secondary_name, "secondary_name")) )
			return false;
		}
	else
		if ( ! fmt->Write(false, "have_2nd") )
			return false;

	return (fmt->Write(name, "name")
		&& fmt->Write((int)type, "type")
		&& fmt->Write((int)subtype, "subtype"),
		fmt->Write(optional, "optional"));
	}

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
	if ( (type == TYPE_ENUM || type == TYPE_STRING || type == TYPE_FILE || type == TYPE_FUNC)
	     && present )
		delete [] val.string_val.data;

	if ( type == TYPE_TABLE && present )
		{
		for ( int i = 0; i < val.set_val.size; i++ )
			delete val.set_val.vals[i];

		delete [] val.set_val.vals;
		}

	if ( type == TYPE_VECTOR && present )
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

bool Value::Read(SerializationFormat* fmt)
	{
	int ty;

	if ( ! (fmt->Read(&ty, "type") && fmt->Read(&present, "present")) )
		return false;

	type = (TypeTag)(ty);

	if ( ! present )
		return true;

	switch ( type ) {
	case TYPE_BOOL:
	case TYPE_INT:
		return fmt->Read(&val.int_val, "int");

	case TYPE_COUNT:
	case TYPE_COUNTER:
		return fmt->Read(&val.uint_val, "uint");

	case TYPE_PORT: {
		int proto;
		if ( ! (fmt->Read(&val.port_val.port, "port") && fmt->Read(&proto, "proto") ) ) {
			return false;
		}

		switch ( proto ) {
			case 0:
				val.port_val.proto = TRANSPORT_UNKNOWN;
				break;
			case 1:
				val.port_val.proto = TRANSPORT_TCP;
				break;
			case 2:
				val.port_val.proto = TRANSPORT_UDP;
				break;
			case 3:
				val.port_val.proto = TRANSPORT_ICMP;
				break;
			default:
				return false;
		}

		return true;
		}

	case TYPE_ADDR:
		{
		char family;

		if ( ! fmt->Read(&family, "addr-family") )
			return false;

		switch ( family ) {
		case 4:
			val.addr_val.family = IPv4;
			return fmt->Read(&val.addr_val.in.in4, "addr-in4");

		case 6:
			val.addr_val.family = IPv6;
			return fmt->Read(&val.addr_val.in.in6, "addr-in6");

		}

		// Can't be reached.
		abort();
		}

	case TYPE_SUBNET:
		{
		char length;
		char family;

		if ( ! (fmt->Read(&length, "subnet-len") && fmt->Read(&family, "subnet-family")) )
			return false;

		switch ( family ) {
		case 4:
			val.subnet_val.length = (uint8_t)length;
			val.subnet_val.prefix.family = IPv4;
			return fmt->Read(&val.subnet_val.prefix.in.in4, "subnet-in4");

		case 6:
			val.subnet_val.length = (uint8_t)length;
			val.subnet_val.prefix.family = IPv6;
			return fmt->Read(&val.subnet_val.prefix.in.in6, "subnet-in6");

		}

		// Can't be reached.
		abort();
		}

	case TYPE_DOUBLE:
	case TYPE_TIME:
	case TYPE_INTERVAL:
		return fmt->Read(&val.double_val, "double");

	case TYPE_ENUM:
	case TYPE_STRING:
	case TYPE_FILE:
	case TYPE_FUNC:
		return fmt->Read(&val.string_val.data, &val.string_val.length, "string");

	case TYPE_TABLE:
		{
		if ( ! fmt->Read(&val.set_val.size, "set_size") )
			return false;

		val.set_val.vals = new Value* [val.set_val.size];

		for ( int i = 0; i < val.set_val.size; ++i )
			{
			val.set_val.vals[i] = new Value;

			if ( ! val.set_val.vals[i]->Read(fmt) )
				return false;
			}

		return true;
		}

	case TYPE_VECTOR:
		{
		if ( ! fmt->Read(&val.vector_val.size, "vector_size") )
			return false;

		val.vector_val.vals = new Value* [val.vector_val.size];

		for ( int i = 0; i < val.vector_val.size; ++i )
			{
			val.vector_val.vals[i] = new Value;

			if ( ! val.vector_val.vals[i]->Read(fmt) )
				return false;
			}

		return true;
		}

	default:
		reporter->InternalError("unsupported type %s in Value::Read",
		                        type_name(type));
	}

	return false;
	}

bool Value::Write(SerializationFormat* fmt) const
	{
	if ( ! (fmt->Write((int)type, "type") &&
		fmt->Write(present, "present")) )
		return false;

	if ( ! present )
		return true;

	switch ( type ) {
	case TYPE_BOOL:
	case TYPE_INT:
		return fmt->Write(val.int_val, "int");

	case TYPE_COUNT:
	case TYPE_COUNTER:
		return fmt->Write(val.uint_val, "uint");

	case TYPE_PORT:
		return fmt->Write(val.port_val.port, "port") && fmt->Write(val.port_val.proto, "proto");

	case TYPE_ADDR:
		{
		switch ( val.addr_val.family ) {
		case IPv4:
			return fmt->Write((char)4, "addr-family")
				&& fmt->Write(val.addr_val.in.in4, "addr-in4");

		case IPv6:
			return fmt->Write((char)6, "addr-family")
				&& fmt->Write(val.addr_val.in.in6, "addr-in6");
			break;
		}

		// Can't be reached.
		abort();
		}

	case TYPE_SUBNET:
		{
		if ( ! fmt->Write((char)val.subnet_val.length, "subnet-length") )
			return false;

		switch ( val.subnet_val.prefix.family ) {
		case IPv4:
			return fmt->Write((char)4, "subnet-family")
				&& fmt->Write(val.subnet_val.prefix.in.in4, "subnet-in4");

		case IPv6:
			return fmt->Write((char)6, "subnet-family")
				&& fmt->Write(val.subnet_val.prefix.in.in6, "subnet-in6");
			break;
		}

		// Can't be reached.
		abort();
		}

	case TYPE_DOUBLE:
	case TYPE_TIME:
	case TYPE_INTERVAL:
		return fmt->Write(val.double_val, "double");

	case TYPE_ENUM:
	case TYPE_STRING:
	case TYPE_FILE:
	case TYPE_FUNC:
		return fmt->Write(val.string_val.data, val.string_val.length, "string");

	case TYPE_TABLE:
		{
		if ( ! fmt->Write(val.set_val.size, "set_size") )
			return false;

		for ( int i = 0; i < val.set_val.size; ++i )
			{
			if ( ! val.set_val.vals[i]->Write(fmt) )
				return false;
			}

		return true;
		}

	case TYPE_VECTOR:
		{
		if ( ! fmt->Write(val.vector_val.size, "vector_size") )
			return false;

		for ( int i = 0; i < val.vector_val.size; ++i )
			{
			if ( ! val.vector_val.vals[i]->Write(fmt) )
				return false;
			}

		return true;
		}

	default:
		reporter->InternalError("unsupported type %s in Value::Write",
		                        type_name(type));
	}

	return false;
	}

