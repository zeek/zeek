// See the file "COPYING" in the main distribution directory for copyright.


#include "SerializationTypes.h"
#include "../RemoteSerializer.h"


using namespace threading;

bool Field::Read(SerializationFormat* fmt)
	{
	int t;
	int st;

	bool success = (fmt->Read(&name, "name") && fmt->Read(&secondary_name, "secondary_name") && 
			fmt->Read(&t, "type") && fmt->Read(&st, "subtype") );
	type = (TypeTag) t;
	subtype = (TypeTag) st;

	return success;
	}

bool Field::Write(SerializationFormat* fmt) const
	{
	return (fmt->Write(name, "name") && fmt->Write(secondary_name, "secondary_name") && fmt->Write((int)type, "type") && 
			fmt->Write((int)subtype, "subtype"));
	}

Value::~Value()
	{
	if ( (type == TYPE_ENUM || type == TYPE_STRING || type == TYPE_FILE || type == TYPE_FUNC)
	     && present )
		delete val.string_val;

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
		
		switch (proto) {
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


	case TYPE_SUBNET:
		{
		uint32 net[4];
		if ( ! (fmt->Read(&net[0], "net0") &&
			fmt->Read(&net[1], "net1") &&
			fmt->Read(&net[2], "net2") &&
			fmt->Read(&net[3], "net3") &&
			fmt->Read(&val.subnet_val.width, "width")) )
			return false;

#ifdef BROv6
		val.subnet_val.net[0] = net[0];
		val.subnet_val.net[1] = net[1];
		val.subnet_val.net[2] = net[2];
		val.subnet_val.net[3] = net[3];
#else
		val.subnet_val.net = net[0];
#endif
		return true;
		}

	case TYPE_ADDR:
		{
		uint32 addr[4];
		if ( ! (fmt->Read(&addr[0], "addr0") &&
			fmt->Read(&addr[1], "addr1") &&
			fmt->Read(&addr[2], "addr2") &&
			fmt->Read(&addr[3], "addr3")) )
			return false;

		val.addr_val[0] = addr[0];
#ifdef BROv6
		val.addr_val[1] = addr[1];
		val.addr_val[2] = addr[2];
		val.addr_val[3] = addr[3];
#endif
		return true;
		}

	case TYPE_DOUBLE:
	case TYPE_TIME:
	case TYPE_INTERVAL:
		return fmt->Read(&val.double_val, "double");

	case TYPE_ENUM:
	case TYPE_STRING:
	case TYPE_FILE:
	case TYPE_FUNC:
		{
		val.string_val = new string;
		return fmt->Read(val.string_val, "string");
		}

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
		reporter->InternalError("unsupported type %s in Value::Write", type_name(type));
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

	case TYPE_SUBNET:
		{
		uint32 net[4];
#ifdef BROv6
		net[0] = val.subnet_val.net[0];
		net[1] = val.subnet_val.net[1];
		net[2] = val.subnet_val.net[2];
		net[3] = val.subnet_val.net[3];
#else
		net[0] = val.subnet_val.net;
		net[1] = net[2] = net[3] = 0;
#endif
		return fmt->Write(net[0], "net0") &&
			fmt->Write(net[1], "net1") &&
			fmt->Write(net[2], "net2") &&
			fmt->Write(net[3], "net3") &&
			fmt->Write(val.subnet_val.width, "width");
		}

	case TYPE_ADDR:
		{
		uint32 addr[4];
		addr[0] = val.addr_val[0];
#ifdef BROv6
		addr[1] = val.addr_val[1];
		addr[2] = val.addr_val[2];
		addr[3] = val.addr_val[3];
#else
		addr[1] = addr[2] = addr[3] = 0;
#endif
		return fmt->Write(addr[0], "addr0") &&
			fmt->Write(addr[1], "addr1") &&
			fmt->Write(addr[2], "addr2") &&
			fmt->Write(addr[3], "addr3");
		}

	case TYPE_DOUBLE:
	case TYPE_TIME:
	case TYPE_INTERVAL:
		return fmt->Write(val.double_val, "double");

	case TYPE_ENUM:
	case TYPE_STRING:
	case TYPE_FILE:
	case TYPE_FUNC:
		return fmt->Write(*val.string_val, "string");

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
		reporter->InternalError("unsupported type %s in Value::REad", type_name(type));
	}

	return false;
	}

