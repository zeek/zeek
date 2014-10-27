// See the file "COPYING" in the main distribution directory for copyright.

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "Foo.h"

#include "threading/SerialTypes.h"
#include "threading/Manager.h"

using namespace input::reader;
using threading::Value;
using threading::Field;

Foo::Foo(ReaderFrontend *frontend) : ReaderBackend(frontend)
	{
	ascii = new threading::formatter::Ascii(this, threading::formatter::Ascii::SeparatorInfo());
	}

Foo::~Foo()
	{
	DoClose();
	delete ascii;
	}

void Foo::DoClose()
	{
	}

bool Foo::DoInit(const ReaderInfo& info, int num_fields, const Field* const* fields)
	{
	DoUpdate();
	return true;
	}

string Foo::RandomString(const int len)
	{
	string s(len, ' ');

	static const char values[] =
	"0123456789!@#$%^&*()-_=+{}[]\\|"
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz";

	for (int i = 0; i < len; ++i)
		s[i] = values[random() / (RAND_MAX / sizeof(values))];

	return s;
	}

// read the entire file and send appropriate thingies back to InputMgr
bool Foo::DoUpdate()
	{
	int linestosend = 5;
	for ( int i = 0; i < linestosend; i++ )
		{
		Value** field = new Value*[NumFields()];
		for  (int j = 0; j < NumFields(); j++ )
			field[j] = EntryToVal(Fields()[j]->type, Fields()[j]->subtype);

		SendEntry(field);
	}

	EndCurrentSend();

	return true;
}

threading::Value* Foo::EntryToVal(TypeTag type, TypeTag subtype)
	{
	Value* val = new Value(type, true);

	// basically construct something random from the fields that we want.

	switch ( type ) {
	case TYPE_ENUM:
		assert(false); // no enums, please.

	case TYPE_STRING:
		{
		string rnd = RandomString(10);
		val->val.string_val.data = copy_string(rnd.c_str());
		val->val.string_val.length = rnd.size();
		break;
		}

	case TYPE_BOOL:
		val->val.int_val = 1; // we never lie.
		break;

	case TYPE_INT:
		val->val.int_val = random();
		break;

	case TYPE_TIME:
		val->val.double_val = 0;
		break;

	case TYPE_DOUBLE:
	case TYPE_INTERVAL:
		val->val.double_val = random();
		break;

	case TYPE_COUNT:
	case TYPE_COUNTER:
		val->val.uint_val = random();
		break;

	case TYPE_PORT:
		val->val.port_val.port = random() / (RAND_MAX / 60000);
		val->val.port_val.proto = TRANSPORT_UNKNOWN;
		break;

	case TYPE_SUBNET:
		{
		val->val.subnet_val.prefix = ascii->ParseAddr("192.168.17.1");
		val->val.subnet_val.length = 16;
		}
		break;

	case TYPE_ADDR:
		val->val.addr_val = ascii->ParseAddr("192.168.17.1");
		break;

	case TYPE_TABLE:
	case TYPE_VECTOR:
		// First - common initialization
		// Then - initialization for table.
		// Then - initialization for vector.
		// Then - common stuff
		{
		// how many entries do we have...
		unsigned int length = random() / (RAND_MAX / 15);

		Value** lvals = new Value* [length];

		if ( type == TYPE_TABLE )
			{
			val->val.set_val.vals = lvals;
			val->val.set_val.size = length;
			}
		else if ( type == TYPE_VECTOR )
			{
			val->val.vector_val.vals = lvals;
			val->val.vector_val.size = length;
			}
		else
			assert(false);

		if ( length == 0 )
			break; //empty

		for ( unsigned int pos = 0; pos < length; pos++ )
			{
			Value* newval = EntryToVal(subtype, TYPE_ENUM);
			if ( newval == 0 )
				{
				Error("Error while reading set");
				delete val;
				return 0;
				}
			lvals[pos] = newval;
			}

		break;
		}


	default:
		Error(Fmt("unsupported field format %d", type));
		delete val;
		return 0;
	}

	return val;

	}


bool Foo::DoHeartbeat(double network_time, double current_time)
{
	return true;
}
