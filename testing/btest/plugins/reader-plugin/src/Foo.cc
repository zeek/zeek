// See the file "COPYING" in the main distribution directory for copyright.

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "Foo.h"

#include "threading/SerialTypes.h"
#include "threading/Manager.h"

using namespace btest::input::reader;
using zeek::threading::Value;
using zeek::threading::Field;

Foo::Foo(zeek::input::ReaderFrontend *frontend) : zeek::input::ReaderBackend(frontend)
	{
	ascii = new zeek::threading::formatter::Ascii(this, zeek::threading::formatter::Ascii::SeparatorInfo());
	}

Foo::~Foo()
	{
	DoClose();
	delete ascii;
	}

void Foo::DoClose()
	{
	}

bool Foo::DoInit(const zeek::input::ReaderBackend::ReaderInfo& info, int num_fields, const Field* const* fields)
	{
	DoUpdate();
	return true;
	}

std::string Foo::RandomString(const int len)
	{
	std::string s(len, ' ');

	static const char values[] =
	"0123456789!@#$%^&*()-_=+{}[]\\|"
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz";

	for (int i = 0; i < len; ++i)
		// zeek::random_number() is not thread-safe; as we are only using one simultaneous thread
		// here, this should not matter in this case. If this test ever starts showing
		// random errors, this might be the culprit.
		s[i] = values[zeek::util::detail::random_number() / (zeek::util::detail::max_random() / sizeof(values))];

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

zeek::threading::Value* Foo::EntryToVal(zeek::TypeTag type, zeek::TypeTag subtype)
	{
	Value* val = new Value(type, true);

	// basically construct something random from the fields that we want.

	switch ( type ) {
	case zeek::TYPE_ENUM:
		assert(false); // no enums, please.

	case zeek::TYPE_STRING:
		{
		std::string rnd = RandomString(10);
		val->val.string_val.data = zeek::util::copy_string(rnd.c_str());
		val->val.string_val.length = rnd.size();
		break;
		}

	case zeek::TYPE_BOOL:
		val->val.int_val = 1; // we never lie.
		break;

	case zeek::TYPE_INT:
		val->val.int_val = random();
		break;

	case zeek::TYPE_TIME:
		val->val.double_val = 0;
		break;

	case zeek::TYPE_DOUBLE:
	case zeek::TYPE_INTERVAL:
		val->val.double_val = random();
		break;

	case zeek::TYPE_COUNT:
		val->val.uint_val = random();
		break;

	case zeek::TYPE_PORT:
		val->val.port_val.port = random() / (RAND_MAX / 60000);
		val->val.port_val.proto = TRANSPORT_UNKNOWN;
		break;

	case zeek::TYPE_SUBNET:
		{
		val->val.subnet_val.prefix = ascii->ParseAddr("192.168.17.1");
		val->val.subnet_val.length = 16;
		}
		break;

	case zeek::TYPE_ADDR:
		val->val.addr_val = ascii->ParseAddr("192.168.17.1");
		break;

	case zeek::TYPE_TABLE:
	case zeek::TYPE_VECTOR:
		// First - common initialization
		// Then - initialization for table.
		// Then - initialization for vector.
		// Then - common stuff
		{
		// how many entries do we have...
		unsigned int length = random() / (RAND_MAX / 15);

		Value** lvals = new Value* [length];

		if ( type == zeek::TYPE_TABLE )
			{
			val->val.set_val.vals = lvals;
			val->val.set_val.size = length;
			}
		else if ( type == zeek::TYPE_VECTOR )
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
			Value* newval = EntryToVal(subtype, zeek::TYPE_ENUM);
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
