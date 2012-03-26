// See the file "COPYING" in the main distribution directory for copyright.

#include "Benchmark.h"
#include "NetVar.h"

#include "../../threading/SerialTypes.h"

#define MANUAL 0
#define REREAD 1
#define STREAM 2

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace input::reader;
using threading::Value;
using threading::Field;



Benchmark::Benchmark(ReaderFrontend *frontend) : ReaderBackend(frontend)
{
}

Benchmark::~Benchmark()
{
	DoFinish();
}

void Benchmark::DoFinish()
{
}

bool Benchmark::DoInit(string path, int arg_mode, int arg_num_fields, const Field* const* arg_fields)
{
	mode = arg_mode;
	
	num_fields = arg_num_fields;
	fields = arg_fields;
	num_lines = atoi(path.c_str());

	if ( ( mode != MANUAL ) && (mode != REREAD) && ( mode != STREAM ) ) {
		Error(Fmt("Unsupported read mode %d for source %s", mode, path.c_str()));
		return false;
	} 	

	DoUpdate();

	return true;
}

string Benchmark::RandomString(const int len) {
	string s(len, ' ');

	static const char values[] =
	"0123456789!@#$%^&*()-_=+{}[]\\|"
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz";

	for (int i = 0; i < len; ++i) {
        	s[i] = values[rand() / (RAND_MAX / sizeof(values))];
    	}

	return s;
}

// read the entire file and send appropriate thingies back to InputMgr
bool Benchmark::DoUpdate() {
	for ( int i = 0; i < num_lines; i++ ) {
		Value** field = new Value*[num_fields];
		for  (unsigned int j = 0; j < num_fields; j++ ) {
			field[j] = EntryToVal(fields[j]->type, fields[j]->subtype);
		}

		if ( mode == STREAM ) {
			// do not do tracking, spread out elements over the second that we have...
			Put(field);
			usleep(900000/num_lines);
		} else {
			SendEntry(field);
		}
	}

	//if ( mode != STREAM ) { // well, does not really make sense in the streaming sense - but I like getting the event.
		EndCurrentSend();
	//}

	return true;
}

threading::Value* Benchmark::EntryToVal(TypeTag type, TypeTag subtype) {
	Value* val = new Value(type, true);

	// basically construct something random from the fields that we want.
	
	switch ( type ) {
	case TYPE_ENUM:
		assert(false); // no enums, please.
	case TYPE_STRING:
		val->val.string_val = new string(RandomString(10));
		break;

	case TYPE_BOOL:
		val->val.int_val = 1; // we never lie.
		break;

	case TYPE_INT:
		val->val.int_val = rand();
		break;

	case TYPE_DOUBLE:
	case TYPE_TIME:
	case TYPE_INTERVAL:
		val->val.double_val = random();
		break;

	case TYPE_COUNT:
	case TYPE_COUNTER:
		val->val.uint_val = rand();
		break;

	case TYPE_PORT:
		val->val.port_val.port = rand() / (RAND_MAX / 60000);
		val->val.port_val.proto = TRANSPORT_UNKNOWN;
		break;

	case TYPE_SUBNET: {
		val->val.subnet_val.prefix = StringToAddr("192.168.17.1");
		val->val.subnet_val.length = 16;
		}
		break;

	case TYPE_ADDR: 
		val->val.addr_val = StringToAddr("192.168.17.1");
		break;

	case TYPE_TABLE:
	case TYPE_VECTOR:
		// First - common initialization
		// Then - initialization for table.
		// Then - initialization for vector.
		// Then - common stuff
		{
		// how many entries do we have...
		unsigned int length = rand() / (RAND_MAX / 15);

		Value** lvals = new Value* [length];

		if ( type == TYPE_TABLE ) {
			val->val.set_val.vals = lvals;
			val->val.set_val.size = length;
		} else if ( type == TYPE_VECTOR ) {
			val->val.vector_val.vals = lvals;
			val->val.vector_val.size = length;
		} else {
			assert(false);
		}

		if ( length == 0 )
			break; //empty

		for ( unsigned int pos = 0; pos < length; pos++ ) {

			Value* newval = EntryToVal(subtype, TYPE_ENUM);
			if ( newval == 0 ) {
				Error("Error while reading set");
				return 0;
			}
			lvals[pos] = newval;
		}

		break;
		}


	default:
		Error(Fmt("unsupported field format %d", type));
		return 0;
	}	

	return val;

}


bool Benchmark::DoHeartbeat(double network_time, double current_time)
{
	ReaderBackend::DoHeartbeat(network_time, current_time);
	
	switch ( mode ) {
		case MANUAL:
			// yay, we do nothing :)
			break;
		case REREAD:
		case STREAM:
			Update(); // call update and not DoUpdate, because update actually checks disabled.
			break;
		default:
			assert(false);
	}

	return true;
}

